"""The check: is an Azure VM reachable from the internet at large on a sensitive TCP port?

For every VM -> NIC -> IP configuration, the inbound path from the internet is:

    public IP  ->  subnet NSG  ->  NIC NSG  ->  VM private IP

Each NSG layer yields the set of public IPv4 sources it lets through; a source reaches
the VM only if every layer lets it through, so the layers' sets are intersected.
A port is EXPOSED when the IP configuration has a public IP and the intersection is
broad (at least nsg.BROAD_ADDRESSES sources). See README, "How the check works":
- A layer without an NSG passes traffic through.
- With NO NSG on either layer, a Standard SKU public IP is closed by default.
- Missing data yields INCONCLUSIVE unless the known layers already settle the answer.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace
from typing import Optional

from . import ipset
from . import nsg as nsg_eval
from .finding import EXPOSED, INCONCLUSIVE, NOT_EXPOSED, SENSITIVE_PORTS, STATUS_ORDER, Evidence, Finding
from .inventory import Inventory, name_of, read_permission, ref_id, subscription_of
from .ipset import PUBLIC_IPV4, IpSet

# Layer states
ALLOW, LIMITED, DENY, NO_NSG, UNKNOWN = "ALLOW", "LIMITED", "DENY", "NO NSG", "UNKNOWN"

ADMIN_PORTS = {22, 3389}


@dataclass
class _Layer:
    """Outcome of one NSG layer for one port."""
    name: str                           # "subnet NSG" / "NIC NSG"
    state: str
    control: str
    detail: str
    allowed_set: Optional[IpSet] = None  # None when the layer has no NSG or could not be evaluated
    allow_rules: tuple = ()              # (rule name, sources it let through)
    shadowed: bool = False               # an Allow rule never takes effect because of earlier Deny rules
    unknown_why: str = "could not be read"
    fix: Optional[str] = None            # remediation when this layer is UNKNOWN

    def evidence(self) -> Evidence:
        return Evidence(self.name, self.control, self.state, self.detail)


def scan(inventory: Inventory, ports: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    for vm in inventory.vms:
        try:
            findings.extend(evaluate_vm(vm, inventory, ports))
        except Exception as err:  # one malformed resource must not stop the scan or look like a finding
            findings.append(Finding("azure", vm.get("id", "?"), vm.get("name", "?"), INCONCLUSIVE, list(ports),
                                    f"Scanner error while evaluating this VM: {type(err).__name__}: {err}", "-",
                                    remediation="Check the VM's inventory data for malformed fields, then rescan."))
    # Most urgent first; within a status, keep inventory order (stable sort).
    return sorted(findings, key=lambda f: STATUS_ORDER.index(f.status))


def evaluate_vm(vm: dict, inv: Inventory, ports: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    network_profile = (vm.get("properties") or {}).get("networkProfile") or {}
    for nic_ref in network_profile.get("networkInterfaces") or []:
        nic = inv.get(nic_ref["id"])
        if nic is None:
            findings.append(_missing(vm, ports, "NIC", nic_ref["id"], path=name_of(nic_ref["id"])))
            continue
        for ip_config in (nic.get("properties") or {}).get("ipConfigurations") or []:
            findings.extend(_evaluate_ip_config(vm, nic, ip_config, inv, ports))
    if not findings:
        findings.append(Finding("azure", vm["id"], vm["name"], NOT_EXPOSED, [],
                                "No checked port is open to the internet on any path.", path="-"))
    return findings


def _evaluate_ip_config(vm: dict, nic: dict, ip_config: dict, inv: Inventory, ports: list[int]) -> list[Finding]:
    props = ip_config.get("properties") or {}
    private_ip = props.get("privateIPAddress")
    asg_ids = {a["id"] for a in props.get("applicationSecurityGroups") or []}

    # 1. Public IP
    pip_id = ref_id(ip_config, "publicIPAddress")
    pip = inv.get(pip_id) if pip_id else None
    pip_sku = ((pip or {}).get("sku") or {}).get("name")  # None = unknown; never assume the safe default
    if pip_id is None:
        pip_state, pip_ev = "NONE", Evidence("public IP", "-", "NONE", "IP configuration has no public IP")
        public_addr = "no public IP"
    elif pip is None:
        pip_state = UNKNOWN
        pip_ev = Evidence("public IP", name_of(pip_id), UNKNOWN, _not_collected())
        public_addr = name_of(pip_id)
    else:
        pip_state = "PRESENT"
        public_addr = (pip.get("properties") or {}).get("ipAddress") or "(dynamic, assigned when running)"
        pip_ev = Evidence("public IP", pip["name"], "PRESENT", f"{public_addr}, {pip_sku or 'unknown'} SKU")
    path = f"{public_addr} -> {private_ip or '?'} ({nic['name']}/{ip_config.get('name', '?')})"

    # NSG destination rules are matched against the private IP; this check evaluates IPv4 only.
    if _ip_version(private_ip) != 4:
        if pip_state == "NONE":
            return []  # no public IP: not internet-facing whatever the rules say
        if _ip_version(private_ip) == 6:
            ev = Evidence("private IP", ip_config.get("name", "?"), UNKNOWN, f"IPv6 address {private_ip}")
            return [Finding("azure", vm["id"], vm["name"], INCONCLUSIVE, list(ports),
                            "Cannot conclude: IPv6 paths are not evaluated by this scanner.", path, [pip_ev, ev],
                            "Verify the IPv6 path with Network Watcher IP flow verify.")]
        ev = Evidence("private IP", ip_config.get("name", "?"), UNKNOWN,
                      f"missing or invalid privateIPAddress ({private_ip!r})")
        return [Finding("azure", vm["id"], vm["name"], INCONCLUSIVE, list(ports),
                        "Cannot conclude: NSG rules are matched against the private IP, which is missing from the "
                        "collected data.", path, [pip_ev, ev],
                        f"Re-collect NIC '{nic['name']}' (needs {read_permission(nic['id'])}), then rescan.")]

    # 2. Subnet -> its NSG reference (the subnet itself may be missing from the data)
    subnet_id = ref_id(ip_config, "subnet")
    subnet = inv.get(subnet_id) if subnet_id else None
    nic_nsg_id = ref_id(nic, "networkSecurityGroup")

    results: list[Finding] = []
    for port in ports:
        if subnet_id and subnet is None:
            subnet_layer = _Layer("subnet NSG", UNKNOWN, name_of(subnet_id), _not_collected(),
                                  fix=_grant_read([subnet_id]))
        else:
            subnet_layer = _nsg_layer("subnet NSG", f"subnet {name_of(subnet_id or '-')}",
                                      ref_id(subnet, "networkSecurityGroup"), inv, port, private_ip, asg_ids)
        nic_layer = _nsg_layer("NIC NSG", f"NIC {nic['name']}", nic_nsg_id, inv, port, private_ip, asg_ids)
        if subnet_layer.state == DENY:
            # Azure stops at the subnet for inbound traffic; show the NIC layer for context only.
            nic_layer.detail += " (not reached)"  # the reason line explains the subnet denies first
        layers = [subnet_layer, nic_layer]

        status, reason, remediation = _verdict(layers, pip_state, pip_sku, pip_id)
        relevant = (
            status != NOT_EXPOSED
            or any(l.state == ALLOW or l.shadowed for l in layers)
            or (pip_state != "NONE" and any(l.state == LIMITED for l in layers))
            or (all(l.state == NO_NSG for l in layers) and pip_state == "PRESENT")
        )
        if relevant:
            evidence = [pip_ev] + [l.evidence() for l in layers]
            results.append(Finding("azure", vm["id"], vm["name"], status, [port], reason, path, evidence, remediation))
    merged = _merge_ports(results)
    for f in merged:
        if f.status == EXPOSED:
            f.remediation = " ".join(filter(None, [f.remediation, _port_hint(f.ports)]))
    return merged


def _nsg_layer(name: str, owner: str, nsg_id: Optional[str], inv: Inventory,
               port: int, private_ip: str, asg_ids: set[str]) -> _Layer:
    if nsg_id is None:
        return _Layer(name, NO_NSG, "-", f"no NSG on {owner}")
    nsg = inv.get(nsg_id)
    if nsg is None:
        return _Layer(name, UNKNOWN, name_of(nsg_id), _not_collected(), fix=_grant_read([nsg_id]))
    r = nsg_eval.evaluate(nsg, port, private_ip, asg_ids)
    if r.malformed:
        return _Layer(name, UNKNOWN, nsg["name"], r.describe(), unknown_why="has a rule without a valid access or priority value",
                      fix=f"Re-collect NSG '{nsg['name']}' and check rule {r.malformed[0].name!r}, then rescan.")
    state = ALLOW if r.allowed else (LIMITED if r.count else DENY)
    return _Layer(name, state, nsg["name"], r.describe(), allowed_set=r.allowed_set,
                  allow_rules=tuple((ref.name, s) for ref, s in r.allow_rules), shadowed=bool(r.shadowed))


def _verdict(layers: list[_Layer], pip_state: str, pip_sku: Optional[str], pip_id: Optional[str]):
    """Return (status, reason, remediation) for one port. Order matters: once the known
    layers settle the answer, missing data elsewhere cannot change it."""
    evaluated = [l for l in layers if l.allowed_set is not None]
    reachable = PUBLIC_IPV4
    for layer in evaluated:
        reachable = ipset.intersect(reachable, layer.allowed_set)
    count = ipset.size(reachable)

    if count == 0:  # no public source passes every known layer
        denies = [l for l in evaluated if l.state == DENY]
        if not denies:
            return NOT_EXPOSED, ("Each layer lets some internet sources through, but no source is allowed by "
                                 "both layers."), None
        deny, others = denies[0], [l for l in evaluated if l.state in (ALLOW, LIMITED)]
        if deny.shadowed:
            return NOT_EXPOSED, (f"The {deny.name} has an Allow rule for this traffic, "
                                 "but a higher-priority Deny rule overrides it."), None
        if others:
            scope = "the internet" if others[0].state == ALLOW else "some public sources"
            return NOT_EXPOSED, (f"The {others[0].name} allows it from {scope}, but the {deny.name} "
                                 "denies it; both layers must allow."), None
        return NOT_EXPOSED, "Denied by NSG rules.", None

    if pip_state == "NONE":
        if count < nsg_eval.BROAD_ADDRESSES:
            return NOT_EXPOSED, (f"No public IP, so the VM is not directly reachable; its NSG rules allow only "
                                 f"{count:,} public addresses ({ipset.to_cidrs(reachable)})."), None
        return NOT_EXPOSED, ("NSG rules allow it from the internet, but there is no public IP, so the VM is "
                             "not directly reachable. Latent risk: attaching a public IP would expose it."), None

    if count < nsg_eval.BROAD_ADDRESSES:  # further (unknown) layers could only narrow this
        return NOT_EXPOSED, (f"Reachable only from {count:,} public addresses ({ipset.to_cidrs(reachable)}), "
                             "not from the internet at large."), None

    unknown_layers = [l for l in layers if l.state == UNKNOWN]
    if unknown_layers or pip_state == UNKNOWN:
        # Say what is already known to pass, so the reader sees how much hangs on the missing data.
        unknown = [f"{l.name} '{l.control}', which {l.unknown_why}" for l in unknown_layers]
        fixes = [l.fix for l in unknown_layers if l.fix]
        if pip_state == UNKNOWN:
            unknown.append(f"public IP '{name_of(pip_id)}', which could not be read")
            fixes.append(_grant_read([pip_id]))
        passing = (["public IP"] if pip_state == "PRESENT" else []) + \
            [f"{l.name.split()[0]} layer" for l in layers if l.state in (ALLOW, NO_NSG)]
        missing = " and ".join(unknown)
        if passing:
            reason = f"The {' and '.join(passing)} let traffic through, so exposure depends only on {missing}."
        else:
            reason = f"Cannot conclude: {missing}."
        return INCONCLUSIVE, reason, " ".join(fixes)

    if not evaluated:  # no NSG on either layer
        if pip_sku is None:
            return INCONCLUSIVE, ("No NSG on the subnet or the NIC, and the public IP SKU is unknown: Standard "
                                  "blocks inbound traffic by default, Basic allows it."), \
                "Re-collect the public IP (its `sku` field), then rescan."
        if pip_sku.lower() == "basic":
            return EXPOSED, "No NSG on the subnet or the NIC, and a Basic SKU public IP is open by default.", \
                ("Attach an NSG that allows only trusted source ranges, and upgrade the public IP to "
                 "Standard SKU (Basic is retired).")
        return NOT_EXPOSED, ("No NSG on the subnet or the NIC: a Standard SKU public IP blocks inbound traffic "
                             "unless an NSG allows it (secure by default)."), None

    # Name the exact rules to change: only those that let a broad share of the reachable sources through
    # (an office-range rule next to an Internet rule is not the problem). The evidence shows all of them.
    opening = []
    for layer in evaluated:
        names = [n for n, s in layer.allow_rules
                 if ipset.size(ipset.intersect(s, reachable)) >= nsg_eval.BROAD_ADDRESSES]
        names = names or [n for n, _ in layer.allow_rules]  # many small rules can add up to broad
        opening.append((layer, names))
    targets = [f"{'rules' if len(names) > 1 else 'rule'} {' and '.join(repr(n) for n in names)} "
               f"in {layer.name} '{layer.control}'" for layer, names in opening]
    it = "them" if sum(len(names) for _, names in opening) > 1 else "it"
    if len(opening) > 1:
        fix = (f"Restrict either {' or '.join(targets)} to trusted source ranges, or remove {it}; "
               "closing either layer closes the path.")
    else:
        fix = f"Restrict {targets[0]} to trusted source ranges, or remove {it}."
    return EXPOSED, "Every layer on the path allows it from the internet at large.", fix


def _ip_version(value: Optional[str]) -> Optional[int]:
    try:
        return ipaddress.ip_address(value or "").version
    except ValueError:
        return None


def _port_hint(ports: list[int]) -> Optional[str]:
    """Safer access pattern for the exposed service, added once per merged finding."""
    admin = [SENSITIVE_PORTS[p] for p in ports if p in ADMIN_PORTS]
    data = [SENSITIVE_PORTS[p] for p in ports if p in SENSITIVE_PORTS and p not in ADMIN_PORTS]
    hints = []
    if admin:
        hints.append(f"For {'/'.join(admin)}, prefer Azure Bastion or Just-in-Time VM access.")
    if data:
        hints.append(f"{'/'.join(data)}: allow only the application's private address ranges, never the internet.")
    return " ".join(hints) or None


def _merge_ports(findings: list[Finding]) -> list[Finding]:
    """Ports with an identical verdict and evidence are reported once."""
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.status, f.reason, f.path, tuple(f.evidence), f.remediation)
        if key in merged:
            merged[key] = replace(merged[key], ports=merged[key].ports + f.ports)
        else:
            merged[key] = f
    return list(merged.values())


def _not_collected() -> str:
    # Evidence states the fact only; the needed permission is in the remediation.
    return "referenced, but not in the collected data"


def _grant_read(resource_ids: list[str]) -> str:
    grants = "; ".join(f"{read_permission(i)} (e.g. Reader) on subscription {subscription_of(i)}"
                       for i in resource_ids)
    return f"Grant {grants}, or connect that subscription to the scanner, then rescan."


def _missing(vm: dict, ports: list[int], what: str, resource_id: str, path: str) -> Finding:
    ev = Evidence(what, name_of(resource_id), UNKNOWN, _not_collected())
    return Finding("azure", vm["id"], vm["name"], INCONCLUSIVE, list(ports),
                   f"Cannot conclude: {what} '{name_of(resource_id)}' could not be read.", path, [ev],
                   _grant_read([resource_id]))
