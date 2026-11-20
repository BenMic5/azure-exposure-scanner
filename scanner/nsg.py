"""Evaluate ONE Azure Network Security Group: which public IPv4 sources may open TCP to a port?

Azure semantics implemented here:
- Rules (custom + default) are processed in priority order (lowest number first). For
  each source address, the first rule that matches decides Allow or Deny. So the result
  is computed over the whole public IPv4 space at once: each rule decides the addresses
  that no higher-priority rule has decided yet. This handles rules that only cover the
  internet in combination (e.g. 0.0.0.0/1 and 128.0.0.0/1 in two rules).
- Sources: `*` and the `Internet` service tag mean all public addresses; IPv4 CIDRs mean
  themselves. IPv6 prefixes never match IPv4 traffic. Other service tags (VirtualNetwork,
  AzureLoadBalancer, AzureCloud, ...) and source ASGs are treated as not internet
  (see README limits).
- NSGs see traffic after the public IP is translated, so the destination is the NIC's
  private IP; a rule written for the public IP does not match.
- Source ports are ignored: the client chooses its own source port.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from . import ipset
from .ipset import PUBLIC_IPV4, IpSet

BROAD_ADDRESSES = 2 ** 23   # "open to the internet" = at least half a /8 of public sources (~8.4M),
                            # so any /8 rule counts even when it contains a private range
INTERNET_TAGS = {"*", "internet"}
ANY_DESTINATION = {"*", "virtualnetwork"}  # the NIC's private IP is always inside its VNet
NO_PRIORITY = 65536  # sort key for a rule without a valid priority: after every real one (max 65500)


@dataclass(frozen=True)
class RuleRef:
    name: str
    priority: int
    default: bool
    source: str

    def label(self, with_source: bool = False) -> str:
        text = f"{'default rule' if self.default else 'rule'} '{self.name}' (priority {self.priority})"
        return text + (f", source {self.source}" if with_source else "")


@dataclass
class NsgResult:
    allowed_set: IpSet                                          # public sources allowed through
    # (rule, sources it allowed): rules that allowed some sources
    allow_rules: list[tuple[RuleRef, IpSet]] = field(default_factory=list)
    deny_rules: list[RuleRef] = field(default_factory=list)     # rules that denied some sources
    carving_denies: list[RuleRef] = field(default_factory=list)  # Denies that removed sources a later Allow covers
    shadowed: list[RuleRef] = field(default_factory=list)       # Allow rules left with nothing by earlier Denies
    malformed: list[RuleRef] = field(default_factory=list)      # matching rules without a valid access or priority
    implicit_deny: bool = False                                 # some sources fell to an uncollected DenyAllInBound

    @property
    def count(self) -> int:
        return ipset.size(self.allowed_set)

    @property
    def allowed(self) -> bool:
        """True when this NSG alone lets the internet at large through."""
        return self.count >= BROAD_ADDRESSES

    def describe(self) -> str:
        if self.malformed:
            names = ", ".join(f"'{r.name}'" for r in self.malformed)
            return f"rule {names} has no valid access (Allow or Deny) or priority value"
        if self.count == 0:
            parts = [r.label() for r in self.deny_rules]
            if self.implicit_deny or not parts:
                parts.append("default rule 'DenyAllInBound' (implicit)")
            text = " + ".join(parts)
            if self.shadowed:
                text += " overrides " + ", ".join(f"'{r.name}' ({r.priority})" for r in self.shadowed)
            return text
        allows = " + ".join(r.label(with_source=True) for r, _ in self.allow_rules)
        if not self.allowed:
            return f"{allows}: only {ipset.to_cidrs(self.allowed_set)} ({self.count:,} addresses)"
        if self.carving_denies:
            allows += "; except sources denied by " + " + ".join(r.label() for r in self.carving_denies)
        return allows


def _values(props: dict[str, Any], single: str, plural: str) -> list[str]:
    """ARM stores e.g. a port either in `destinationPortRange` or `destinationPortRanges`."""
    values = list(props.get(plural) or [])
    if props.get(single):
        values.append(props[single])
    return [str(v) for v in values]


def _port_matches(port_specs: list[str], port: int) -> bool:
    for spec in port_specs:
        if spec == "*":
            return True
        if "-" in spec:
            low, high = spec.split("-", 1)
            if int(low) <= port <= int(high):
                return True
        elif int(spec) == port:
            return True
    return False


def _destination_matches(props: dict[str, Any], private_ip: str, asg_ids: set[str]) -> bool:
    rule_asgs = {a["id"].lower() for a in props.get("destinationApplicationSecurityGroups") or []}
    if rule_asgs:
        return bool(rule_asgs & asg_ids)
    ip = ipaddress.ip_address(private_ip)
    for prefix in _values(props, "destinationAddressPrefix", "destinationAddressPrefixes"):
        if prefix.lower() in ANY_DESTINATION:
            return True
        try:
            if ip in ipaddress.ip_network(prefix, strict=False):
                return True
        except ValueError:
            continue  # another service tag (e.g. Storage): does not cover a VM's private IP
    return False


def source_set(props: dict[str, Any]) -> IpSet:
    """The public IPv4 sources a rule covers."""
    if props.get("sourceApplicationSecurityGroups"):
        return []  # ASGs group NICs inside Azure, never internet hosts
    ranges: IpSet = []
    for prefix in _values(props, "sourceAddressPrefix", "sourceAddressPrefixes"):
        if prefix.lower() in INTERNET_TAGS:
            return PUBLIC_IPV4
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue  # a service tag that is not the internet (e.g. AzureLoadBalancer)
        if network.version == 4:  # IPv6 prefixes never match IPv4 traffic
            ranges += ipset.from_cidr(str(network))
    return ipset.intersect(ipset.normalize(ranges), PUBLIC_IPV4)


def _applies(props: dict[str, Any], port: int, private_ip: str, asg_ids: set[str]) -> bool:
    """Everything except the source: direction, protocol, port, destination."""
    return (
        (props.get("direction") or "").lower() == "inbound"
        and (props.get("protocol") or "").lower() in {"tcp", "*"}
        and _port_matches(_values(props, "destinationPortRange", "destinationPortRanges"), port)
        and _destination_matches(props, private_ip, asg_ids)
    )


def _priority(props: dict[str, Any]) -> int:
    value = props.get("priority")
    return value if isinstance(value, int) and not isinstance(value, bool) else NO_PRIORITY


def evaluate(nsg: dict[str, Any], port: int, private_ip: str, asg_ids: set[str] = frozenset()) -> NsgResult:
    props = nsg.get("properties") or {}
    rules = [(r, False) for r in props.get("securityRules") or []]
    rules += [(r, True) for r in props.get("defaultSecurityRules") or []]
    rules.sort(key=lambda pair: _priority(pair[0].get("properties") or {}))

    asg_ids = {a.lower() for a in asg_ids}
    result = NsgResult(allowed_set=[])
    undecided = PUBLIC_IPV4
    denied: list[tuple[RuleRef, IpSet]] = []   # (Deny rule, sources it decided), in priority order
    for rule, is_default in rules:
        rp = rule.get("properties") or {}
        # Keep walking after every source is decided, to report Allow rules that never take effect.
        if not _applies(rp, port, private_ip, asg_ids):
            continue
        sources = source_set(rp)
        if not sources:
            continue
        decided = ipset.intersect(undecided, sources)
        ref = RuleRef(rule.get("name", "?"), _priority(rp), is_default,
                      ", ".join(_values(rp, "sourceAddressPrefix", "sourceAddressPrefixes")))
        access = (rp.get("access") or "").lower()
        if ref.priority == NO_PRIORITY:
            # Without a priority its place in the order is unknown: never guess what it decides.
            result.malformed.append(ref)
            access = ""  # leave its sources undecided; the malformed rule already makes the layer UNKNOWN
            decided = []
        if access == "allow":
            if decided:
                result.allowed_set = ipset.union(result.allowed_set, decided)
                result.allow_rules.append((ref, decided))
            elif not is_default and any(ipset.intersect(sources, d) for _, d in denied):
                result.shadowed.append(ref)
            # A Deny "carves" an Allow when it decided sources this later Allow also covers.
            for deny_ref, deny_set in denied:
                if not deny_ref.default and deny_ref not in result.carving_denies \
                        and ipset.intersect(deny_set, sources):
                    result.carving_denies.append(deny_ref)
        elif access == "deny":
            if decided:
                result.deny_rules.append(ref)
                denied.append((ref, decided))
        elif decided:
            # Missing or unexpected access value: never guess Allow or Deny for these sources.
            result.malformed.append(ref)
        undecided = ipset.subtract(undecided, decided)
    # Sources no rule decided fall to DenyAllInBound, which Azure applies even if not collected.
    result.implicit_deny = bool(undecided)  # a collected DenyAllInBound ('*') would have decided them
    return result
