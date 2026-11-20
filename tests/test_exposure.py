"""Run with: python3 -m unittest discover tests"""
import copy
import json
import os
import unittest

from scanner import nsg
from scanner.exposure import scan
from scanner.finding import EXPOSED, INCONCLUSIVE, NOT_EXPOSED, SENSITIVE_PORTS
from scanner.inventory import Inventory, read_permission

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "demo.json")
PORTS = list(SENSITIVE_PORTS)


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def by_vm(findings):
    out = {}
    for f in findings:
        out.setdefault(f.resource_name, []).append(f)
    return out


def rule(name, priority, access="Allow", port="22", source="Internet", dest="*", **extra):
    props = {"priority": priority, "direction": "Inbound", "access": access, "protocol": "Tcp",
             "sourceAddressPrefix": source, "sourcePortRange": "*",
             "destinationAddressPrefix": dest, "destinationPortRange": port}
    props.update(extra)
    return {"name": name, "properties": props}


def make_nsg(*rules):
    return {"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
            "name": "n", "properties": {"securityRules": list(rules), "defaultSecurityRules": [
                rule("DenyAllInBound", 65500, access="Deny", port="*", source="*")]}}


class DemoScenarios(unittest.TestCase):
    """Each demo VM is a finding or a look-alike that a per-NSG check would flag."""

    @classmethod
    def setUpClass(cls):
        cls.results = by_vm(scan(Inventory.load(FIXTURE), PORTS))

    def assertOnly(self, vm, status, ports):
        findings = self.results[vm]
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0].status, status)
        self.assertEqual(sorted(findings[0].ports), sorted(ports))
        return findings[0]

    def test_exposed_ssh_is_a_finding_with_the_deciding_rule(self):
        f = self.assertOnly("vm-exposed-ssh", EXPOSED, [22])
        self.assertIn("allow-ssh-internet", f.remediation)
        self.assertEqual([e.decision for e in f.evidence], ["PRESENT", "NO NSG", "ALLOW"])

    def test_subnet_nsg_blocks_the_same_open_nic_rule(self):
        f = self.assertOnly("vm-subnet-blocks", NOT_EXPOSED, [22])
        self.assertIn("DenyAllInBound", f.evidence[1].detail)

    def test_higher_priority_deny_wins(self):
        f = self.assertOnly("vm-priority-deny", NOT_EXPOSED, [22])
        self.assertIn("allow-ssh-any", f.evidence[2].detail)

    def test_open_rule_without_public_ip_is_latent_only(self):
        f = self.assertOnly("vm-no-public-ip", NOT_EXPOSED, [22])
        self.assertIn("Latent", f.reason)

    def test_no_nsg_with_standard_public_ip_is_secure_by_default(self):
        self.assertOnly("vm-no-nsg", NOT_EXPOSED, PORTS)

    def test_missing_nsg_is_inconclusive_with_needed_permission(self):
        f = self.assertOnly("vm-missing-nsg", INCONCLUSIVE, PORTS)
        self.assertIn("Microsoft.Network/networkSecurityGroups/read", f.remediation)
        self.assertIn("22222222-2222-2222-2222-222222222222", f.remediation)


class EdgeCases(unittest.TestCase):
    def setUp(self):
        self.data = load_fixture()

    def vm_result(self, vm):
        return by_vm(scan(Inventory(self.data), PORTS))[vm]

    def test_basic_sku_without_nsg_is_open_by_default(self):
        pip = next(p for p in self.data["publicIPAddresses"] if p["name"] == "pip-no-nsg")
        pip["sku"]["name"] = "Basic"
        self.assertEqual(self.vm_result("vm-no-nsg")[0].status, EXPOSED)

    def test_missing_data_does_not_matter_when_another_layer_denies(self):
        # vm-subnet-blocks: subnet denies, so an unreadable NIC NSG cannot change the answer.
        nic = next(n for n in self.data["networkInterfaces"] if n["name"] == "nic-subnet-blocks")
        nic["properties"]["networkSecurityGroup"]["id"] += "-unreadable"
        statuses = {f.status for f in self.vm_result("vm-subnet-blocks")}
        self.assertNotIn(INCONCLUSIVE, statuses)

    def test_missing_nic_is_inconclusive(self):
        self.data["networkInterfaces"] = [n for n in self.data["networkInterfaces"] if n["name"] != "nic-exposed-ssh"]
        self.assertEqual(self.vm_result("vm-exposed-ssh")[0].status, INCONCLUSIVE)

    def test_results_are_ordered_most_urgent_first(self):
        statuses = [f.status for f in scan(Inventory(self.data), PORTS)]
        self.assertEqual(statuses, sorted(statuses, key=[EXPOSED, INCONCLUSIVE, NOT_EXPOSED].index))
        self.assertEqual(statuses[0], EXPOSED)

    def test_fix_names_every_allowing_rule_when_both_layers_allow(self):
        locked = next(n for n in self.data["networkSecurityGroups"] if n["name"] == "nsg-subnet-locked")
        locked["properties"]["securityRules"].append(rule("allow-ssh-subnet", 110))
        f = self.vm_result("vm-subnet-blocks")[0]
        self.assertEqual(f.status, EXPOSED)
        self.assertIn("rule 'allow-ssh-subnet' in subnet NSG 'nsg-subnet-locked'", f.remediation)
        self.assertIn("rule 'allow-ssh-internet' in NIC NSG 'nsg-ssh-open'", f.remediation)
        self.assertIn("closing either layer closes the path", f.remediation)

    def test_one_open_rule_on_all_ports_is_one_finding_with_advice_per_service(self):
        nsg_open = next(n for n in self.data["networkSecurityGroups"] if n["name"] == "nsg-ssh-open")
        nsg_open["properties"]["securityRules"][0]["properties"]["destinationPortRange"] = "*"
        findings = self.vm_result("vm-exposed-ssh")
        self.assertEqual(len(findings), 1)
        self.assertEqual(sorted(findings[0].ports), sorted(PORTS))
        self.assertIn("For SSH/RDP, prefer Azure Bastion", findings[0].remediation)
        self.assertIn("never the internet", findings[0].remediation)

    def test_missing_private_ip_is_inconclusive_not_guessed(self):
        nic = next(n for n in self.data["networkInterfaces"] if n["name"] == "nic-exposed-ssh")
        del nic["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]
        f = self.vm_result("vm-exposed-ssh")[0]
        self.assertEqual(f.status, INCONCLUSIVE)
        self.assertIn("Microsoft.Network/networkInterfaces/read", f.remediation)

    def test_missing_private_ip_without_public_ip_is_not_exposed(self):
        nic = next(n for n in self.data["networkInterfaces"] if n["name"] == "nic-no-public-ip")
        del nic["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]
        self.assertEqual([f.status for f in self.vm_result("vm-no-public-ip")], [NOT_EXPOSED])

    def nsg_named(self, name):
        return next(n for n in self.data["networkSecurityGroups"] if n["name"] == name)

    def test_office_only_rule_is_limited_not_exposed(self):
        self.nsg_named("nsg-ssh-open")["properties"]["securityRules"][0]["properties"]["sourceAddressPrefix"] = \
            "203.0.113.0/24"
        f = self.vm_result("vm-exposed-ssh")[0]
        self.assertEqual(f.status, NOT_EXPOSED)
        self.assertIn("Reachable only from 256 public addresses", f.reason)
        self.assertEqual(f.evidence[2].decision, "LIMITED")

    def test_layers_allowing_disjoint_halves_let_nothing_through(self):
        # Subnet allows only 0.0.0.0/1, NIC allows only 128.0.0.0/1: each is broad, together nothing passes.
        self.nsg_named("nsg-subnet-locked")["properties"]["securityRules"].append(rule("half-a", 110, source="0.0.0.0/1"))
        self.nsg_named("nsg-ssh-open")["properties"]["securityRules"][0]["properties"]["sourceAddressPrefix"] = \
            "128.0.0.0/1"
        f = self.vm_result("vm-subnet-blocks")[0]
        self.assertEqual(f.status, NOT_EXPOSED)
        self.assertIn("no source is allowed by both layers", f.reason)

    def test_ipv6_ip_configuration_is_inconclusive(self):
        nic = next(n for n in self.data["networkInterfaces"] if n["name"] == "nic-exposed-ssh")
        nic["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"] = "fd00::4"
        f = self.vm_result("vm-exposed-ssh")[0]
        self.assertEqual(f.status, INCONCLUSIVE)
        self.assertIn("IPv6", f.reason)

    def test_unknown_public_ip_sku_without_nsg_is_inconclusive(self):
        pip = next(p for p in self.data["publicIPAddresses"] if p["name"] == "pip-no-nsg")
        del pip["sku"]
        self.assertEqual(self.vm_result("vm-no-nsg")[0].status, INCONCLUSIVE)

    def test_null_fields_in_real_data_do_not_crash(self):
        self.data["virtualMachines"][0]["properties"]["networkProfile"] = None
        self.data["networkInterfaces"][1]["properties"]["ipConfigurations"] = None
        self.nsg_named("nsg-priority-deny")["properties"]["securityRules"][0]["properties"]["protocol"] = None
        statuses = {f.status for f in scan(Inventory(self.data), PORTS)}
        self.assertTrue(statuses)  # scanned everything without raising

    def test_internal_error_is_reported_per_vm_not_raised(self):
        del self.data["virtualMachines"][0]["properties"]["networkProfile"]["networkInterfaces"][0]["id"]
        findings = scan(Inventory(self.data), PORTS)
        broken = [f for f in findings if f.resource_name == "vm-exposed-ssh"]
        self.assertEqual([f.status for f in broken], [INCONCLUSIVE])
        self.assertIn("Scanner error", broken[0].reason)
        self.assertEqual(len({f.resource_name for f in findings}), 6)  # the other VMs were still scanned

    def test_missing_access_field_makes_the_vm_inconclusive(self):
        del self.nsg_named("nsg-ssh-open")["properties"]["securityRules"][0]["properties"]["access"]
        f = self.vm_result("vm-exposed-ssh")[0]
        self.assertEqual(f.status, INCONCLUSIVE)
        self.assertIn("without a valid access or priority value", f.reason)
        self.assertIn("Re-collect NSG 'nsg-ssh-open'", f.remediation)

    def test_narrow_rule_without_public_ip_is_not_called_a_latent_exposure(self):
        self.nsg_named("nsg-ssh-open")["properties"]["securityRules"][0]["properties"]["sourceAddressPrefix"] = \
            "203.0.113.0/24"
        findings = self.vm_result("vm-no-public-ip")
        self.assertTrue(all("Latent" not in f.reason for f in findings))
        self.assertEqual([f.status for f in findings], [NOT_EXPOSED])

    def test_fix_names_only_the_rule_that_opens_the_path(self):
        rules = self.nsg_named("nsg-ssh-open")["properties"]["securityRules"]
        rules.insert(0, rule("office", 90, source="203.0.113.0/24"))
        f = self.vm_result("vm-exposed-ssh")[0]
        self.assertEqual(f.status, EXPOSED)
        self.assertIn("rule 'allow-ssh-internet' in NIC NSG", f.remediation)
        self.assertNotIn("office", f.remediation)

    def test_narrow_allow_behind_a_subnet_deny_is_not_called_internet(self):
        self.nsg_named("nsg-ssh-open")["properties"]["securityRules"][0]["properties"]["sourceAddressPrefix"] = \
            "203.0.113.0/24"
        findings = self.vm_result("vm-subnet-blocks")
        self.assertTrue(all("from the internet" not in f.reason for f in findings))

    def test_vm_with_nothing_open_gets_one_summary_line(self):
        nsg_open = next(n for n in self.data["networkSecurityGroups"] if n["name"] == "nsg-ssh-open")
        nsg_open["properties"]["securityRules"] = []
        findings = self.vm_result("vm-exposed-ssh")
        self.assertEqual([(f.status, f.ports) for f in findings], [(NOT_EXPOSED, [])])


class RuleMatching(unittest.TestCase):
    IP = "10.0.1.4"

    def decide(self, *rules, port=22, asgs=frozenset()):
        return nsg.evaluate(make_nsg(*rules), port, self.IP, asgs)

    def test_port_range_and_list(self):
        self.assertTrue(self.decide(rule("r", 100, port="20-25")).allowed)
        self.assertTrue(self.decide(rule("r", 100, port=None, destinationPortRanges=["80", "3380-3390"]),
                                    port=3389).allowed)
        self.assertFalse(self.decide(rule("r", 100, port="23-25")).allowed)

    def test_internet_source_variants(self):
        for source in ("*", "Internet", "0.0.0.0/0"):
            self.assertTrue(self.decide(rule("r", 100, source=source)).allowed, source)
        self.assertTrue(self.decide(rule("r", 100, source=None,
                                         sourceAddressPrefixes=["10.0.0.0/8", "0.0.0.0/0"])).allowed)

    def test_cidrs_in_one_rule_that_add_up_to_the_internet(self):
        self.assertTrue(self.decide(rule("r", 100, source=None,
                                         sourceAddressPrefixes=["0.0.0.0/1", "128.0.0.0/1"])).allowed)

    def test_allow_rules_that_only_cover_the_internet_together(self):
        d = self.decide(rule("a1", 100, source="0.0.0.0/1"), rule("a2", 110, source="128.0.0.0/1"))
        self.assertTrue(d.allowed)
        self.assertEqual([r.name for r, _ in d.allow_rules], ["a1", "a2"])

    def test_deny_rules_that_cover_the_internet_together_beat_a_later_allow(self):
        d = self.decide(rule("d1", 100, access="Deny", source="0.0.0.0/1"),
                        rule("d2", 110, access="Deny", source="128.0.0.0/1"), rule("a", 200, source="*"))
        self.assertFalse(d.allowed)
        self.assertEqual(d.count, 0)
        self.assertEqual([r.name for r in d.shadowed], ["a"])

    def test_all_public_space_without_private_ranges_is_the_internet(self):
        public = ["1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
                  "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/3"]
        self.assertTrue(self.decide(rule("r", 100, source=None, sourceAddressPrefixes=public)).allowed)

    def test_ipv6_prefixes_never_match_ipv4_traffic(self):
        # A Deny for all IPv6 sources must not hide an IPv4 Allow below it ...
        self.assertTrue(self.decide(rule("d6", 100, access="Deny", source="::/0"), rule("a", 200, source="*")).allowed)
        # ... and an Allow for all IPv6 sources must not open the VM to IPv4.
        self.assertFalse(self.decide(rule("a6", 100, source="::/0")).allowed)

    def test_blocking_a_few_sources_still_leaves_the_internet_open(self):
        d = self.decide(rule("deny-attacker", 100, access="Deny", source="198.51.100.66"), rule("a", 200))
        self.assertTrue(d.allowed)
        self.assertIn("except sources denied by rule 'deny-attacker'", d.describe())

    def test_specific_source_cidr_is_limited_not_the_internet(self):
        d = self.decide(rule("office-only", 100, source="203.0.113.0/24"))
        self.assertFalse(d.allowed)
        self.assertEqual(d.count, 256)
        self.assertIn("only 203.0.113.0/24 (256 addresses)", d.describe())

    def test_other_service_tags_are_not_the_internet(self):
        for tag in ("VirtualNetwork", "AzureLoadBalancer", "AzureCloud"):
            self.assertEqual(self.decide(rule("r", 100, source=tag)).count, 0, tag)

    def test_priority_order_not_list_order(self):
        d = self.decide(rule("allow", 300), rule("deny", 100, access="Deny"))
        self.assertFalse(d.allowed)
        self.assertEqual([r.name for r in d.shadowed], ["allow"])

    def test_missing_access_is_malformed_not_deny(self):
        r = rule("noaccess", 100)
        del r["properties"]["access"]
        d = self.decide(r)
        self.assertEqual([x.name for x in d.malformed], ["noaccess"])

    def test_missing_priority_is_malformed_not_sorted_last(self):
        r = rule("nopriority", 100)
        del r["properties"]["priority"]
        d = self.decide(r)  # sorted last it would sit after DenyAllInBound and silently allow nothing
        self.assertEqual([x.name for x in d.malformed], ["nopriority"])

    def test_except_lists_only_denies_that_remove_allowed_sources(self):
        d = self.decide(rule("lo", 100, source="0.0.0.0/1"), rule("hi", 200, access="Deny", source="128.0.0.0/1"))
        self.assertNotIn("except", d.describe())
        d = self.decide(rule("deny-attacker", 100, access="Deny", source="198.51.100.66"), rule("a", 200))
        self.assertIn("except sources denied by rule 'deny-attacker'", d.describe())

    def test_partial_deny_without_default_rules_names_the_implicit_deny(self):
        d = nsg.evaluate({"properties": {"securityRules": [rule("lo", 100, access="Deny", source="0.0.0.0/1")]}},
                         22, self.IP)
        self.assertEqual(d.count, 0)
        self.assertIn("default rule 'DenyAllInBound' (implicit)", d.describe())

    def test_allow_after_earlier_allow_is_not_shadowed(self):
        d = self.decide(rule("a1", 100), rule("a2", 200))
        self.assertEqual(d.shadowed, [])

    def test_any_slash_8_rule_counts_as_the_internet(self):
        for cidr in ("192.0.0.0/8", "172.0.0.0/8", "100.0.0.0/8", "8.0.0.0/8"):
            self.assertTrue(self.decide(rule("r", 100, source=cidr)).allowed, cidr)
        self.assertFalse(self.decide(rule("r", 100, source="10.0.0.0/8")).allowed)  # entirely private

    def test_null_fields_do_not_crash(self):
        d = self.decide(rule("r", 100, protocol=None, direction=None))
        self.assertEqual(d.count, 0)

    def test_destination_must_cover_private_ip(self):
        self.assertTrue(self.decide(rule("r", 100, dest="10.0.1.0/24")).allowed)
        self.assertTrue(self.decide(rule("r", 100, dest="VirtualNetwork")).allowed)
        # NSGs see the private IP after NAT, so a rule for the public IP does not match.
        self.assertFalse(self.decide(rule("r", 100, dest="198.51.100.10")).allowed)

    def test_destination_application_security_group(self):
        asg = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/web"
        r = rule("r", 100, dest=None, destinationApplicationSecurityGroups=[{"id": asg}])
        self.assertTrue(self.decide(copy.deepcopy(r), asgs={asg}).allowed)
        self.assertFalse(self.decide(r).allowed)

    def test_udp_rule_does_not_allow_tcp(self):
        self.assertFalse(self.decide(rule("r", 100, protocol="Udp")).allowed)

    def test_no_rules_collected_is_implicit_deny(self):
        d = nsg.evaluate({"properties": {}}, 22, self.IP)
        self.assertFalse(d.allowed)


class Permissions(unittest.TestCase):
    def test_read_permission_from_resource_id(self):
        self.assertEqual(
            read_permission("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/x"),
            "Microsoft.Network/virtualNetworks/subnets/read")


if __name__ == "__main__":
    unittest.main()
