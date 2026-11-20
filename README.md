# Azure Internet-Exposure Scanner (PoC)

A small proof of concept that answers one question accurately: **is this Azure VM actually reachable from the internet on a sensitive port?**, not just "does some rule look open?".

## Quick start
Requires Python 3.9+. Standard library only, so there is nothing to install.

```bash
python3 scan.py                             # scan the demo inventory (fixtures/demo.json)
python3 scan.py my-inventory.json --ports 22,3389 --json
python3 scan.py fixtures/live-azure.json    # a real Azure export (see Bonus)
python3 -m unittest discover tests          # 57 tests
```
Exit codes: `0` nothing exposed, `1` something EXPOSED (so the scanner can gate a CI pipeline), `2` invalid input (bad `--ports` or an unreadable inventory, reported in one line).

**Example output** (from `python3 scan.py`; results are ordered most urgent first): the finding, and a look-alike that per-NSG scanners would also flag:
```
[EXPOSED] vm-exposed-ssh: 22/tcp (SSH)
  why:  Every layer on the path allows it from the internet at large.
  path: 198.51.100.10 -> 10.0.1.4 (nic-exposed-ssh/ipconfig1)
    1. public IP   pip-exposed-ssh      PRESENT  198.51.100.10, Standard SKU
    2. subnet NSG  -                    NO NSG   no NSG on subnet snet-open
    3. NIC NSG     nsg-ssh-open         ALLOW    rule 'allow-ssh-internet' (priority 100), source Internet
  fix:  Restrict rule 'allow-ssh-internet' in NIC NSG 'nsg-ssh-open' to trusted source ranges, or remove it. For SSH,
        prefer Azure Bastion or Just-in-Time VM access.

[NOT_EXPOSED] vm-subnet-blocks: 22/tcp (SSH)
  why:  The NIC NSG allows it from the internet, but the subnet NSG denies it; both layers must allow.
  path: 198.51.100.11 -> 10.0.2.4 (nic-subnet-blocks/ipconfig1)
    1. public IP   pip-subnet-blocks    PRESENT  198.51.100.11, Standard SKU
    2. subnet NSG  nsg-subnet-locked    DENY     default rule 'DenyAllInBound' (priority 65500)
    3. NIC NSG     nsg-ssh-open         ALLOW    rule 'allow-ssh-internet' (priority 100), source Internet (not reached)
```

All demo scenarios (one VM each in `fixtures/demo.json`):

| VM | Setup | Result |
|---|---|---|
| `vm-exposed-ssh` | Standard public IP, NIC NSG allows 22 from `Internet`, no subnet NSG | **EXPOSED** |
| `vm-subnet-blocks` | Same open NIC NSG, subnet NSG denies | NOT_EXPOSED: both layers must allow |
| `vm-priority-deny` | Allow 22 at priority 300, Deny 22 from `Internet` at priority 100 | NOT_EXPOSED: the Deny wins |
| `vm-no-public-ip` | Same open NIC NSG, no public IP | NOT_EXPOSED, flagged as a latent risk |
| `vm-no-nsg` | Standard public IP, no NSG anywhere | NOT_EXPOSED: secure by default |
| `vm-missing-nsg` | NIC NSG lives in a subscription we cannot read | **INCONCLUSIVE**, with the missing permission |

## Decisions

Decisions made before planning, with the reasoning behind each.

### 1. Cloud: Azure
- **Why:** Azure layers network controls in a way that separates *configured* exposure from *effective* exposure:
  - A Network Security Group (NSG) can sit on the NIC **and** on the subnet. Inbound traffic must be allowed by both.
  - NSG rules are priority-ordered and can **Deny**, so the deciding rule must be found, not just any matching Allow.
  - Standard SKU public IPs are closed to inbound traffic by default: with no NSG on either layer, the VM is *not* reachable. Basic SKU (open by default) was retired in September 2025.
  - Without a public IP the VM is not directly reachable at all.
- Azure also offers ground-truth tools to validate against (Network Watcher effective rules / IP flow verify) and Azure Resource Graph for querying many subscriptions at once (relevant to scale).
- **Alternatives:**
  - AWS is equally valid. Choosing it would not change solution quality, only familiarity.
  - GCP has interesting hierarchical firewall policies, but shows less control layering for the same effort.

### 2. Check to implement: internet-reachable VM on a sensitive port
- A finding is raised only when every layer on the path allows the traffic: public IP → subnet NSG → NIC NSG → port.
- The look-alike safe case is the same open NIC rule, but blocked by the subnet NSG, a higher-priority Deny, no public IP, or no NSG at all. This is where naive scanners produce false positives.

### 3. Engine: our own evaluator, not an existing open-source scanner
- **Why:** the value of this check is combining several resources: the public IP, the subnet NSG, the NIC NSG, and rule priority. Every open-source tool we reviewed either evaluates one NSG at a time or only collects data. Using any of them, we would still write the core logic ourselves, plus carry a heavy dependency and a live subscription requirement. Our evaluator is about 580 lines (`nsg.py`, `exposure.py` and `ipset.py`, a large share of it comments), and fixture-based tests cover its correctness.
- **Tools considered (source code reviewed):**

  | Tool | What it does for this case | Why it doesn't fit |
  |---|---|---|
  | Prowler | `network_ssh_internet_access_restricted` flags any NSG with an Allow rule for port 22 from `Internet`/`*`/`0.0.0.0/0` | Evaluates each NSG in isolation: ignores rule priority (a higher-priority Deny), NSG attachment, public IPs, the NIC + subnet combination, and list-valued ports/sources. It flags our safe cases as false positives. Needs a live subscription. |
  | Steampipe / Powerpipe (azure_compliance mod) | SQL query flags any NSG with an internet Allow rule for port 22 (handles port/source lists) | Same per-NSG logic: no priority, attachment, public IP, or NIC + subnet combination. Needs a live subscription plus Steampipe/Postgres. |
  | ScoutSuite | JSON rule flags NSG rules exposing a port to the internet | Same per-rule logic. No commits since May 2024. |
  | Cloud Custodian | `ingress` filter on NSGs by ports and access | A policy and remediation engine. Its filter still matches one NSG at a time, not effective reachability. |
  | Cartography | Loads NICs, NSGs, rules, subnets, and public IPs into a Neo4j graph | Collects data but does not evaluate reachability. We would still write the logic, as graph queries, and need Neo4j plus a live subscription. Too heavy for a PoC. |
  | Checkov | Static IaC scanning (Terraform/ARM templates) | Scans code, not deployed resources. A different problem. |
  | Azure Network Watcher (native, not open source) | Effective security rules / IP flow verify combine NIC + subnet NSGs | The closest to ground truth, but it needs a running VM and the `Microsoft.Network/networkWatchers/ipFlowVerify/action` permission (not in `Reader`). It ignores public IPs and cannot run on fixtures. Useful as a cross-check, not as the engine. |

- **Where existing tools fit in production:** use an open-source scanner such as Prowler for breadth (simple single-resource checks), custom code only for checks that need cross-resource context, and Network Watcher as a cross-check where permissions allow.

### 4. Data: ARM-shaped JSON fixtures; live read-only mode as a stretch goal
- Fixtures mirror real Azure Resource Manager API responses (VMs, NICs, public IPs, virtual networks with their subnets, NSGs including default rules), so the same code path works on live data.
- Live collection would be read-only: the built-in `Reader` role, via the SDK or one Resource Graph query.

### 5. Language: Python, standard library only
The choice was judged only on what the task asks for. Both languages were viable.

| Task need | Python | Go |
|---|---|---|
| A "small, understandable" PoC | Evaluation logic reads close to pseudocode | Azure SDK types are pointer-heavy (`*string`, `*int32`), so the logic fills with nil checks and dereferences |
| Reviewers can run it easily | `python3 scan.py` with no installs (`json`, `ipaddress`, `unittest`) | Needs the Go toolchain plus SDK modules |
| 3-hour time box | Less code for the same logic | More boilerplate |
| Correctness | Weaker typing, offset by fixture tests | Typed structs, a modest advantage |
| Moving to a live mode | Some extra mapping work | Fixtures and live data share the SDK types, Go's strongest advantage |

- **Outcome:** Go's main advantage only matters for live mode, which is a stretch goal. The scale design (3,000 environments) is a design discussion, not PoC code, so it does not favor either language. Python wins on readability, zero-install runs, and speed.
- Live mode, if built, adds the Azure SDK for Python as an optional dependency.

### 6. Single provider, not provider-generic
- **Why not generic:**
  - The brief asks for one cloud and a lightweight PoC.
  - A shared model designed from one provider would most likely be wrong, because the exposure models differ in kind, not just in field names:
    - AWS: allow-only security groups, stateless NACLs, and an internet-gateway route.
    - Azure: two layers of priority-ordered NSGs with Deny rules, closed by default.
    - GCP: hierarchical firewall policies, plus VPC rules targeted by network tag or service account.
  - Abstraction layers would add indirection that makes the PoC harder to read.
- **What we did instead:**
  - Only `inventory.py` and `nsg.py` know Azure.
  - The check emits a provider-neutral `Finding` (`scanner/finding.py`), the only thing the report renders.
  - The design for adding providers is in [Extending to AWS and GCP](#extending-to-aws-and-gcp).

## 1. Proposed checks
| # | Check | Customer risk | Why this priority |
|---|---|---|---|
| 1 | **Internet-reachable VM on an admin or database port** (implemented) | Brute force and exploitation of SSH, RDP, or database services: a common first step into a cloud environment. | Direct external attack path. Today's per-rule checks are also noisy, so precision here removes the most false positives. |
| 2 | **Effectively public storage data** | Data leak from blob containers readable anonymously. | High impact and cheap to evaluate. It has the same "layers" shape: account `allowBlobPublicAccess` × container access level × network rules (`publicNetworkAccess`, firewall default action). Only a container passing every layer is public. |
| 3 | **Identity privilege escalation** | A principal that can grant itself more rights (`Microsoft.Authorization/roleAssignments/write`, e.g. Owner or User Access Administrator, or a custom role) takes over the subscription. Stale app secrets make such principals easy to steal. | Needs Entra ID / Microsoft Graph data, so it costs more. Combined with check 1 it gives the most valuable finding: *an exposed VM whose managed identity can escalate*. |

**How checks 2 and 3 would be built:**
- **Check 2 (storage):** read storage accounts and their blob containers with ARM list calls. Both are covered by `Reader`, so no data-plane access is needed. Report a container as public only if every layer allows anonymous reads:
  - the account has `allowBlobPublicAccess: true`;
  - the container's `publicAccess` is `Blob` or `Container`;
  - the account's network rules let the internet in (`publicNetworkAccess` enabled and firewall `defaultAction: Allow`).

  As in check 1, a container that is unreadable or missing data is INCONCLUSIVE.
- **Check 3 (identity):**
  1. Read role assignments and role definitions from ARM (covered by `Reader`).
  2. Resolve each principal's effective actions across inherited scopes, taking `NotActions` into account.
  3. Flag any principal that can perform `roleAssignments/write`.
  4. Add app credential expiry and age from Microsoft Graph. This needs `Application.Read.All`, a permission beyond `Reader`, so it would be an opt-in.

## 2. Approach
**Data sources.** Every input is a read-only ARM list call, all covered by the built-in **`Reader`** role:

| Fixture key | ARM REST API (`GET /subscriptions/{id}/providers/...`) | Permission |
|---|---|---|
| `virtualMachines` | `Microsoft.Compute/virtualMachines` | `Microsoft.Compute/virtualMachines/read` |
| `networkInterfaces` | `Microsoft.Network/networkInterfaces` | `Microsoft.Network/networkInterfaces/read` |
| `publicIPAddresses` | `Microsoft.Network/publicIPAddresses` | `Microsoft.Network/publicIPAddresses/read` |
| `virtualNetworks` (subnets embedded) | `Microsoft.Network/virtualNetworks` | `Microsoft.Network/virtualNetworks/read` |
| `networkSecurityGroups` (custom + default rules) | `Microsoft.Network/networkSecurityGroups` | `Microsoft.Network/networkSecurityGroups/read` |

At scale, all five come from one Azure Resource Graph query over the `Resources` table, across many subscriptions at once. The Azure SDK for Python (`azure-mgmt-compute`, `azure-mgmt-network`) returns the same shapes.

**Tools.** Existing scanners are reviewed in [Decision 3](#3-engine-our-own-evaluator-not-an-existing-open-source-scanner). Network Watcher IP flow verify is the cross-check for validating results.

## 3. How the check works
Code: `scanner/nsg.py` evaluates one NSG, `scanner/exposure.py` walks the path, `scanner/ipset.py` does the address-range arithmetic.

**What "exposed" means.** The VM has a public IP, and the set of public IPv4 source addresses that every layer lets through is *broad*: at least half a /8's worth (8.4 million addresses, `BROAD_ADDRESSES` in `nsg.py`), so any /8 rule counts even when it contains a private range. A rule open to `*` or `Internet` is exposed; a rule open only to an office range is reported as *reachable only from* that range, not as a finding. Blocking a handful of attackers in front of an open rule does not make it safe.

For each VM, NIC, IP configuration, and port, the scanner walks the path an internet packet takes:
1. **Public IP.**
   - None: not directly reachable. If NSG rules would allow the traffic, report it as a *latent* risk.
   - Referenced but unreadable: unknown.
2. **Subnet NSG, then NIC NSG.** Each NSG yields the set of public sources it lets through, computed the way Azure decides:
   - Sort all rules (custom and default) by priority. For each source address, the first rule that matches it decides. So each rule decides only the addresses that no higher-priority rule has decided yet; this handles rules that cover the internet only together (e.g. `0.0.0.0/1` and `128.0.0.0/1` in two rules).
   - A rule applies only if its protocol is `Tcp` or `*`, its destination ports cover the port (single, range, or list), and its destination covers the NIC's **private** IP (`*`, `VirtualNetwork`, a matching CIDR, or one of the NIC's Application Security Groups). NSGs see the private IP after translation, so a rule written for the public IP never matches.
   - Sources: `*` and `Internet` mean every public address; IPv4 CIDRs mean themselves; IPv6 prefixes never match IPv4 traffic; other service tags and source ASGs are not treated as internet (see Limits).
   - A layer without an NSG passes traffic through.
3. **Combine the layers.** A source reaches the VM only if both layers let it through, so the two sets are intersected.
4. **Verdict:** the first case that applies wins.
   - No public source passes the known layers: **NOT_EXPOSED**. This holds even if other data is missing, because a proven Deny settles it.
   - No public IP: **NOT_EXPOSED** (latent if the rules would allow it).
   - Fewer sources than the broad threshold: **NOT_EXPOSED**, *reachable only from* the listed ranges. Missing data could only narrow this further.
   - Something needed is unreadable: **INCONCLUSIVE**.
   - No NSG on either layer: **NOT_EXPOSED** (Standard SKU is secure by default; a legacy Basic SKU is EXPOSED; an unknown SKU is INCONCLUSIVE).
   - Otherwise: **EXPOSED**.

**Output.**
- *Noise control:* results are ordered most urgent first (EXPOSED, INCONCLUSIVE, NOT_EXPOSED). NOT_EXPOSED results are only shown for look-alikes, where some rule allows the traffic or no NSG exists. Ports with an identical verdict are grouped into one result.
- *Evidence:* every result carries the evidence chain (which control decided each step).
- *Remediation:* names the exact rules to change, plus a safer access pattern for the exposed service (Bastion or JIT for SSH/RDP; private ranges only for databases).

## Assumptions
- **The question is inbound TCP over IPv4** from an arbitrary internet host to a VM's own NIC. Other protocols, IPv6, and other entry points are listed in the limits below.
- **"The internet at large" means at least 8.4 million public source addresses** (see "What exposed means" above).
- **The inventory is one consistent snapshot**, collected at one point in time with read-only access, in the shape ARM returns.
- **Azure behavior follows Microsoft's documentation:**
  - For inbound traffic, the subnet NSG is evaluated before the NIC NSG, and both must allow.
  - NSG rules see the private IP after translation.
  - Standard SKU public IPs are closed by default.

  These were confirmed on one live VM (see [Bonus](#bonus-aikido-scan-of-a-live-test-vm)), not yet on a broad set of configurations.
- **Default ports** are common admin and database services: 22, 3389, 1433, 3306, 5432, 6379, 27017. `--ports` changes them.

## 4. Limits of the conclusion
**Controls that can change the result.** These are not evaluated; each can make a reported EXPOSED safe, or a NOT_EXPOSED reachable:
- **Azure Virtual Network Manager security admin rules.** Evaluated *before* NSGs; they can deny or force-allow traffic regardless of NSGs.
- **Routing to Azure Firewall or a network virtual appliance** (user-defined routes). Return traffic forced through a firewall can break inbound connections to an instance public IP (asymmetric routing).
- **On the VM itself:** host firewall (iptables, Windows Firewall), whether anything is listening on the port, and whether the VM is running (deallocated VMs may lose a dynamic IP).
- **Just-in-Time VM access.** Opens rules temporarily, so a scan shows a point in time.
- **The broad threshold is a judgement.** Exposure to fewer than 8.4 million sources (e.g. an office or partner range) is reported as "reachable only from", not as a finding. Such a range is still a real, narrower exposure.
- **Service tags as sources.** Tags other than `Internet` (e.g. `AzureCloud`, `Storage`, `VirtualNetwork`) are treated as not internet. Two can admit attackers:
  - `AzureCloud` covers every Azure public IP, which anyone can rent.
  - `VirtualNetwork` also includes address ranges from user-defined routes. With a `0.0.0.0/0` route, Azure's default `AllowVnetInBound` rule can admit the internet.

**Exposure paths not covered** (possible under-reporting): Load Balancer rules and inbound NAT, Application Gateway, Azure Firewall DNAT, instances of Uniform-mode VM Scale Sets (they are not in the VM list), and outbound/egress risks. IPv6 IP configurations are reported as INCONCLUSIVE rather than evaluated.

**Missing data or permissions.**
- If a resource on the path is referenced but cannot be read (another subscription, or no permission), a NIC's private IP or a public IP's SKU is missing, an NSG rule has no valid `access` or `priority` value, or a VM's data is malformed, the result is **INCONCLUSIVE**, never a silent pass. One malformed VM never stops the scan of the others.
- The output names the missing resource and the exact RBAC action needed, for example `Microsoft.Network/networkSecurityGroups/read on subscription 2222…`.
- If another layer already denies the traffic, the missing data cannot change the answer, so the result stays NOT_EXPOSED.

## 5. Production scale (3,000 environments)
**Design.**
- **Collect in bulk.** One Azure Resource Graph query per tenant or management group fetches all five resource types instead of about 15,000 ARM calls. Results are paged (at most 1,000 rows per page), and tenant scope covers up to 10,000 subscriptions. Per-subscription ARM calls are the fallback where Resource Graph is unavailable or stale.
- **Rough sizing.** Assume about 100 relevant resources per subscription:
  - **Collection:** 3,000 subscriptions give about 300,000 rows, so about 300 pages. Microsoft's documented example quota for Resource Graph is 15 queries per 5 seconds per user. The real quota varies, and each response reports it in `x-ms-user-quota-remaining`. At that rate, one full sweep takes a few minutes.
  - **Evaluation:** this evaluator measured about 0.2 ms per VM for all 7 ports. 150,000 VMs (50 per subscription) take about 30 seconds on one core.

  Collection and API throttling, not evaluation, are what limit scale.
- **Separate collection from evaluation.** Collectors write a versioned snapshot per subscription; evaluators are pure functions over snapshots, as in this PoC. Evaluation is cheap and repeatable, and a snapshot can be replayed when debugging a disputed finding.
- **Work queue per subscription.**
  - Bounded concurrency per tenant, to respect ARM and Resource Graph throttling.
  - Retries with exponential backoff and jitter on 429/5xx errors.
  - Idempotent jobs, so one failing subscription never blocks the other 2,999.
- **Incremental rescans.** React to resource changes (Resource Graph `resourcechanges`, or Activity Log events through Event Grid) and rescan only the affected path. A full sweep on a schedule catches anything missed.
- **Onboarding at tenant level.** `Reader` on the root management group covers new subscriptions automatically.
- **Findings with a lifecycle.** Stable IDs (resource + port) to deduplicate across scans, auto-resolve when fixed, and support suppressions / risk acceptance.

**Before going to production, in priority order:**
1. **Correctness.** Build a test corpus validated against Network Watcher IP flow verify, and cover the missing controls and paths from section 4 (AVNM admin rules and Load Balancer NAT first). A wrong EXPOSED costs customer trust.
2. **Coverage visibility.** Per-subscription health showing what was scanned, what was INCONCLUSIVE, and which permission is missing, so a quiet dashboard means "safe", not "not scanned".
3. **Rate-limit and failure testing** at 3,000 subscriptions.
4. **Noise controls.** Severity (e.g. raise it when the VM identity is privileged), grouping, suppressions.

### Extending to AWS and GCP
- **The shared question:** does every layer on the path from the internet allow this traffic?
- **The plan:** each provider gets its own collector and path evaluator emitting the same `Finding`; reporting, the finding lifecycle, and scheduling are shared.
- **The path per provider:**
  - **AWS:** public IP + a route to an internet gateway, then the network ACL (stateless, ordered, with Deny rules), then the security group (allow-only, any rule allows).
  - **GCP:** external IP, then hierarchical firewall policies (organization, then folder), then VPC firewall rules by priority, matched on network tags or service accounts.

## What I'd do next
1. **Live read-only mode:** a small collector (Resource Graph or SDK) writing the same inventory JSON.
2. **Raise severity** when the VM's managed identity holds Owner or Contributor (check 1 + check 3).
3. **Cover the remaining paths:** Load Balancer inbound NAT and rules, AVNM security admin rules, IPv6.
4. **Validate more broadly:** one live VM already matches Network Watcher IP flow verify (see Bonus). Next comes a corpus of real configurations: Deny overrides, subnet NSGs, and look-alikes.
5. **Severity by service:** e.g. an internet-exposed Redis or MongoDB (often unauthenticated) above SSH.
6. **Compact output at scale:** one line per look-alike by default, with full evidence behind a `--verbose` flag. The demo prints full evidence on purpose, since the look-alikes are what the brief asks to see.

## Bonus: Aikido scan of a live test VM
I connected a personal Azure subscription to Aikido. The connection is read-only, using the Security Reader and Log Analytics Reader roles. The subscription held one VM built like the `vm-exposed-ssh` fixture:
- a Standard public IP;
- an NSG on the NIC allowing TCP 22 from `Any` (`default-allow-ssh`, priority 1000);
- no NSG on the subnet;
- no admin rules.

The VM was really reachable over SSH from the internet ([Azure network settings](docs/bonus/azure-vm-networking.png)). The test resources were removed after the scan.

**What Aikido reported** ([all findings](docs/bonus/aikido-findings.png)): five findings, all Low. The SSH one ([detail](docs/bonus/aikido-ssh-finding.png)):
- is "Network Security Group allows SSH access from entire Internet", reported on the **NSG** resource;
- has a risk score of 18 (Low), marked "Downgraded: AI assessed cloud issue to be less severe".

**Compared with this scanner:** the same configuration is the `vm-exposed-ssh` demo case, which this scanner reports as **EXPOSED**. To confirm it on the real data, I exported the five resource types from the live subscription with read-only ARM calls (`fixtures/live-azure.json`, with the SSH public key removed), and asked Azure directly:
- **This scanner:** `python3 scan.py fixtures/live-azure.json` reports **EXPOSED** on 22/tcp, deciding rule `default-allow-ssh` (priority 1000), no subnet NSG, public IP `135.225.57.85`.
- **Azure Network Watcher IP flow verify** (internet host `8.8.8.8` to `10.0.0.4:22`): `"access": "Allow", "ruleName": "securityRules/default-allow-ssh"`.

Both agree on the verdict and on the deciding rule.

**Takeaway:** Aikido found the misconfiguration. From the finding alone, though, you can't tell whether a VM is actually reachable through that NSG, and I don't know what the AI downgrade took into account. Evaluating the whole path could do two things:
- confirm this case as a real exposure and raise its priority;
- keep look-alikes low, such as an NSG on a VM with no public IP or an NSG overridden by the subnet layer.

That is the precision argument behind [check 1](#1-proposed-checks).

## Layout
```
scan.py                 CLI
scanner/inventory.py    load ARM-shaped JSON, look up by resource id   (Azure-specific)
scanner/nsg.py          evaluate one NSG for internet traffic            (Azure-specific)
scanner/ipset.py        IPv4 address-range arithmetic (union, intersect, subtract)
scanner/exposure.py     walk VM → NIC → public IP / subnet NSG / NIC NSG, decide the verdict
scanner/finding.py      provider-neutral Finding / Evidence
scanner/report.py       text and JSON output
fixtures/demo.json      demo inventory, one VM per scenario
fixtures/live-azure.json  export of the live test subscription (bonus)
tests/                  scenario and rule-matching tests
docs/bonus/             screenshots of the Aikido scan (bonus)
```
