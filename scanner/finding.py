"""Provider-neutral finding model. Only this is rendered by report.py, so an AWS or GCP
evaluator could emit the same structure without changing the output layer."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

EXPOSED = "EXPOSED"
NOT_EXPOSED = "NOT_EXPOSED"
INCONCLUSIVE = "INCONCLUSIVE"  # required data/permissions were missing; never reported as a pass
STATUS_ORDER = [EXPOSED, INCONCLUSIVE, NOT_EXPOSED]  # report order: most urgent first

# Default ports checked: remote admin and databases, the most attacked services when exposed.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
}


@dataclass(frozen=True)
class Evidence:
    layer: str      # step on the network path, e.g. "public IP", "subnet NSG"
    control: str    # the resource that decided this step
    decision: str   # e.g. ALLOW, DENY, NO NSG, UNKNOWN
    detail: str     # the rule / fact behind the decision


@dataclass
class Finding:
    provider: str
    resource_id: str
    resource_name: str
    status: str
    ports: list[int]
    reason: str                 # one-line conclusion
    path: str                   # e.g. "198.51.100.10 -> 10.0.1.4 (nic-x/ipconfig1)"
    evidence: list[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
