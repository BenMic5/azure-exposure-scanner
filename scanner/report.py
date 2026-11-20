"""Render findings as readable text or JSON. Knows only the provider-neutral Finding."""
from __future__ import annotations

import json
import textwrap
from dataclasses import asdict

from .finding import SENSITIVE_PORTS, STATUS_ORDER, Finding

WIDTH = 120  # fixed, so output is identical in a terminal, a pipe, and the README


def _wrap(text: str, prefix: str, indent: str = "") -> str:
    # Never split resource names or ids (they contain hyphens) across lines.
    return textwrap.fill(text, WIDTH, initial_indent=prefix, subsequent_indent=indent or " " * len(prefix),
                         break_long_words=False, break_on_hyphens=False)


def _ports(ports: list[int], checked: list[int]) -> str:
    if not ports or (len(checked) > 1 and sorted(ports) == sorted(checked)):
        return "all checked ports"
    return ", ".join(f"{p}/tcp ({SENSITIVE_PORTS[p]})" if p in SENSITIVE_PORTS else f"{p}/tcp" for p in ports)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def to_text(findings: list[Finding], source: str, ports: list[int]) -> str:
    lines = [f"Internet-exposure scan of {source}",
             f"Question: can the internet at large open TCP to {', '.join(map(str, ports))} on each VM?", ""]
    # Size the evidence columns to their contents so detail text gets the most room.
    evidence = [e for f in findings for e in f.evidence]
    w_layer = max((len(e.layer) for e in evidence), default=0)
    w_control = max((len(e.control) for e in evidence), default=0)
    w_decision = max((len(e.decision) for e in evidence), default=0)
    for f in findings:
        lines.append(_wrap(f"[{f.status}] {f.resource_name}: {_ports(f.ports, ports)}", "", indent="  "))
        lines.append(_wrap(f.reason, "  why:  "))
        if f.evidence:
            lines.append(f"  path: {f.path}")
            for i, e in enumerate(f.evidence, 1):
                lines.append(_wrap(e.detail, f"    {i}. {e.layer:<{w_layer}}  {e.control:<{w_control}}  {e.decision:<{w_decision}}  "))
        if f.remediation:
            lines.append(_wrap(f.remediation, "  fix:  "))
        lines.append("")
    vms = len({f.resource_id for f in findings})
    counts = ", ".join(f"{sum(f.status == s for f in findings)} {s}" for s in STATUS_ORDER)
    lines.append(f"Summary: {_plural(vms, 'VM')}, {_plural(len(findings), 'result')}: {counts}")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)
