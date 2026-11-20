#!/usr/bin/env python3
"""Azure internet-exposure scanner (PoC). Standard library only.

    python3 scan.py                         # scan fixtures/demo.json
    python3 scan.py inventory.json --ports 22,3389 --json

Exit codes: 0 nothing EXPOSED, 1 at least one port EXPOSED, 2 invalid input.
"""
import argparse
import os
import sys

from scanner.exposure import scan
from scanner.finding import EXPOSED, SENSITIVE_PORTS
from scanner.inventory import Inventory
from scanner.report import to_json, to_text

DEFAULT_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "demo.json")
MAX_PORT = 65535  # highest TCP port number


def port_list(value: str) -> list[int]:
    try:
        ports = [int(p) for p in value.split(",") if p.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected comma-separated port numbers, got {value!r}")
    if not ports or any(not 1 <= p <= MAX_PORT for p in ports):
        raise argparse.ArgumentTypeError(f"ports must be between 1 and {MAX_PORT}, got {value!r}")
    return list(dict.fromkeys(ports))  # drop duplicates, keep order


def main() -> int:
    parser = argparse.ArgumentParser(description="Find Azure VMs reachable from the internet on sensitive ports.")
    parser.add_argument("inventory", nargs="?", default=DEFAULT_FIXTURE, help="ARM-shaped inventory JSON")
    parser.add_argument("--ports", type=port_list, default=list(SENSITIVE_PORTS),
                        help=f"comma-separated TCP ports (default: {','.join(map(str, SENSITIVE_PORTS))})")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()  # exits with code 2 and a usage message on bad arguments

    try:
        inventory = Inventory.load(args.inventory)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as err:  # unreadable file, invalid JSON, wrong shape
        print(f"error: cannot load inventory {args.inventory!r}: {err}", file=sys.stderr)
        return 2

    findings = scan(inventory, args.ports)
    print(to_json(findings) if args.json else to_text(findings, os.path.relpath(args.inventory), args.ports))
    return 1 if any(f.status == EXPOSED for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
