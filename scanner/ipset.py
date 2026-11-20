"""Sets of IPv4 addresses as sorted, non-overlapping inclusive integer ranges.

Used to answer "which internet sources can reach this port?" exactly, across many
rules and both NSG layers, instead of judging one rule at a time. Provider-neutral.
"""
from __future__ import annotations

import ipaddress

IpSet = list[tuple[int, int]]  # [(first, last), ...], sorted, non-overlapping, non-adjacent

# Address space that is never "the internet" (private, loopback, link-local, CGNAT,
# multicast and reserved). Documentation ranges (TEST-NETs) are deliberately kept, so
# examples such as 203.0.113.0/24 behave like real public ranges.
_NON_INTERNET = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                 "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"]


def from_cidr(cidr: str) -> IpSet:
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [(int(net.network_address), int(net.broadcast_address))]


def normalize(ranges: IpSet) -> IpSet:
    out: IpSet = []
    for first, last in sorted(ranges):
        if out and first <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], last))
        else:
            out.append((first, last))
    return out


def union(a: IpSet, b: IpSet) -> IpSet:
    return normalize(a + b)


def intersect(a: IpSet, b: IpSet) -> IpSet:
    out: IpSet = []
    i = j = 0
    while i < len(a) and j < len(b):
        first, last = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if first <= last:
            out.append((first, last))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a: IpSet, b: IpSet) -> IpSet:
    out: IpSet = []
    for first, last in a:
        for b_first, b_last in b:
            if b_last < first or b_first > last:
                continue
            if b_first > first:
                out.append((first, b_first - 1))
            first = b_last + 1
            if first > last:
                break
        if first <= last:
            out.append((first, last))
    return out


def size(s: IpSet) -> int:
    return sum(last - first + 1 for first, last in s)


def to_cidrs(s: IpSet, limit: int = 3) -> str:
    """Human summary, e.g. '203.0.113.0/24, 198.51.100.7/32' (first `limit` blocks)."""
    cidrs = [str(c) for first, last in s for c in ipaddress.summarize_address_range(
        ipaddress.IPv4Address(first), ipaddress.IPv4Address(last))]
    more = f" and {len(cidrs) - limit} more" if len(cidrs) > limit else ""
    return ", ".join(cidrs[:limit]) + more


PUBLIC_IPV4: IpSet = subtract([(0, 2**32 - 1)], normalize([r for c in _NON_INTERNET for r in from_cidr(c)]))
