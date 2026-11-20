"""The range arithmetic is checked against plain Python sets on a small address universe."""
import random
import unittest

from scanner import ipset


def random_set(rng):
    ranges = []
    for _ in range(rng.randint(0, 4)):
        first = rng.randint(0, 60)
        ranges.append((first, first + rng.randint(0, 8)))
    return ipset.normalize(ranges)


def members(s):
    return {n for first, last in s for n in range(first, last + 1)}


class IpSetMatchesPythonSets(unittest.TestCase):
    def test_operations_on_random_sets(self):
        rng = random.Random(7)
        for _ in range(2000):
            a, b = random_set(rng), random_set(rng)
            self.assertEqual(members(ipset.union(a, b)), members(a) | members(b))
            self.assertEqual(members(ipset.intersect(a, b)), members(a) & members(b))
            self.assertEqual(members(ipset.subtract(a, b)), members(a) - members(b))
            self.assertEqual(ipset.size(a), len(members(a)))

    def test_public_space_excludes_private_ranges(self):
        for private in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"):
            self.assertEqual(ipset.intersect(ipset.PUBLIC_IPV4, ipset.from_cidr(private)), [], private)
        self.assertEqual(ipset.to_cidrs(ipset.intersect(ipset.PUBLIC_IPV4, ipset.from_cidr("8.8.8.0/24"))),
                         "8.8.8.0/24")


if __name__ == "__main__":
    unittest.main()
