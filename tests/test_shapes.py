"""
Unit tests for per-profile selection logic in shapes.py.

select_geo_density_ranked is tested with a stubbed GeoCache (no network) --
the important behavior under test is the /24 bucketing, ranking, and
US-or-unannounced filter, not Cymru's actual answers.

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_feeds import geo, shapes
from threat_feeds.fetch import FeedResult


def _result(name: str, cidrs: list[str]) -> FeedResult:
    return FeedResult(
        name=name,
        url="https://example.invalid",
        networks=[ipaddress.ip_network(c) for c in cidrs],
        fetched=True,
    )


class TestSelectNone(unittest.TestCase):
    def test_validates_and_collapses_but_does_not_reorder_meaningfully(self):
        results = [_result("feodotracker", ["1.2.3.0/24", "192.168.1.0/24"])]
        out = shapes.select_none(results)
        # 192.168.1.0/24 is RFC1918 -- must be rejected by validate.py.
        self.assertEqual(out, [ipaddress.ip_network("1.2.3.0/24")])

    def test_unfetched_feed_contributes_nothing(self):
        unfetched = FeedResult(name="down", url="x", fetched=False, error="timeout")
        out = shapes.select_none([unfetched])
        self.assertEqual(out, [])


class TestSelectSizeRanked(unittest.TestCase):
    def test_largest_network_comes_first(self):
        # 203.0.113.0/24 and 198.51.100.0/24 are reserved TEST-NET documentation
        # ranges that ipaddress correctly flags as private -- using them here
        # would degenerate this to a single-element list. Use real public space.
        results = [_result("spamhaus-drop", ["3.2.3.0/24", "1.0.0.0/8", "3.2.4.0/28"])]
        out = shapes.select_size_ranked(results)
        sizes = [n.num_addresses for n in out]
        self.assertEqual(len(out), 3)
        self.assertEqual(sizes, sorted(sizes, reverse=True))
        self.assertEqual(out[0], ipaddress.ip_network("1.0.0.0/8"))

    def test_truncating_size_ranked_keeps_more_address_space_than_address_order(self):
        # The exact bug measured 2026-08-25/26: address-order truncation of
        # a mixed feed covers far less space than size-ranked truncation of
        # the same budget, because a large valuable block can sort anywhere
        # in address order regardless of its size. Put the one big block at
        # a HIGH address, after 20 small /24s at low addresses, so
        # address-order truncation at a small budget misses it entirely.
        small_24s = [f"1.2.{i}.0/24" for i in range(20)]
        cidrs = small_24s + ["200.0.0.0/16"]
        results = [_result("mixed", cidrs)]

        address_order = sorted(
            [
                ipaddress.ip_network(c)
                for c in cidrs
                if not ipaddress.ip_network(c).is_private
            ],
            key=lambda n: int(n.network_address),
        )
        size_ranked = shapes.select_size_ranked(results)

        budget = 3
        address_order_covered = sum(n.num_addresses for n in address_order[:budget])
        size_ranked_covered = sum(n.num_addresses for n in size_ranked[:budget])
        self.assertGreater(size_ranked_covered, address_order_covered)
        self.assertIn(ipaddress.ip_network("200.0.0.0/16"), size_ranked[:budget])
        self.assertNotIn(ipaddress.ip_network("200.0.0.0/16"), address_order[:budget])


class TestSelectGeoDensityRanked(unittest.TestCase):
    def _cache_returning(self, answers: dict) -> geo.GeoCache:
        """A GeoCache whose resolve() returns canned answers, no network."""
        cache = mock.MagicMock(spec=geo.GeoCache)
        cache.resolve.side_effect = lambda ips: {
            ip: answers.get(ip, geo.LOOKUP_FAILED) for ip in ips
        }
        return cache

    def test_denser_24_ranks_before_sparser_24(self):
        # 5 distinct addresses in 1.2.0.0/24, 2 in 1.2.1.0/24
        cidrs = [f"1.2.0.{i}/32" for i in range(1, 6)] + [
            f"1.2.1.{i}/32" for i in range(1, 3)
        ]
        results = [_result("voipbl", cidrs)]
        us_everywhere = self._cache_returning(
            {
                "1.2.0.1": geo.GeoInfo("1", "US", "TEST"),
                "1.2.1.1": geo.GeoInfo("1", "US", "TEST"),
            }
        )
        out = shapes.select_geo_density_ranked(results, us_everywhere)
        self.assertEqual(out[0], ipaddress.ip_network("1.2.0.0/24"))
        self.assertEqual(out[1], ipaddress.ip_network("1.2.1.0/24"))

    def test_non_us_announced_24_is_excluded(self):
        cidrs = [f"1.2.0.{i}/32" for i in range(1, 6)] + [
            f"1.2.1.{i}/32" for i in range(1, 3)
        ]
        results = [_result("voipbl", cidrs)]
        mixed = self._cache_returning(
            {
                "1.2.0.1": geo.GeoInfo("1", "US", "TEST"),
                "1.2.1.1": geo.GeoInfo("2", "CN", "OTHER"),
            }
        )
        out = shapes.select_geo_density_ranked(results, mixed)
        self.assertEqual(out, [ipaddress.ip_network("1.2.0.0/24")])

    def test_unannounced_24_is_included(self):
        cidrs = [f"1.2.0.{i}/32" for i in range(1, 3)]
        results = [_result("voipbl", cidrs)]
        unannounced = self._cache_returning(
            {
                "1.2.0.1": geo.GeoInfo("NA", "??", "NA"),
            }
        )
        out = shapes.select_geo_density_ranked(results, unannounced)
        self.assertEqual(out, [ipaddress.ip_network("1.2.0.0/24")])

    def test_lookup_failure_excludes_rather_than_includes(self):
        cidrs = [f"1.2.0.{i}/32" for i in range(1, 3)]
        results = [_result("voipbl", cidrs)]
        failing = self._cache_returning({})  # every lookup misses -> LOOKUP_FAILED
        out = shapes.select_geo_density_ranked(results, failing)
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()
