"""
Unit tests for the safety-critical gates: validate.py and git_store's delta gate.

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_feeds import validate
from threat_feeds.git_store import DEFAULT_MAX_DELTA_PCT, GateRefusalError, check_delta


class TestRejectionReason(unittest.TestCase):
    def test_accepts_a_normal_spamhaus_style_range(self):
        # 1.2.3.0/24 is real APNIC-assigned public space, not a documentation/
        # reserved block -- 198.51.100.0/24 and 203.0.113.0/24 are TEST-NET
        # ranges that ipaddress correctly reports as private, so they're wrong
        # fixtures for "an ordinary public entry."
        net = ipaddress.ip_network("1.2.3.0/24")
        self.assertIsNone(validate.rejection_reason(net))

    def test_rejects_default_route(self):
        net = ipaddress.ip_network("0.0.0.0/0")
        self.assertIsNotNone(validate.rejection_reason(net))

    def test_rejects_overly_broad_prefix(self):
        # Narrower than /0 but still far broader than any legitimate feed entry --
        # this is the "parsing bug produced a huge range" case the gate exists for.
        # strict=False mirrors fetch.py's parsing, which never assumes a feed's
        # CIDR is aligned to its own prefix.
        net = ipaddress.ip_network("11.0.0.0/6", strict=False)
        self.assertIsNotNone(validate.rejection_reason(net))

    def test_rejects_rfc1918(self):
        net = ipaddress.ip_network("192.168.1.0/24")
        self.assertIsNotNone(validate.rejection_reason(net))

    def test_rejects_loopback(self):
        net = ipaddress.ip_network("127.0.0.0/8")
        self.assertIsNotNone(validate.rejection_reason(net))

    def test_filter_safe_splits_and_counts(self):
        networks = [
            ipaddress.ip_network("1.2.3.0/24"),
            ipaddress.ip_network("0.0.0.0/0"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        safe, reasons = validate.filter_safe(networks)
        self.assertEqual(len(safe), 1)
        self.assertEqual(sum(reasons.values()), 2)


class TestDeltaGate(unittest.TestCase):
    def test_bootstrap_case_never_gates(self):
        # No previous commit yet -- must not raise, regardless of new_count.
        check_delta(None, 50000, DEFAULT_MAX_DELTA_PCT)

    def test_small_change_passes(self):
        check_delta(1000, 1050, DEFAULT_MAX_DELTA_PCT)

    def test_large_shrink_is_refused(self):
        with self.assertRaises(GateRefusalError):
            check_delta(1000, 100, DEFAULT_MAX_DELTA_PCT)

    def test_large_growth_is_refused(self):
        with self.assertRaises(GateRefusalError):
            check_delta(1000, 5000, DEFAULT_MAX_DELTA_PCT)


if __name__ == "__main__":
    unittest.main()
