"""
Unit tests for the SIP shape's geo classification -- geo.py's
is_us_or_unannounced, and GeoCache's cache-hit/expiry/failure behavior.
None of these touch the network: GeoCache.resolve is exercised with a
monkeypatched _query_cymru so cache logic is tested independently of Cymru's
actual availability.

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threat_feeds import geo


class TestIsUsOrUnannounced(unittest.TestCase):
    def test_us_country_is_included(self):
        info = geo.GeoInfo(asn="15169", country="US", as_name="GOOGLE")
        self.assertTrue(geo.is_us_or_unannounced(info))

    def test_confirmed_unannounced_is_included(self):
        # Cymru's own signal for "allocated, no BGP-announcing ASN" -- a
        # real answer, deliberately included per the SIP shape's policy.
        info = geo.GeoInfo(asn="NA", country="??", as_name="NA")
        self.assertTrue(geo.is_us_or_unannounced(info))

    def test_non_us_announced_is_excluded(self):
        info = geo.GeoInfo(asn="4837", country="CN", as_name="CHINA-UNICOM")
        self.assertFalse(geo.is_us_or_unannounced(info))

    def test_failed_lookup_is_excluded_not_treated_as_unannounced(self):
        # The critical distinction this module exists to enforce: OUR OWN
        # "couldn't resolve this" marker must NOT be conflated with Cymru's
        # "confirmed unannounced" -- a transient failure fails closed.
        self.assertFalse(geo.is_us_or_unannounced(geo.LOOKUP_FAILED))
        self.assertNotEqual(geo.LOOKUP_FAILED.asn, "NA")


class TestGeoCache(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = Path(self._tmpdir.name) / "cache.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_fresh_cache_queries_cymru_for_everything(self):
        cache = geo.GeoCache(self.cache_path)
        with mock.patch.object(
            geo,
            "_query_cymru",
            return_value={"1.2.3.4": geo.GeoInfo("1234", "US", "TEST")},
        ) as mocked:
            result = cache.resolve(["1.2.3.4"])
        mocked.assert_called_once()
        self.assertEqual(result["1.2.3.4"].country, "US")

    def test_unexpired_entry_served_from_cache_no_query(self):
        cache = geo.GeoCache(self.cache_path)
        with mock.patch.object(
            geo,
            "_query_cymru",
            return_value={"1.2.3.4": geo.GeoInfo("1234", "US", "TEST")},
        ):
            cache.resolve(["1.2.3.4"])  # populates the cache

        with mock.patch.object(geo, "_query_cymru") as mocked:
            result = cache.resolve(["1.2.3.4"])
        mocked.assert_not_called()
        self.assertEqual(result["1.2.3.4"].country, "US")

    def test_expired_entry_is_re_resolved(self):
        cache = geo.GeoCache(self.cache_path)
        with mock.patch.object(
            geo,
            "_query_cymru",
            return_value={"1.2.3.4": geo.GeoInfo("1234", "US", "TEST")},
        ):
            cache.resolve(["1.2.3.4"])

        # Force the cached entry to look like it was resolved long enough
        # ago to have expired, without waiting CACHE_TTL_SECONDS for real.
        cache._data["1.2.3.4"]["resolved_at"] = time.time() - geo.CACHE_TTL_SECONDS - 1

        with mock.patch.object(
            geo,
            "_query_cymru",
            return_value={"1.2.3.4": geo.GeoInfo("5678", "CA", "OTHER")},
        ) as mocked:
            result = cache.resolve(["1.2.3.4"])
        mocked.assert_called_once()
        self.assertEqual(result["1.2.3.4"].country, "CA")

    def test_connection_failure_marks_addresses_as_lookup_failed_not_dropped(self):
        cache = geo.GeoCache(self.cache_path)
        with mock.patch.object(geo, "_query_cymru", side_effect=OSError("unreachable")):
            result = cache.resolve(["9.9.9.9"])
        self.assertIn("9.9.9.9", result)
        self.assertEqual(result["9.9.9.9"], geo.LOOKUP_FAILED)

    def test_cache_persists_to_disk_and_reloads(self):
        cache = geo.GeoCache(self.cache_path)
        with mock.patch.object(
            geo,
            "_query_cymru",
            return_value={"1.2.3.4": geo.GeoInfo("1234", "US", "TEST")},
        ):
            cache.resolve(["1.2.3.4"])

        self.assertTrue(self.cache_path.is_file())
        reloaded = geo.GeoCache(self.cache_path)
        with mock.patch.object(geo, "_query_cymru") as mocked:
            result = reloaded.resolve(["1.2.3.4"])
        mocked.assert_not_called()
        self.assertEqual(result["1.2.3.4"].country, "US")

    def test_unreadable_cache_file_starts_fresh_instead_of_crashing(self):
        self.cache_path.write_text("not valid json {{{", encoding="utf-8")
        cache = geo.GeoCache(self.cache_path)  # must not raise
        self.assertEqual(cache._data, {})


if __name__ == "__main__":
    unittest.main()
