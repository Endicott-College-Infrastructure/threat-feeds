"""
Resolve IPv4 addresses to (ASN, country, AS name) via Team Cymru's bulk whois
service, with a local on-disk cache.

WHY A CACHE, NOT A FRESH LOOKUP EVERY RUN

The sync job runs hourly (see ops/systemd/threat-feeds-sync.timer). ASN and
country attribution for a given address changes on the timescale of BGP
reallocations -- weeks to years, not hours. Re-resolving thousands of
candidate /24s against a free, community-run whois service every single hour
would be needless load on it, for data that essentially never changes
between runs. A 7-day TTL means Cymru sees a burst of lookups roughly once a
week per candidate address, not 168 times.

PROTOCOL

whois.cymru.com:43, bulk mode: send "begin\\nverbose\\n<ip>\\n...\\nend\\n",
read back one pipe-delimited line per IP:
    asn | ip | bgp prefix | country | registry | allocated | as name
Cymru reports an address with no BGP-announcing ASN as asn="NA" -- that is a
real, meaningful answer ("allocated but not announced"), distinct from OUR
own failure marker below for "the lookup itself didn't work."
"""

from __future__ import annotations

import json
import logging
import socket
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
BATCH_SIZE = 1000
SOCKET_TIMEOUT_SECONDS = 60
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class GeoInfo:
    asn: str
    country: str
    as_name: str


# Our OWN marker for "we tried to resolve this and couldn't" -- e.g. Cymru
# was unreachable for this batch. Deliberately NOT the same as Cymru's own
# asn="NA" ("allocated, not BGP-announced"), which is a real answer this
# module's callers are meant to treat as included, not unknown. A lookup
# failure must fail closed (excluded), not be silently treated as
# unannounced-and-therefore-included.
LOOKUP_FAILED = GeoInfo(asn="", country="??", as_name="lookup-failed")


def _query_cymru(ips: list[str]) -> dict[str, GeoInfo]:
    """One bulk-mode round-trip. Raises OSError on connection failure."""
    payload = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    chunks = []
    with socket.create_connection(
        (CYMRU_HOST, CYMRU_PORT), timeout=SOCKET_TIMEOUT_SECONDS
    ) as s:
        s.sendall(payload.encode())
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="ignore")

    out: dict[str, GeoInfo] = {}
    for line in text.splitlines():
        if "|" not in line or line.lower().startswith("bulk mode"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        asn, ip, _prefix, cc, _registry, _allocated, as_name = parts[:7]
        out[ip] = GeoInfo(asn=asn, country=cc, as_name=as_name)
    return out


class GeoCache:
    """On-disk cache of IP -> GeoInfo, TTL-expired or missing entries re-resolved."""

    def __init__(self, path: Path):
        self.path = path
        self._data: dict[str, dict] = {}
        if path.is_file():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError) as e:
                log.warning(
                    "geo cache at %s unreadable (%s) -- starting fresh", path, e
                )
                self._data = {}

    def resolve(self, ips: list[str]) -> dict[str, GeoInfo]:
        """Resolve every address, using the cache where it's still fresh."""
        now = time.time()
        result: dict[str, GeoInfo] = {}
        stale_or_missing: list[str] = []

        for ip in ips:
            entry = self._data.get(ip)
            if entry and (now - entry.get("resolved_at", 0)) < CACHE_TTL_SECONDS:
                result[ip] = GeoInfo(
                    asn=entry["asn"], country=entry["country"], as_name=entry["as_name"]
                )
            else:
                stale_or_missing.append(ip)

        if stale_or_missing:
            log.info(
                "geo cache: %d/%d addresses need a live lookup (%d served from cache)",
                len(stale_or_missing),
                len(ips),
                len(ips) - len(stale_or_missing),
            )
            for i in range(0, len(stale_or_missing), BATCH_SIZE):
                batch = stale_or_missing[i : i + BATCH_SIZE]
                try:
                    resolved = _query_cymru(batch)
                except OSError as e:
                    log.warning(
                        "Cymru lookup failed for a batch of %d addresses (%s) -- "
                        "those addresses are excluded from any US-scoped profile "
                        "this run, not silently included",
                        len(batch),
                        e,
                    )
                    resolved = {}
                for ip in batch:
                    info = resolved.get(ip, LOOKUP_FAILED)
                    result[ip] = info
                    # Do NOT cache a failure: this dict is exactly what gets
                    # persisted below, and stamping it with resolved_at=now
                    # would make a transient Cymru outage look as fresh as a
                    # real answer -- stuck excluded for the full TTL instead
                    # of retried on the very next run. Simply not writing an
                    # entry means it stays in "stale_or_missing" next time.
                    if info is not LOOKUP_FAILED:
                        self._data[ip] = {
                            "asn": info.asn,
                            "country": info.country,
                            "as_name": info.as_name,
                            "resolved_at": now,
                        }
            self._save()

        return result

    def _save(self) -> None:
        try:
            self.path.write_text(json.dumps(self._data), encoding="utf-8")
        except OSError as e:
            log.warning(
                "could not write geo cache to %s (%s) -- will re-resolve next run",
                self.path,
                e,
            )


def is_us_or_unannounced(info: GeoInfo) -> bool:
    """
    True if this address belongs in the SIP shape's slot-limited profile:
    US-allocated, OR allocated-but-not-announced in BGP.

    Unannounced address space is included DELIBERATELY, not by omission --
    see AGENTS.md section 2 for the justification (no legitimate SIP traffic
    is expected from unrouted space; the false-positive risk there is
    accepted on purpose). A failed lookup (LOOKUP_FAILED) is neither of
    these and is correctly excluded by the checks below.
    """
    if info.country == "US":
        return True
    return info.asn == "NA"
