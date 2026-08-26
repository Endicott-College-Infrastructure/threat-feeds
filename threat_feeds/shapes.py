"""
Per-profile selection logic: how a shape's validated networks get ordered
and/or filtered before a budget (if any) truncates the list.

Each function takes already-fetched feed results (see fetch.py) and returns
networks in priority order -- best-first -- so truncation at any budget
keeps the highest-value entries, never an address-order accident. That
accident is exactly what the "none" and "size-ranked" methods exist to fix:
measured 2026-08-26, address-order truncation of spamhaus-drop at 200
entries covered only 28.5% of its address space; ranking by network size
first covers 89.0% from the same 200 slots.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter

from . import geo, validate

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# How many /24 candidates (ranked by raw attacker count) get a geo lookup
# before the US-or-unannounced filter is applied. Bounded so a pathologically
# large feed can't turn every run into tens of thousands of whois lookups --
# sized against the SIP shape's measured real candidate pool (low thousands
# of /24s), not an arbitrary round number.
SIP_CANDIDATE_POOL = 5000

# The sip shape's whole design assumes near-host-granularity entries --
# measured 2026-08-25, blocklist-de-sip and voipbl are >99.9% /32s, with only
# a handful of entries as wide as /24. A network wider than /24 here is a
# data anomaly (or, since voipbl is fetched over plain HTTP -- see AGENTS.md
# section 1 -- possibly a tampered one), not a legitimate single attacker.
# Two independent reasons to reject it outright rather than just enumerate
# it faster: enumerating a /8's ~16.7M addresses is a real CPU/memory
# problem, and -- worse -- density-ranking by raw address count would let
# one such entry fabricate thousands of maximum-density /24 buckets that
# never actually appeared in any feed, potentially crowding out real
# attacker-dense blocks in the published result.
SIP_MAX_NETWORK_WIDTH = 24


def _validated_networks(feed_results) -> list[IPNetwork]:
    """
    Every v4 network from every successfully-fetched feed, bogon-filtered,
    with rejections logged per feed so it's clear which source produced them.
    """
    all_networks: list[IPNetwork] = []
    for r in feed_results:
        if not r.fetched:
            continue
        v4 = [n for n in r.networks if n.version == 4]
        safe, rejected = validate.filter_safe(v4)
        if rejected:
            log.warning("%s: rejected networks by reason: %s", r.name, dict(rejected))
        all_networks.extend(safe)
    return all_networks


def select_none(feed_results) -> list[IPNetwork]:
    """No ranking, no filtering -- validate and collapse only. For uncapped profiles."""
    return list(ipaddress.collapse_addresses(_validated_networks(feed_results)))


def select_size_ranked(feed_results) -> list[IPNetwork]:
    """
    Rank by network size, largest first.

    Sized against spamhaus-drop specifically: it mixes huge historical
    netblocks with small recent additions, and size -- not recency or
    address value -- is what determines how much protection one object slot
    buys. See module docstring for the measured before/after.
    """
    collapsed = list(ipaddress.collapse_addresses(_validated_networks(feed_results)))
    return sorted(collapsed, key=lambda n: -n.num_addresses)


def select_geo_density_ranked(feed_results, geo_cache: geo.GeoCache) -> list[IPNetwork]:
    """
    Bucket every validated address into its /24, keep only US-allocated or
    confirmed-unannounced blocks, rank surviving /24s by distinct-attacker
    count descending, and emit them as /24 networks.

    Emitting the containing /24 rather than individual /32s is the entire
    point: measured 2026-08-26, SIP attackers cluster heavily (129,714
    addresses in only 50,596 distinct /24s), so a slot-limited consumer gets
    vastly more coverage per object this way than from a flat address list.
    Aggregating WIDER than /24 was measured and rejected -- real hostile
    networks in this data are lone /24s; anything wider mixes in enormous
    benign space at near-zero density (e.g. a /10 at 0.0% density). See
    AGENTS.md section 2 for the full density table.

    Non-US space is excluded because it is redundant with this org's on-box
    Geo-IP filtering for the rules this feed protects -- confirmed against
    the actual rule scope, not assumed. US-allocated-but-unannounced space is
    included deliberately (see geo.is_us_or_unannounced), on the reasoning
    that no legitimate SIP traffic originates from unrouted address space.
    """
    validated = _validated_networks(feed_results)

    wide = [n for n in validated if n.prefixlen < SIP_MAX_NETWORK_WIDTH]
    if wide:
        log.warning(
            "sip: %d network(s) wider than /%d rejected outright (not enumerated) -- "
            "this shape assumes near-host-granularity entries; anything this wide is "
            "a data anomaly or a tampered feed, not a legitimate single attacker: %s",
            len(wide),
            SIP_MAX_NETWORK_WIDTH,
            [str(n) for n in wide[:10]],
        )
    narrow_enough = [n for n in validated if n.prefixlen >= SIP_MAX_NETWORK_WIDTH]

    addrs: set[int] = set()
    for n in narrow_enough:
        for a in n:
            addrs.add(int(a))

    buckets: Counter = Counter(a >> 8 for a in addrs)
    candidates = buckets.most_common(SIP_CANDIDATE_POOL)
    if len(buckets) > SIP_CANDIDATE_POOL:
        log.warning(
            "sip: %d distinct /24s found, only the top %d (by raw attacker count) "
            "were considered for the geo filter -- the rest are dropped before "
            "geo resolution even runs",
            len(buckets),
            SIP_CANDIDATE_POOL,
        )

    rep_ips = [
        str(ipaddress.IPv4Address((bucket << 8) + 1)) for bucket, _ in candidates
    ]
    resolved = geo_cache.resolve(rep_ips)

    kept = [
        (bucket, count)
        for (bucket, count), ip in zip(candidates, rep_ips)
        if geo.is_us_or_unannounced(resolved.get(ip, geo.LOOKUP_FAILED))
    ]
    kept.sort(key=lambda bc: -bc[1])
    log.info(
        "sip: %d/%d candidate /24s kept after the US-or-unannounced filter",
        len(kept),
        len(candidates),
    )
    return [ipaddress.IPv4Network((bucket << 8, 24)) for bucket, _ in kept]


SELECTORS = {
    "none": select_none,
    "size-ranked": select_size_ranked,
    "geo-density-ranked": select_geo_density_ranked,  # needs geo_cache -- see build.py
}
