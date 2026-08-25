"""
Reject any parsed network that must never end up in a firewall blocklist rule.

This is the safety-critical gate in this repo. The output of this module becomes
a live block rule on every device pointed at the same feed URL (see README.md).
A single malformed feed line -- or a tampered one; VoIPBL's source is plain
HTTP, see AGENTS.md section 1 -- must not be able to blackhole campus traffic
just because it happened to parse as valid CIDR.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import Counter

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Anything broader than this is refused outright, regardless of which feed it came
# from. Spamhaus DROP itself -- the broadest legitimate source in feeds.json --
# does not list anything wider than /8. A parsed network broader than that is far
# more likely a parsing bug or a tampered feed than a real entry, and blocking a
# /7 or wider is an outage, not a security control.
MIN_PREFIX_LENGTH_V4 = 8
MIN_PREFIX_LENGTH_V6 = 32


def rejection_reason(network: IPNetwork) -> str | None:
    """Why this network must not be committed, or None if it's safe to keep."""
    if network.version == 4:
        if network.prefixlen < MIN_PREFIX_LENGTH_V4:
            return f"broader than /{MIN_PREFIX_LENGTH_V4} (is /{network.prefixlen})"
    else:
        if network.prefixlen < MIN_PREFIX_LENGTH_V6:
            return f"broader than /{MIN_PREFIX_LENGTH_V6} (is /{network.prefixlen})"

    if network.is_private:
        return "private (RFC 1918 or ULA)"
    if network.is_loopback:
        return "loopback"
    if network.is_link_local:
        return "link-local"
    if network.is_multicast:
        return "multicast"
    if network.is_reserved:
        return "IANA-reserved"
    if network.is_unspecified:
        return "unspecified (0.0.0.0/... or ::/...)"
    return None


def filter_safe(networks: list[IPNetwork]) -> tuple[list[IPNetwork], Counter]:
    """
    Split networks into (safe, rejection-reason counts).

    Every rejection is counted, not just logged, so a run that suddenly starts
    rejecting hundreds of entries shows up in the summary rather than silently
    trimming coverage.
    """
    safe: list[IPNetwork] = []
    reasons: Counter = Counter()
    for net in networks:
        reason = rejection_reason(net)
        if reason is None:
            safe.append(net)
        else:
            reasons[reason] += 1
            log.warning("rejected %s: %s", net, reason)
    return safe, reasons
