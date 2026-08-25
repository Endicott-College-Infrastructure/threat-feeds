"""
Fetch each configured feed and parse it into a list of ipaddress networks.

Each feed is fetched independently: one feed's failure never blocks the others,
and a failure is logged (never swallowed) with a single retry on transient
network errors, so a source silently going dark for one run is visible in the
run log instead of just quietly shrinking coverage forever.
"""

from __future__ import annotations

import ipaddress
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

FETCH_TIMEOUT_SECONDS = 30
RETRY_DELAY_SECONDS = 5
USER_AGENT = (
    "Mozilla/5.0 (Endicott-threat-feeds; "
    "+https://github.com/Endicott-College-Infrastructure/threat-feeds)"
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class FeedResult:
    name: str
    url: str
    networks: list[IPNetwork] = field(default_factory=list)
    fetched: bool = False
    error: str | None = None
    skipped_lines: int = 0


def _parse_lines(text: str) -> tuple[list[IPNetwork], int]:
    """
    Parse feed text into networks.

    Feed formats differ line-to-line across sources -- Spamhaus DROP is
    `CIDR ; SBLnnnnn`, feodotracker is a comment-header block then one network
    per line, ipsum's leveled files are bare IPs -- but every one of them
    resolves to "the first whitespace token on a data line is the IP/CIDR",
    which is what this generic parser relies on. A line that doesn't parse as
    a network is skipped and counted, not fatal: every feed here carries blank
    lines and comment headers as a matter of course.
    """
    networks: list[IPNetwork] = []
    skipped = 0
    for line in text.splitlines():
        clean = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not clean or clean.startswith("//"):
            continue
        token = clean.split()[0]
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            skipped += 1
    return networks, skipped


def fetch_feed(name: str, url: str) -> FeedResult:
    """Fetch and parse one feed. Never raises -- failures are recorded on the result."""
    result = FeedResult(name=name, url=url)
    last_error: BaseException | None = None

    for attempt in range(2):  # one retry, transient network errors only
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as response:
                text = response.read().decode("utf-8", errors="ignore")
            result.networks, result.skipped_lines = _parse_lines(text)
            result.fetched = True
            return result
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_error = e
            if attempt == 0:
                log.warning(
                    "feed %s (%s) failed on attempt 1 (%s), retrying once", name, url, e
                )
                time.sleep(RETRY_DELAY_SECONDS)
        except Exception as e:  # noqa: BLE001 -- HTTPError, decode errors, etc: not retriable
            last_error = e
            break

    result.error = f"{type(last_error).__name__}: {last_error}"
    log.error("feed %s (%s) failed: %s", name, url, result.error)
    return result


def fetch_all(feeds: list[dict]) -> list[FeedResult]:
    """Fetch every enabled feed. One feed's failure never blocks the others."""
    results = []
    for feed in feeds:
        if not feed.get("enabled", True):
            log.info("feed %s disabled in feeds.json, skipping", feed["name"])
            continue
        results.append(fetch_feed(feed["name"], feed["url"]))
    return results
