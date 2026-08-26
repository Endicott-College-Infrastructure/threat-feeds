#!/usr/bin/env python3
"""
Fetch every enabled feed in feeds.json, validate and cap the merged result, and
commit it to docs/blocklist.txt on `main`.

Required env vars: none -- all sources are public and unauthenticated.
Example usage:
    python3 -m threat_feeds.build --dry-run
    python3 -m threat_feeds.build --max-delta-pct 40

Exit codes: 0 = committed or no change, 1 = a safety gate refused, 2 = every
feed failed to fetch.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from collections import Counter
from pathlib import Path

from . import fetch, validate
from .git_store import (
    DEFAULT_MAX_DELTA_PCT,
    GateRefusalError,
    check_delta,
    check_nonempty,
    commit_and_push,
    previous_entry_count,
    scan_gitleaks,
)

log = logging.getLogger("threat_feeds")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FEEDS_FILE = REPO_ROOT / "feeds.json"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "blocklist.txt"

# Verified 2026-08-26 by reading each device's own runtime-reported ceiling
# on externally-fetched address objects, off a vendor-generated diagnostic
# report -- not a vendor doc guess. The smaller tier is the binding
# constraint, by a wide margin:
#   larger tier:  1,030 max externally-fetched address objects
#   smaller tier:   256 max externally-fetched address objects   <- binds
# 240 leaves headroom below the smaller tier's reported hard ceiling, since
# device behavior at exactly the reported max hasn't been verified live. If
# this feed is ever shared with a device tier smaller than the one measured
# here, re-verify against ITS OWN report before assuming 240 still fits -- see
# AGENTS.md section 2.
MAX_ENTRIES = 240


def build(
    feeds_file: Path,
    output_path: Path,
    *,
    max_entries: int = MAX_ENTRIES,
    max_delta_pct: int = DEFAULT_MAX_DELTA_PCT,
    dry_run: bool = False,
    allow_missing_gitleaks: bool = False,
) -> int:
    feeds_config = json.loads(feeds_file.read_text(encoding="utf-8"))
    feeds_list = feeds_config["feeds"]
    results = fetch.fetch_all(feeds_list)
    priority_by_name = {f["name"]: f.get("priority", 100) for f in feeds_list}

    for r in results:
        if r.fetched:
            log.info(
                "%s: %d networks (%d unparsed lines skipped)",
                r.name,
                len(r.networks),
                r.skipped_lines,
            )
        else:
            log.error("%s: FAILED -- %s", r.name, r.error)

    if not any(r.fetched for r in results):
        log.error("every feed failed to fetch -- nothing to build")
        return 2

    # Validate and collapse EACH feed independently, before any cross-feed
    # merging. A single flat merge-then-truncate (the draft's approach) lets
    # whichever feed's addresses happen to sort lowest crowd out every other
    # feed entirely -- measured 2026-08-25: VoIPBL's ~98k raw host entries
    # swamped a 1,500 cap so completely that the committed file was ENTIRELY
    # VoIPBL addresses in a narrow range, with spamhaus/feodotracker/ipsum/
    # blocklist.de silently absent despite the run reporting success.
    per_feed: dict[str, list] = {}
    all_rejections: Counter = Counter()
    for r in results:
        if not r.fetched:
            continue
        v4 = [n for n in r.networks if n.version == 4]
        safe, rejected = validate.filter_safe(v4)
        all_rejections.update(rejected)
        per_feed[r.name] = list(ipaddress.collapse_addresses(safe))

    if all_rejections:
        log.warning("rejected networks by reason: %s", dict(all_rejections))

    # Fill the budget in priority order (feeds.json's "priority", lower first),
    # not address order. Every enabled feed gets a chance at the budget before
    # any single feed can exhaust it; if total demand still exceeds max_entries,
    # the LOWEST-priority feeds are the ones truncated or excluded, and that
    # tradeoff is logged per feed rather than happening invisibly.
    ordered_names = sorted(per_feed, key=lambda name: priority_by_name.get(name, 100))
    allocated: list = []
    remaining = max_entries
    for name in ordered_names:
        feed_nets = per_feed[name]
        if remaining <= 0:
            log.warning(
                "%s: excluded entirely -- no budget remaining (%d entries dropped)",
                name,
                len(feed_nets),
            )
            continue
        if len(feed_nets) <= remaining:
            allocated.extend(feed_nets)
            log.info("%s: %d entries included in full", name, len(feed_nets))
            remaining -= len(feed_nets)
        else:
            allocated.extend(feed_nets[:remaining])
            log.warning(
                "%s: truncated to %d of %d entries -- out of budget",
                name,
                remaining,
                len(feed_nets),
            )
            remaining = 0

    # Cross-feed collapse can only reduce the count further (two feeds flagging
    # adjacent netblocks merge into one entry) -- never increases it, so this is
    # free headroom, not a risk to the budget just enforced above.
    collapsed = list(ipaddress.collapse_addresses(allocated))
    new_count = len(collapsed)
    log.info("final list: %d entries (budget %d)", new_count, max_entries)

    try:
        check_nonempty(new_count)
        previous_count = previous_entry_count(REPO_ROOT, output_path)
        check_delta(previous_count, new_count, max_delta_pct)
    except GateRefusalError as e:
        log.error("gate refused: %s", e)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(f"{net}\n" for net in collapsed), encoding="utf-8")

    if dry_run:
        log.info(
            "dry run: wrote %s locally, skipping gitleaks scan / commit / push",
            output_path,
        )
        return 0

    try:
        scan_gitleaks(REPO_ROOT, require=not allow_missing_gitleaks)
    except GateRefusalError as e:
        log.error("gate refused: %s", e)
        return 1

    message = f"[Agent] threat-feeds sync -- {new_count} entries"
    commit_and_push(REPO_ROOT, output_path, message, dry_run=dry_run)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feeds-file", type=Path, default=DEFAULT_FEEDS_FILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-entries", type=int, default=MAX_ENTRIES)
    parser.add_argument("--max-delta-pct", type=int, default=DEFAULT_MAX_DELTA_PCT)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch, validate, and run gates, but write nothing to git",
    )
    parser.add_argument(
        "--allow-missing-gitleaks",
        action="store_true",
        help="commit even if gitleaks is not installed (not the default for a reason)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    return build(
        args.feeds_file,
        args.output,
        max_entries=args.max_entries,
        max_delta_pct=args.max_delta_pct,
        dry_run=args.dry_run,
        allow_missing_gitleaks=args.allow_missing_gitleaks,
    )


if __name__ == "__main__":
    sys.exit(main())
