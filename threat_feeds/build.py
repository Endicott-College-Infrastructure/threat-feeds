#!/usr/bin/env python3
"""
Fetch every enabled feed in feeds.json, run each shape's per-profile
selection logic, and publish one file per shape x profile to the gh-pages
branch.

Required env vars: none -- all sources are public and unauthenticated.
Example usage:
    python3 -m threat_feeds.build --dry-run
    python3 -m threat_feeds.build

Exit codes: 0 = published (or no change), 1 = a safety gate refused for
every profile (nothing to publish), 2 = every feed failed to fetch.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path

from . import fetch, geo, shapes
from .git_store import (
    DEFAULT_MAX_DELTA_PCT,
    GateRefusalError,
    GhPagesStore,
    check_delta,
    check_nonempty,
    scan_gitleaks,
)

log = logging.getLogger("threat_feeds")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FEEDS_FILE = REPO_ROOT / "feeds.json"
GEO_CACHE_FILE = REPO_ROOT / ".geo_cache.json"


def _build_profile(
    shape_name: str,
    profile_name: str,
    profile_config: dict,
    feed_results: list,
    geo_cache: geo.GeoCache,
    store: GhPagesStore,
    *,
    max_delta_pct: int,
) -> tuple[str, str] | None:
    """
    Run one profile's selection, gate it against the currently-published
    version of its own file, and return (relative_path, content) if it
    should be written -- or None if a gate refused it. A refusal here only
    skips THIS profile; it never affects any other shape or profile.
    """
    selection = profile_config["selection"]
    selector = shapes.SELECTORS[selection]
    if selection == "geo-density-ranked":
        ranked = selector(feed_results, geo_cache)
    else:
        ranked = selector(feed_results)

    budget = profile_config["budget"]
    subset = ranked if budget is None else ranked[:budget]
    collapsed = list(ipaddress.collapse_addresses(subset))
    new_count = len(collapsed)
    relative_path = f"{shape_name}-{profile_name}.txt"

    try:
        check_nonempty(new_count)
        previous_count = store.previous_line_count(relative_path)
        check_delta(previous_count, new_count, max_delta_pct)
    except GateRefusalError as e:
        log.error("%s: gate refused: %s", relative_path, e)
        return None

    log.info(
        "%s: %d entries (budget %s)",
        relative_path,
        new_count,
        budget if budget is not None else "none",
    )
    content = "".join(f"{n}\n" for n in collapsed)
    return relative_path, content


def build(
    feeds_file: Path,
    *,
    max_delta_pct: int = DEFAULT_MAX_DELTA_PCT,
    dry_run: bool = False,
    allow_missing_gitleaks: bool = False,
) -> int:
    feeds_config = json.loads(feeds_file.read_text(encoding="utf-8"))
    feeds_by_name = {f["name"]: f for f in feeds_config["feeds"]}
    shapes_config = feeds_config["shapes"]
    geo_cache = geo.GeoCache(GEO_CACHE_FILE)

    store = GhPagesStore(REPO_ROOT)
    if not dry_run or store.worktree_exists():
        # A real run always needs the worktree. A dry run only opens it if
        # it's already there (so the delta-gate preview is accurate against
        # real prior state) -- it must never CREATE one, since that's real
        # local git state (an orphan branch, a worktree checkout on disk)
        # for a mode whose whole contract is "write and publish nothing."
        # On a dry run against a fresh clone with no worktree yet,
        # previous_line_count() below simply reports None (never published)
        # rather than fabricate a worktree just to answer that question.
        store.ensure_worktree()

    any_feed_fetched = False
    to_write: list[tuple[str, str]] = []

    for shape_name, shape_config in shapes_config.items():
        shape_feeds = [
            feeds_by_name[name]
            for name in shape_config["feeds"]
            if feeds_by_name[name].get("enabled", True)
        ]
        results = fetch.fetch_all(shape_feeds)
        for r in results:
            if r.fetched:
                any_feed_fetched = True
                log.info(
                    "%s/%s: %d networks (%d unparsed lines skipped)",
                    shape_name,
                    r.name,
                    len(r.networks),
                    r.skipped_lines,
                )
            else:
                log.error("%s/%s: FAILED -- %s", shape_name, r.name, r.error)

        if not any(r.fetched for r in results):
            log.error(
                "%s: every feed failed to fetch -- skipping this shape entirely",
                shape_name,
            )
            continue

        for profile_name, profile_config in shape_config["profiles"].items():
            written = _build_profile(
                shape_name,
                profile_name,
                profile_config,
                results,
                geo_cache,
                store,
                max_delta_pct=max_delta_pct,
            )
            if written is not None:
                to_write.append(written)

    if not any_feed_fetched:
        log.error("every feed in every shape failed to fetch -- nothing to publish")
        return 2

    if not to_write:
        log.error(
            "every profile was gate-refused or produced nothing -- nothing to publish"
        )
        return 1

    if dry_run:
        log.info(
            "dry run: %d profile(s) would be published: %s",
            len(to_write),
            ", ".join(p for p, _ in to_write),
        )
        return 0

    for relative_path, content in to_write:
        store.write(relative_path, content)

    try:
        scan_gitleaks(store.worktree, require=not allow_missing_gitleaks)
    except GateRefusalError as e:
        log.error("gate refused: %s -- discarding this run's changes", e)
        store.discard_uncommitted()
        return 1

    message = f"[Agent] threat-feeds sync -- {len(to_write)} profile(s) updated"
    store.commit_and_push(message)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feeds-file", type=Path, default=DEFAULT_FEEDS_FILE)
    parser.add_argument("--max-delta-pct", type=int, default=DEFAULT_MAX_DELTA_PCT)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="fetch, select, and run gates, but write and publish nothing",
    )
    parser.add_argument(
        "--allow-missing-gitleaks",
        action="store_true",
        help="publish even if gitleaks is not installed (not the default for a reason)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    return build(
        args.feeds_file,
        max_delta_pct=args.max_delta_pct,
        dry_run=args.dry_run,
        allow_missing_gitleaks=args.allow_missing_gitleaks,
    )


if __name__ == "__main__":
    sys.exit(main())
