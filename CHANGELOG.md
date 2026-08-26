# Changelog

## 2026-08-26

- **`MAX_ENTRIES` dropped from 1,500 to 240**, based on real vendor diagnostic reports pulled
  from both device tiers this feed is shared across (larger tier: 1,030 max externally-fetched
  address objects; smaller tier: 256, which binds). The prior 1,500 default would have badly
  overflowed the smaller tier.
- Added `ops/install.sh`: creates a local git identity on the clone and documents the correct
  service-account creation command (`--home-dir` outside `/home`, required because
  `ProtectHome` masks it). Corrected the deployment plan from the shared `github-run` account
  (that's the Actions runner, a different job) to a dedicated `threat-feeds` account, matching
  how other scheduled capture-style tools in this estate are actually deployed.

## 2026-08-25

- Initial version. Ports and hardens a draft aggregation script (previously written to
  `/var/www/html/` for a dedicated web server) into a versioned, GitHub-Pages-served feed:
  - Added `threat_feeds/validate.py`: rejects private/loopback/link-local/multicast/reserved/
    unspecified networks and anything broader than `/8` (v4) / `/32` (v6) before a network can
    reach the committed file.
  - Added a per-feed priority/quota allocation in `threat_feeds/build.py` after measuring that a
    flat merge-then-truncate let VoIPBL's ~98k raw entries silently crowd out every other feed
    (the committed file was entirely VoIPBL addresses in a narrow range, with the other four
    feeds completely absent despite the run reporting success).
  - Added `threat_feeds/git_store.py`: a delta-size gate (refuses a run that shrinks or grows
    the entry count past a threshold, with an explicit bootstrap case for the first-ever
    commit), an empty-list gate, and a gitleaks scan, all before commit.
  - Added fetch timeouts and a single retry on transient network errors; feed failures are
    logged per-feed instead of silently swallowed.
  - Externalized the feed list to `feeds.json` (with a `priority` field) instead of hardcoding
    URLs in the script.
  - Added `--dry-run`.
