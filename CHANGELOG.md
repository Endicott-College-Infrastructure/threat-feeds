# Changelog

## 2026-08-26 (2)

**Replaced the single blended blocklist with three shapes, each published at its own tiers.**
`general` (Spamhaus DROP), `sip` (blocklist.de + VoIPBL), `botnet` (feodotracker + ipsum) each
now draw from their own feeds and publish independently — see `AGENTS.md` section 2 for the full
reasoning. Highlights:

- **Fixed a real bug in the `general` shape**: truncating in address order (an artifact of
  `ipaddress.collapse_addresses`) covered only 28.5% of Spamhaus's flagged address space at a
  200-entry budget. Ranking by network size first covers 89.0% from the same budget — added
  `shapes.select_size_ranked`.
- **Added the `sip` shape's geo/ASN-aware selection**: `threat_feeds/geo.py` (a Team Cymru bulk
  whois client, stdlib `socket` only, with a 7-day local cache so an hourly sync job doesn't
  hammer a free public service) and `shapes.select_geo_density_ranked`, which excludes non-US
  address space (redundant with on-box Geo-IP filtering for this shape's specific rule scope —
  confirmed against the actual rule, not assumed), includes confirmed-unannounced space
  deliberately, ranks candidate `/24`s by attacker density, and emits `/24` blocks rather than
  individual addresses. Prefix aggregation wider than `/24` was measured and explicitly
  rejected — see `AGENTS.md` section 2's density table.
- **Publishing moved from `main`/`docs` to an orphan `gh-pages` branch** (`GhPagesStore` in
  `threat_feeds/git_store.py`, modelled on a similar snapshot-branch pattern already used
  elsewhere in this estate) — five published files, several uncapped and large, no longer
  belong in code history.
- Every shape/profile gates and publishes independently: one profile's gate refusal, or one
  shape's feeds being briefly unreachable, no longer stops any other profile from publishing.
- `MAX_ENTRIES` (a single global cap) is gone, replaced by a per-profile `budget` in
  `feeds.json`. The two capped tiers (`general-200`, `sip-400`) are both sized from real
  devices' own reported object-count ceilings (1,030 / 256, the smaller binding) rather than a
  vendor-doc guess — see `AGENTS.md` section 2.
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
