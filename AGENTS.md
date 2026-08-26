# AGENTS.md — threat-feeds

Repo-specific rules. **These take precedence over
[STANDARDS.md](https://github.com/Endicott-College-Infrastructure/.github/blob/main/STANDARDS.md)
on conflict** — but STANDARDS.md still governs everything not restated here, and it is not
copied into this repo. **Read it first.**

If the `.github` repo is cloned as a sibling, read it locally at
`../.github/STANDARDS.md`. Otherwise fetch it:

```
gh api repos/Endicott-College-Infrastructure/.github/contents/STANDARDS.md \
  -H "Accept: application/vnd.github.raw"
```

**Before designing a schema, adding a field, or wiring an integration, read
[COMPLIANCE.md](https://github.com/Endicott-College-Infrastructure/.github/blob/main/COMPLIANCE.md).**
Nothing here has flagged as applicable so far — this repo aggregates public threat-intel IP
lists and touches no student, payment, or CJI data — but re-check before changing scope.

This repo aggregates public IP-blocklist feeds (Spamhaus DROP, VoIPBL, ipsum, blocklist.de,
feodotracker) into a single capped, CIDR-collapsed file, committed to `main` and published via
GitHub Pages. It becomes a **live firewall block rule** on every device pointed at the same URL
— a wrong entry here is not a data-quality nuisance, it's an outage or a hole in the block list,
either of which is much more expensive to discover after the fact than in this file.

**This repo is public.** It has to be — GitHub Pages on a private repo isn't available on this
org's plan. That changes what belongs in it: the aggregated IP data is already public, but our
specific vendor, hardware models, hostnames, and internal topology are not, and naming them here
hands a would-be attacker free reconnaissance for no benefit to the tool. See section 0.

## 0. Never name our specific vendor or hardware in this repo

Keep every doc, comment, commit message, issue, and PR in this repo describing *devices* and
*firewalls* in the abstract — never a specific vendor, product line, or model number, and never
a hostname. This is a **stricter bar than the usual compliance boundary** (section 4): it's not
about regulated data, it's about not publishing a recon map of our security posture next to a
tool that's ITSELF meant to be useful to anyone running any brand of firewall. The internal,
non-public equivalent of this file's operational guidance — which vendor, which models, real
entry-count limits, exact device-side configuration steps — is tracked outside this repo; ask
where before adding any of that detail here.

---

## 1. What this code must never do

- **Never commit an unvalidated network.** `threat_feeds/validate.py` is the safety-critical
  gate: it rejects anything private/loopback/link-local/multicast/reserved/unspecified, and
  anything broader than `/8` (v4) or `/32` (v6) — see `MIN_PREFIX_LENGTH_V4/V6` there for why.
  A single malformed or tampered feed line parsing as e.g. `0.0.0.0/0` must never reach
  `docs/blocklist.txt`, because that file becomes a real firewall rule unattended.
- **VoIPBL's feed URL (`feeds.json`) is plain HTTP** — the only non-HTTPS source of the five.
  A feed fetched in the clear can be tampered with in transit; the validation gate above is the
  stated mitigation, not a fix. If VoIPBL ever ships an HTTPS endpoint, switch to it.
- **Never commit an empty or wildly-different-sized list.** `threat_feeds/git_store.py`'s
  `check_nonempty` and `check_delta` gates run before every commit; don't weaken or bypass them
  to "fix" a refused run — a refusal means something upstream changed and needs a human, not a
  bigger `--max-delta-pct`.

## 2. Load-bearing details that look incidental

- **`feeds.json`'s `priority` field determines what survives truncation, not fetch order.**
  Measured 2026-08-25: VoIPBL alone returns ~98k raw entries against a 240-entry budget — more
  than every other feed combined, by nearly three orders of magnitude. `build.py` allocates
  budget in priority order (lower number = filled first) specifically so one oversized feed
  can't silently crowd out every other source the way a flat merge-then-truncate did in an
  earlier version of this script. **Real-world consequence of the current priority order and
  `MAX_ENTRIES=240`**: feodotracker and blocklist-de-sip are included in full (~80 entries
  combined), spamhaus-drop is truncated to whatever's left (~160 entries), and ipsum-level5 and
  voipbl are excluded entirely. If you want broader inclusion, raise `MAX_ENTRIES` only after
  re-verifying the device ceiling below, or reprioritize — but do it deliberately and re-run
  with `--dry-run` to see the new allocation logged, not by guessing.
- **`MAX_ENTRIES=240` in `threat_feeds/build.py` is a verified device ceiling, not a guess.**
  Confirmed 2026-08-26 by reading each device's own runtime-reported object-count ceiling
  directly off a vendor-generated diagnostic report — not a vendor doc estimate, the device's
  own reported limit:
  - larger tier: 1,030 max externally-fetched address objects
  - smaller tier: 256 max externally-fetched address objects ← **this one binds**
  240 leaves a small margin below the smaller tier's reported hard ceiling, since behavior at
  exactly the reported max hasn't been verified live. **If this feed is ever shared with a
  device tier smaller than the one measured here, re-verify against that device's own report
  before assuming 240 still fits** — do not assume the pattern holds without checking. (Which
  devices, and the exact model/tier names, are tracked internally — see section 0.)

## 3. Names that are frozen

- `docs/blocklist.txt` — this exact path is what GitHub Pages serves and what every consuming
  device points its externally-fetched address list at. Renaming it breaks every device pointed
  at the old URL with no warning; if it must move, keep the old path as a redirect or coordinate
  the device-side config change first.

## 4. Compliance boundary in this repo

Public threat-intel IP addresses only — no student, payment, or CJI data of any kind, and no
internal network topology beyond "these firewalls exist and fetch from GitHub." That's what
makes the repo safe to keep public. If a future consumer format (a WAF export, a cloud
firewall address group) ever needed to embed anything internal — a VPC ID, an account ID, an
internal hostname — stop and reconsider whether that output belongs in a *public* repo before
adding it.

## 5. Credentials this repo touches

None committed. The service account that runs the sync job needs push access to this repo (a
new grant — deploy keys/PATs in this estate are scoped per-repo, so having push access to other
repos does not carry over). No API keys: every feed source is public and unauthenticated. Which
host runs the sync job is tracked internally, not in this repo — see section 0.

## 6. Exit codes

`threat_feeds/build.py` (also `python3 -m threat_feeds.build`):

| Code | Meaning | Consumed by |
| :--- | :--- | :--- |
| 0 | Committed, or no change since last run | `ops/threat_feeds_sync.sh` |
| 1 | A safety gate refused (empty list, delta-size gate, or gitleaks) | same |
| 2 | Every feed failed to fetch | same |

## 7. Testing and verification

- `python3 -m unittest discover -s tests` — covers `validate.py`'s rejection logic and
  `git_store.py`'s delta gate, including the bootstrap (first-run, no previous commit) case.
- `python3 -m threat_feeds.build --dry-run` against the real feed URLs is the real end-to-end
  test: it fetches, validates, allocates budget, writes `docs/blocklist.txt` locally, and logs
  the full per-feed allocation — but skips the gitleaks scan, commit, and push.
- No integration test against an actual consuming device exists in this repo. Verifying the
  published Pages URL actually loads cleanly into a real device's externally-fetched address
  list is a manual step, done outside this repo.

## 8. Conventions specific to this repo

- **Failure alerting is not wired up yet.** `ops/systemd/threat-feeds-sync.service`'s
  `OnFailure=` points at `threat-feeds-sync-failure@%n.service`, which does not exist yet on
  the management host as of this writing. A silently-stale blocklist is a worse failure mode than
  most capture-job failures, since the feed becomes a firewall rule other systems trust to be
  current. Wire up a real handler (email/Slack/an issue) or an `activexperts-monitoring` check
  on the output file's last-commit age before treating this timer as sufficient on its own.
- `feeds.json` is the only config file; there is no `/etc/threat-feeds/` config and no env vars
  are read, since every source is public and unauthenticated.

---

## Before you open a PR

Nothing gates a merge on this plan: free-plan private repos get no branch protection, so no
status check can be required. **Review is something you run.**

- Run the **pre-pr** skill (Claude: `/endicott:pre-pr`; Zoo: the 🚦 Endicott Pre-PR mode).
- Run the **secret-scan** skill — both scanners, then diff them.
- Update `README.md` and `CHANGELOG.md`. Bring in new information **and cut what is now
  obsolete**.

## Commits

Prefix every agent-written commit `[Agent]`. Explain *why* in the body, not *what*.

**Recommend, don't execute:** pushes, force-pushes and merges are Zach's to run.
