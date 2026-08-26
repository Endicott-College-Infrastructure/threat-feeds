# threat-feeds

Aggregates public threat-intelligence IP blocklists into a single, capped, CIDR-collapsed file,
versioned in this repo and published via GitHub Pages — so a firewall (or a WAF, or a
cloud-firewall address group) can fetch a live feed over plain HTTPS with no dedicated web
server behind it.

Currently aggregates: Spamhaus DROP, feodotracker (abuse.ch), blocklist.de (SIP/VoIP attackers),
ipsum (multi-source aggregate, ≥5-list threshold), and VoIPBL.

**This is a public repo.** It exists to publish the aggregated file, which is itself already
public data — but keep anything about *our* specific infrastructure (vendor, hardware model,
hostnames, internal topology) out of it. Operational specifics for consuming this feed live in
an internal, non-public location — ask before adding vendor/hardware detail here.

## What this repo does not need

No credentials, no API keys, no env vars. Every feed source is public and unauthenticated.

## Dependencies

- Python 3.10+ (uses `X | Y` union type syntax; stdlib only, no `requirements.txt`)
- `gitleaks` on the host that runs the sync job — see `.github/workflows/secret-scan.yml` for
  the pinned version. `build.py` refuses to commit unscanned by default.
- `ruff` for linting (CI only; not required to run the script)

## Running it

```bash
# Fetch, validate, and see what WOULD be committed -- writes docs/blocklist.txt locally but
# skips the gitleaks scan, commit, and push.
python3 -m threat_feeds.build --dry-run

# Real run: fetch, validate, gate, commit, and push to main.
python3 -m threat_feeds.build
```

Exit codes: `0` committed or no change, `1` a safety gate refused, `2` every feed failed to
fetch. See `AGENTS.md` section 6 for the full table and section 7 for how to test changes.

## `feeds.json`

```json
{
  "feeds": [
    {"name": "...", "url": "...", "enabled": true, "priority": 1}
  ]
}
```

`priority` (lower = filled first) decides which feeds survive if the merged result exceeds
`MAX_ENTRIES` in `threat_feeds/build.py` — see `AGENTS.md` section 2 for why this matters and
what it means for the feeds configured today. Set `"enabled": false` to disable a feed without
deleting its entry.

## Deployment: the sync job

This runs on a systemd timer on an internal management host — **not** GitHub Actions cron
(GitHub silently disables scheduled workflows after 60 days of repo inactivity; see
`ops/systemd/threat-feeds-sync.timer` for the full reasoning).

```bash
# Once: create the dedicated service account. NOT github-run (that's the Actions
# runner, a different job) -- --home-dir is required, not optional, see ops/install.sh.
sudo useradd --system -M --home-dir /var/lib/threat-feeds --shell /usr/sbin/nologin threat-feeds

sudo git clone https://github.com/Endicott-College-Infrastructure/threat-feeds /srv/threat-feeds
cd /srv/threat-feeds
sudo ./ops/install.sh              # dry run -- prints, changes nothing
sudo ./ops/install.sh --commit      # sets git identity, installs the systemd units

# Run once by hand and read the output before enabling the timer
sudo systemctl start threat-feeds-sync.service
journalctl -u threat-feeds-sync.service -n 80 --no-pager

sudo systemctl enable --now threat-feeds-sync.timer
```

Prerequisites on the host (see `ops/install.sh` and `ops/threat_feeds_sync.sh` headers):
- A clone of this repo at `/srv/threat-feeds` with a working **push** credential for the
  `threat-feeds` account — a new grant, scoped to this repo only.
- `gitleaks` installed.
- **Failure alerting is not wired up yet** — `OnFailure=` in the `.service` file points at a
  handler that doesn't exist yet as of this writing. See `AGENTS.md` section 8 before treating
  the timer alone as sufficient monitoring.

Which host runs this, and any host-specific setup, is tracked internally — not in this repo.

## Publishing: GitHub Pages

One-time, manual, in the repo's GitHub settings (not scriptable): **Settings → Pages → Source:
Deploy from a branch → `main` → `/docs`**. Once enabled, the published URL serves
`docs/blocklist.txt` directly over HTTPS.

## Consuming this feed

Most next-generation firewalls, WAFs, and cloud-firewall services support fetching an
externally-hosted address list on a timed interval — consult your specific device's
documentation for the exact feature name and configuration steps. In general:

- Match the device's fetch interval to this repo's own sync cadence (see
  `ops/systemd/threat-feeds-sync.timer`) — no reason to poll more often than the source updates.
- If multiple devices share this one feed URL, a poll interval on the order of an hour avoids a
  synchronized fetch spike against GitHub Pages, since most devices stagger their actual fetch
  time based on when the rule was configured.
- **Confirm your device's own entry-count ceiling before relying on `MAX_ENTRIES` in
  `build.py`.** Many firewalls cap the number of objects they'll create from an externally
  fetched list — the current default was set from the devices' own reported runtime limits
  (not a vendor doc guess), but if you add a device tier smaller than the ones already
  measured, re-check its own ceiling before assuming the default still fits. See `AGENTS.md`
  section 2 for the confirmed numbers and how they were obtained.
- The specific device models and vendor-specific setup steps used at this organization are
  tracked internally, not in this public repo.

## Known limitations

- VoIPBL's feed URL is plain HTTP — the only non-HTTPS source of the five. See `AGENTS.md`
  section 1.
- At the current `MAX_ENTRIES=240` and priority order, spamhaus-drop is truncated and
  ipsum-level5/voipbl are excluded entirely from the committed file — every feed is fetched and
  validated, but the budget runs out before their turn. Run `--dry-run` to see the actual
  allocation for any given moment; raise `MAX_ENTRIES` (only after re-verifying every device
  tier's own ceiling still supports it) or
  reprioritize in `feeds.json` if broader inclusion is wanted.
