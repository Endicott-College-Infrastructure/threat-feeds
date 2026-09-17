# threat-feeds

Aggregates public threat-intelligence IP blocklists into several shaped, tiered files, versioned
in this repo and published via GitHub Pages from an orphan `gh-pages` branch — so a firewall (or
a WAF, a cloud-firewall address group, or an IdP) can fetch a live feed over plain HTTPS with no
dedicated web server behind it.

Three shapes, each drawing from its own feeds and published at its own tiers:

| shape | feeds | tiers published |
| :--- | :--- | :--- |
| `general` | Spamhaus DROP | `general-200.txt`, `general-full.txt` |
| `sip` | blocklist.de (SIP/VoIP attackers), VoIPBL | `sip-400.txt`, `sip-full.txt` |
| `botnet` | feodotracker (abuse.ch), ipsum (≥6-list threshold) | `botnet-full.txt` |

See `AGENTS.md` section 2 for why each shape draws from the feeds it does, and how each capped
tier's selection method was chosen and measured.

**This is a public repo.** It exists to publish the aggregated files, which are themselves
already public data — but keep anything about *our* specific infrastructure (vendor, hardware
model, hostnames, internal topology) out of it. Operational specifics for consuming this feed
live in an internal, non-public location — ask before adding vendor/hardware detail here.

## What this repo does not need

No credentials, no API keys, no env vars. Every feed source is public and unauthenticated, and
so is the geo/ASN lookup service the `sip` shape uses (see below) — it's a plain TCP query, no
API key.

## Dependencies

- Python 3.10+ (uses `X | Y` union type syntax; stdlib only, no `requirements.txt` — the geo/ASN
  lookup in `threat_feeds/geo.py` is a raw `socket` connection, not a third-party client library)
- `gitleaks` on the host that runs the sync job — see `.github/workflows/secret-scan.yml` for
  the pinned version. `build.py` refuses to publish unscanned by default.
- `ruff` for linting (CI only; not required to run the script)

## Running it

```bash
# Fetch, select, and run every gate, but publish nothing.
python3 -m threat_feeds.build --dry-run

# Real run: fetch, select, gate, write, gitleaks-scan, commit, and push to gh-pages.
python3 -m threat_feeds.build
```

Exit codes: `0` published (or no change), `1` every shape x profile was gate-refused, `2` every
feed in every shape failed to fetch. A single profile's own gate refusal (say, `sip-400`'s delta
gate firing) does **not** stop the other profiles from publishing — see `AGENTS.md` section 6 for
the full table.

## `feeds.json`

```json
{
  "feeds": [
    {"name": "...", "url": "...", "enabled": true}
  ],
  "shapes": {
    "general": {
      "feeds": ["spamhaus-drop"],
      "profiles": {
        "200": {"budget": 200, "selection": "size-ranked"},
        "full": {"budget": null, "selection": "none"}
      }
    }
  }
}
```

Selection is set **per profile**, not per shape: a capped profile needs a ranking/filter method
suited to a slot-limited consumer, while a shape's `full` profile should generally use `none`
(validated addresses only, no aggregation or geographic filtering) since those constraints exist
because of the slot budget, not the shape itself. Three selection methods exist today —
`none`, `size-ranked`, `geo-density-ranked` — see `threat_feeds/shapes.py` and `AGENTS.md`
section 2 for what each does and why. Set `"enabled": false` on a feed to disable it without
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
  `threat-feeds` account — a new grant, scoped to this repo only. It needs push access to `main`
  (this script keeps that branch current) and `gh-pages` (where `build.py` publishes).
- `gitleaks` installed.
- **Failure alerting**: `ops/install.sh` also installs `threat-feeds-sync-failure@.service`,
  the `OnFailure=` handler — alert-only (a journal line), not mail/paging. See `AGENTS.md`
  section 8 before treating the timer alone as sufficient monitoring.
- The geo/ASN lookup the `sip` shape uses caches its answers in `.geo_cache.json` at the repo
  root (gitignored, never committed) — outbound TCP to `whois.cymru.com:43` needs to be
  reachable from this host.

Which host runs this, and any host-specific setup, is tracked internally — not in this repo.

## Publishing: GitHub Pages

One-time, manual, in the repo's GitHub settings (not scriptable): **Settings → Pages → Source:
Deploy from a branch → `gh-pages` → `/` (root)**. Every profile file (`general-200.txt`,
`sip-400.txt`, etc.) is then fetchable directly at `<pages-url>/<file>.txt`.

The `gh-pages` branch is orphaned from `main` on purpose — see `threat_feeds/git_store.py`'s
module docstring. It holds nothing but published data, has no shared history with the code
branches, and `build.py` manages it entirely on its own via a separate worktree; nothing here
commits published output to `main`.

## Consuming this feed

Most next-generation firewalls, WAFs, cloud-firewall services, and IdPs support fetching an
externally-hosted address list on a timed interval — consult your specific device's
documentation for the exact feature name and configuration steps. In general:

- Pick the shape that matches what you're protecting (`general` for broad inbound rules, `sip`
  for SIP/VoIP-facing infrastructure, `botnet` for a botnet/IP-reputation filter) and the tier
  that matches your consumer's own object-count ceiling.
- Match the device's fetch interval to this repo's own sync cadence (see
  `ops/systemd/threat-feeds-sync.timer`) — no reason to poll more often than the source updates.
- If multiple devices share one profile's URL, a poll interval on the order of an hour avoids a
  synchronized fetch spike against GitHub Pages, since most devices stagger their actual fetch
  time based on when the rule was configured.
- **Confirm your device's own entry-count ceiling before pointing it at a capped profile.** The
  `general-200`/`sip-400` defaults were set from real devices' own reported runtime limits (not
  a vendor doc guess) — see `AGENTS.md` section 2 for the confirmed numbers and how they were
  obtained. If your device's ceiling is smaller than the ones already measured, re-check before
  assuming a capped tier fits; a `full` tier exists specifically for consumers with a much
  higher (or no practical) limit.
- The specific device models and vendor-specific setup steps used at this organization are
  tracked internally, not in this public repo.

## Known limitations

- VoIPBL's feed URL is plain HTTP — the only non-HTTPS source. See `AGENTS.md` section 1.
- The `sip` shape's capped tier (`sip-400`) deliberately excludes non-US address space and
  applies a `/24`-density ranking — see `AGENTS.md` section 2 for the measurements behind both
  calls, and why the same exclusion is **not** applied to the `general` shape.
- The geo/ASN lookup only classifies the top few thousand candidate `/24`s by raw attacker
  count (see `SIP_CANDIDATE_POOL` in `threat_feeds/shapes.py`) before the US-or-unannounced
  filter runs — a pathologically large feed could have relevant `/24`s outside that pool that
  never get considered at all. Sized against the shape's real measured candidate pool, not an
  arbitrary round number; re-check if a new SIP feed source is ever added.
- A failed geo/ASN lookup for a given address is excluded from the `sip` shape's capped tier,
  not silently included (see `threat_feeds/geo.py`'s `LOOKUP_FAILED` marker) — a Cymru outage
  during a sync run means that run's `sip-400` may be smaller than usual, not wrong.
