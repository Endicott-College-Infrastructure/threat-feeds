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

This repo aggregates public IP-blocklist feeds into three **shapes** (`general`, `sip`,
`botnet`), each published at one or more **profiles** (a capped tier and/or an uncapped `full`
tier), to an orphan `gh-pages` branch. Every published file becomes a **live firewall block
rule** on every device pointed at it — a wrong entry here is not a data-quality nuisance, it's
an outage or a hole in the block list, either of which is much more expensive to discover after
the fact than in this file.

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

- **Never write an unvalidated network to any published file.** `threat_feeds/validate.py` is
  the safety-critical gate shared by every shape: it rejects anything
  private/loopback/link-local/multicast/reserved/unspecified, and anything broader than `/8`
  (v4) or `/32` (v6) — see `MIN_PREFIX_LENGTH_V4/V6` there for why. A single malformed or
  tampered feed line parsing as e.g. `0.0.0.0/0` must never reach a published `.txt` file,
  because that file becomes a real firewall rule unattended.
- **VoIPBL's feed URL (`feeds.json`) is plain HTTP** — the only non-HTTPS source in this repo.
  A feed fetched in the clear can be tampered with in transit; the validation gate above is the
  stated mitigation, not a fix. If VoIPBL ever ships an HTTPS endpoint, switch to it.
- **Never publish an empty or wildly-different-sized file.** `threat_feeds/git_store.py`'s
  `check_nonempty` and `check_delta` gates run before every publish, per profile file — don't
  weaken or bypass them to "fix" a refused run. A refusal means something upstream changed and
  needs a human, not a bigger `--max-delta-pct`.
- **A failed geo/ASN lookup must exclude an address from the `sip` shape's capped tier, never
  include it.** `threat_feeds/geo.py`'s `LOOKUP_FAILED` marker is deliberately distinct from
  Cymru's own `asn="NA"` ("allocated, not BGP-announced" — a real answer this shape includes on
  purpose). Conflating "we don't know" with "confirmed unannounced" would silently expand the
  block list based on our own connectivity problems, not evidence. See `geo.is_us_or_unannounced`
  and its tests.

## 2. Load-bearing details that look incidental

**Why three shapes, not one blended list.** An earlier version of this repo merged every feed
into one capped list, in priority order. Measured 2026-08-26: this defeats the "catch what
nothing else does" principle the feed was meant to serve, because different consumers already
cover different threat categories through different controls (an on-box Geo-IP filter, a
separate botnet/IP-reputation filter). Blending them meant one control's data competed with
another's for the same scarce object slots. Splitting by shape means each published file maps to
exactly one consuming control, and no feed is spent twice.

**`general` (Spamhaus DROP): size-ranked, not address-order — a real bug, not a style choice.**
`ipaddress.collapse_addresses()` returns networks in address order, and an earlier version of
`build.py` truncated in that order. Measured 2026-08-26 on the real feed: address-order
truncation at a 200-entry budget covered only **28.5%** of Spamhaus's total flagged address
space; ranking by network size (largest block first) covers **89.0%** from the same 200 slots —
a 3.1x improvement for free, no extra budget needed. Diminishing returns set in fast past that:
200→300 entries only adds +4.2 points of coverage, 300→500 only +3.3 more. `general`'s
geographic mix is deliberately **not** filtered to US-only, unlike `sip` — measured 2026-08-26,
non-US space is 61.1% of Spamhaus's objects and **76.9%** of its total flagged address space (CN
alone is 36.1%, bigger than the entire US share). `general` protects broad inbound rules with no
single geographic scope, so culling non-US would throw away most of the shape's actual value —
this is the opposite conclusion from `sip`'s, and deliberately so; see below for why they differ.

**`sip` (blocklist.de + VoIPBL): US-or-unannounced only, ranked by `/24` attacker density, no
aggregation wider than `/24`.** Three separate, measured decisions:
1. *Why US-only here but not for `general`*: this shape protects a narrowly-scoped SIP/VoIP
   rule set, and non-US traffic is already excluded by this org's on-box Geo-IP filtering for
   that specific rule scope — confirmed against the actual rule, not assumed. Measured
   2026-08-26: US-allocated space is only 52.8% of `/24`s but the *addressable* attacker
   population once non-US is dropped is still substantial (out of the top 5,000 candidate
   `/24`s by raw count, 1,899 are US-or-unannounced). Do not copy this exclusion onto a shape
   that protects something without that same geographic rule scope (see `general`, above) —
   check the actual consuming rule before excluding anything by geography.
2. *Why rank by `/24`, not emit individual addresses*: measured 2026-08-26, SIP attackers
   cluster heavily — 129,714 flagged addresses fall into only 50,596 distinct `/24`s. Emitting
   the containing `/24` instead of a flat address list buys enormous coverage per object slot
   for a density-ranked selection (400 slots this way covers ~86% of the addressable — US or
   unannounced — attacker population; a flat top-400-by-address-order list would cover a
   fraction of a percent of it).
3. *Why not aggregate wider than `/24`*: measured and rejected. Ranking candidate prefixes by
   raw attacker count without a density floor pulls in enormous, nearly-benign supernets — e.g.
   a `/10` containing 1,506 attackers across 4.2 million addresses, 0.0% density. Gating on
   density correctly excludes these; what survives a density threshold is overwhelmingly lone
   `/24`s, not wider prefixes. `/24` is therefore the right and final aggregation unit for this
   shape, not an arbitrary starting point.

**Unannounced (no BGP-announcing ASN) US-allocated space is included in `sip`'s capped tier
deliberately, not by omission.** Reasoning, not a measurement: no legitimate SIP registration
traffic is expected to originate from address space with no BGP path back to it, so the
false-positive risk there is accepted on purpose. This is a policy decision, documented here so
it reads as intentional rather than a gap — revisit if it ever causes a real false positive.

**`SIP_CANDIDATE_POOL` in `threat_feeds/shapes.py` bounds how many `/24`s get a geo/ASN lookup at
all**, before the US-or-unannounced filter even runs. Sized against the shape's measured real
candidate pool (low thousands of distinct `/24`s), not an arbitrary round number — a much larger
future SIP feed could have relevant `/24`s outside this pool that are silently never considered.
Re-measure if a new SIP feed source is added.

**`.geo_cache.json` exists because the sync job runs hourly against a free, community-run
lookup service.** ASN/country attribution changes on the timescale of BGP reallocations — weeks
to years — so re-resolving thousands of `/24`s against Cymru's public whois every single hour
would be needless load on it for data that essentially never changes between runs. The 7-day TTL
(`geo.CACHE_TTL_SECONDS`) means Cymru sees a burst of lookups roughly once a week per candidate
address, not 168 times. Never committed (gitignored) — it's a performance cache, not data.

**Every capped tier's budget is a verified device ceiling, not a guess** — read directly off
real devices' own reported runtime object-count limits, not vendor documentation:
- larger device tier: 1,030 max externally-fetched address objects
- smaller device tier: 256 max externally-fetched address objects ← binds `sip-400`'s design
`general-200` and `sip-400` were both chosen with margin below the smaller tier's reported
ceiling (240 was the prior single-list default; splitting into shapes freed room to size `sip`
at 400 given the smaller tier's actual 256 limit is shared across both shapes on that device —
the current 200+400=600 allocation leaves headroom, not a hard boundary at exactly 256+ceiling
math). **If this feed is ever shared with a device tier smaller than the one measured here,
re-verify against that device's own report before assuming either budget still fits** — do not
assume the pattern holds without checking. (Which devices, and the exact model/tier names, are
tracked internally — see section 0.)

## 3. Names that are frozen

- `gh-pages` — the orphan branch every profile file is published to. Renaming it means
  reconfiguring GitHub Pages and updating every consuming device's URL simultaneously.
- `general-200.txt`, `general-full.txt`, `sip-400.txt`, `sip-full.txt`, `botnet-full.txt` — these
  exact filenames are what GitHub Pages serves and what every consuming device points its
  externally-fetched address list at. Renaming any of them breaks every device pointed at the
  old URL with no warning; if one must move, keep the old path as a redirect or coordinate the
  device-side config change first.

## 4. Compliance boundary in this repo

Public threat-intel IP addresses only — no student, payment, or CJI data of any kind, and no
internal network topology beyond "these firewalls exist and fetch from GitHub." That's what
makes the repo safe to keep public. If a future consumer format ever needed to embed anything
internal — a VPC ID, an account ID, an internal hostname — stop and reconsider whether that
output belongs in a *public* repo before adding it.

## 5. Credentials this repo touches

None committed. The service account that runs the sync job needs push access to this repo (a
new grant — deploy keys/PATs in this estate are scoped per-repo, so having push access to other
repos does not carry over), covering both `main` (kept current by the sync script) and
`gh-pages` (where `build.py` publishes). No API keys anywhere: every feed source is public and
unauthenticated, and so is the Cymru geo/ASN lookup (a plain TCP query, no key). Which host runs
the sync job is tracked internally, not in this repo — see section 0.

## 6. Exit codes

`threat_feeds/build.py` (also `python3 -m threat_feeds.build`):

| Code | Meaning | Consumed by |
| :--- | :--- | :--- |
| 0 | Published (at least one profile), or no change since last run | `ops/threat_feeds_sync.sh` |
| 1 | Every shape x profile was gate-refused (empty list, delta-size gate, or gitleaks) | same |
| 2 | Every feed in every shape failed to fetch | same |

A single profile's own gate refusal does **not** produce exit 1 by itself — that code means
every profile across every shape refused. One shape's fetch failure (e.g. `sip`'s feeds are
briefly unreachable) also does not stop other shapes from publishing; see `build.py`'s per-shape
independence.

## 7. Testing and verification

- `python3 -m unittest discover -s tests` — covers `validate.py`'s rejection logic,
  `git_store.py`'s delta gate (including the bootstrap/first-publish case), `geo.py`'s
  `is_us_or_unannounced` classifier and `GeoCache`'s cache-hit/expiry/failure behavior (all
  network-free, using a monkeypatched Cymru query), and `shapes.py`'s three selection methods
  (including the specific address-order-vs-size-ranked regression that motivated the `general`
  shape's fix).
- `python3 -m threat_feeds.build --dry-run` against the real feed URLs (and the real Cymru
  lookup service, for `sip`) is the real end-to-end test: it fetches, selects, and runs every
  gate, logging the full per-shape/profile outcome — but writes and publishes nothing.
- No integration test against an actual consuming device exists in this repo. Verifying a
  published Pages URL actually loads cleanly into a real device's externally-fetched address
  list is a manual step, done outside this repo.

## 8. Conventions specific to this repo

- **Failure alerting is not wired up yet.** `ops/systemd/threat-feeds-sync.service`'s
  `OnFailure=` points at `threat-feeds-sync-failure@%n.service`, which does not exist yet on
  the management host as of this writing. A silently-stale blocklist is a worse failure mode than
  most capture-job failures, since the feed becomes a firewall rule other systems trust to be
  current. Wire up a real handler (email/Slack/an issue) or an `activexperts-monitoring` check
  on a published file's last-commit age before treating this timer as sufficient on its own.
- `feeds.json` is the only config file; there is no `/etc/threat-feeds/` config and no env vars
  are read, since every source (feeds and the geo/ASN lookup) is public and unauthenticated.
- `.geo_cache.json` at the repo root is a local performance cache, gitignored, never committed —
  see section 2.

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
