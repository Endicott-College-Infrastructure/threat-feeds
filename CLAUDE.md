@AGENTS.md

## Claude Code

Skills available here: `pre-pr`, `secret-scan`, `style`, `diagramming`,
`activexperts-monitoring`, `endicott-doctor`. Run `/endicott:pre-pr` and
`/endicott:secret-scan` before opening a PR — nothing gates a merge on this plan, so your
review is the only one this change gets.

Prefix every commit `[Agent]`. Explain *why* in the body, not *what*.

## Non-negotiables

- **Compliance is a stop-and-raise, before writing code.** If a change would pull student
  academic classification, payment data, or CJI into a system — stop and raise it. FERPA is
  the sharpest constraint here; PCI DSS and CJIS also apply.
- **Never hardcode a credential, key or token**, shell scripts included. Read from env vars or
  a config file outside the web root. Production config files are never committed, never
  recreated, never overwritten — ask for values.
- **Never push, force-push, or merge.** Recommend; Zach runs those. Branch from `dev`; if you
  are on `main` or `dev`, branch first.
- **These are real systems.** No sandbox — the live tenants and the real database. Read-only
  by default; any script touching production gets a `--dry-run` flag before anything else.
