#!/bin/bash
# =============================================================================
# threat_feeds_sync.sh
#
# PURPOSE:
#   Runs on a systemd timer on an internal management host. Fetches the
#   configured public threat-intel feeds, validates and caps the merged
#   result, and commits + pushes docs/blocklist.txt straight to `main` -- no
#   PR, no human review step, because the point is a feed that stays current
#   unattended.
#   The safety net is threat_feeds/build.py's own gates (bogon/broad-prefix
#   rejection, delta-size gate, gitleaks scan), not a person in the loop.
#
# PAIRED WITH:
#   systemd/threat-feeds-sync.{timer,service}
#
# CONFIGURATION:
#   Edit REPO_DIR below if this repo is cloned somewhere other than /srv.
#
# PREREQUISITES:
#   - REPO_DIR is a clone of this repo with a working push credential for the
#     github-run account (see README.md -- this is a new grant, not automatic,
#     since deploy keys/PATs in this estate are scoped per-repo).
#   - gitleaks installed. build.py refuses to commit unscanned by default; see
#     .github/workflows/secret-scan.yml for the pinned version to install.
# =============================================================================

set -uo pipefail   # NOT -e: the build's exit code is inspected deliberately below

REPO_DIR="/srv/threat-feeds"

cd "$REPO_DIR" || { echo "ERROR: $REPO_DIR does not exist or is not accessible."; exit 1; }

echo "--- threat-feeds sync: $(date -u '+%Y-%m-%dT%H:%M:%SZ') ---"

git fetch origin
git checkout main
git reset --hard origin/main

if python3 -m threat_feeds.build; then
    echo "--- threat-feeds sync complete ---"
    exit 0
else
    rc=$?
    echo ""
    echo "ERROR: build refused (exit $rc). See the log above for which gate fired:"
    echo "  1 = a safety gate refused (empty list, delta-size gate, or gitleaks)"
    echo "  2 = every feed failed to fetch"
    echo "Nothing partial was pushed -- git_store.py commits and pushes only after"
    echo "every gate has already passed."
    exit "$rc"
fi
