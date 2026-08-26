#!/bin/bash
# =============================================================================
# threat_feeds_sync.sh
#
# PURPOSE:
#   Runs on a systemd timer on an internal management host. Fetches the
#   configured public threat-intel feeds, runs each shape's own selection
#   logic (see threat_feeds/shapes.py), and commits + pushes every
#   shape x profile file straight to the orphan `gh-pages` branch -- no PR,
#   no human review step, because the point is a feed that stays current
#   unattended. This script itself only keeps `main` (the CODE branch)
#   current; build.py manages the gh-pages branch entirely on its own via a
#   separate worktree -- see threat_feeds/git_store.py.
#   The safety net is threat_feeds/build.py's own gates (bogon/broad-prefix
#   rejection, per-file delta-size gate, gitleaks scan), not a person in the
#   loop.
#
# PAIRED WITH:
#   systemd/threat-feeds-sync.{timer,service}
#
# CONFIGURATION:
#   Edit REPO_DIR below if this repo is cloned somewhere other than /srv.
#
# PREREQUISITES:
#   - Set up via ops/install.sh, not by hand -- it creates the dedicated
#     threat-feeds service account (NOT github-run, which is the Actions
#     runner) with its home directory outside /home, sets a local git
#     identity on the clone, and installs the systemd units. See README.md.
#   - REPO_DIR is a clone of this repo with a working push credential for
#     the threat-feeds account -- a new grant, not automatic, since deploy
#     keys/PATs in this estate are scoped per-repo.
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
    echo "  1 = every shape x profile was gate-refused (empty list, delta-size gate,"
    echo "      or gitleaks) -- a SINGLE profile failing its own gate does not stop"
    echo "      the others from publishing; this code means ALL of them failed"
    echo "  2 = every feed in every shape failed to fetch"
    echo "Nothing partial was pushed -- git_store.py commits and pushes only after"
    echo "every gate has already passed."
    exit "$rc"
fi
