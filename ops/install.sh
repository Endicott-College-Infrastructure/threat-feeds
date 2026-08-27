#!/bin/sh
#
# install.sh -- turn a repo clone into a running threat-feeds sync job.
#
# Modelled on a similar capture-style tool's own ops/install.sh, which found
# (and fixed) two real bugs the hard way on its deployment host: a service
# account with no home directory has no git identity, so its first commit
# fails outright; and ProtectHome=true masks /home entirely, which breaks
# anything resolving $HOME (git's global config lookup, gitleaks) unless the
# account's home is pointed elsewhere. Both are applied here proactively.
#
# USAGE
#   cd /srv/threat-feeds && sudo ./ops/install.sh              # dry run
#   cd /srv/threat-feeds && sudo ./ops/install.sh --commit      # actually install
#
# Idempotent: re-running is the upgrade path. Never overwrites an existing
# systemd unit's [Install] enable state, and never touches credentials --
# this tool has none (every feed source is public and unauthenticated).
#
# REQUIRES: root, git, python3.10+, gitleaks.

set -eu

COMMIT=0
SVC_USER=threat-feeds
for arg in "$@"; do
    case "$arg" in
        --commit)     COMMIT=1 ;;
        --dry-run)    COMMIT=0 ;;
        --svc-user=*) SVC_USER=${arg#*=} ;;
        -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

HERE=$(cd "$(dirname "$0")/.." && pwd)   # the repo root -- expected to be /srv/threat-feeds

FAILED=0

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (try: sudo $0 $*)" >&2
    exit 2
fi

if [ ! -d "$HERE/.git" ]; then
    echo "ERROR: $HERE is not a git repository." >&2
    echo "git_store.py commits to this clone directly -- it has to be a real repo." >&2
    exit 2
fi

if ! id "$SVC_USER" >/dev/null 2>&1; then
    cat >&2 <<EOF
ERROR: service account '$SVC_USER' does not exist on this host.

Create it with its home directory OUTSIDE /home -- ProtectHome=true in the
unit masks /home entirely, and a service account's default home lands there
regardless of --no-create-home. Point it at the state directory instead:
    sudo useradd --system -M --home-dir /var/lib/$SVC_USER --shell /usr/sbin/nologin $SVC_USER

Or pass the real name:
    sudo $0 --svc-user=<name> $*
EOF
    exit 2
fi

say() {
    if [ "$COMMIT" -eq 1 ]; then echo "  $*"; else echo "  [dry-run] $*"; fi
}

run() {
    if [ "$COMMIT" -eq 1 ]; then
        "$@" || { echo "FAILED: $*" >&2; FAILED=1; }
    fi
}

echo "--- Ownership ---"
CURRENT_OWNER=$(stat -c '%U' "$HERE")
if [ "$CURRENT_OWNER" = "$SVC_USER" ]; then
    say "$HERE already owned by $SVC_USER -- skipping the recursive chown"
else
    say "chown -R $SVC_USER:$SVC_USER $HERE"
    run chown -R "$SVC_USER:$SVC_USER" "$HERE"
fi

echo "--- Git identity (local to this clone, not --global) ---"
# Without this, git_store.py's first `git commit` fails outright with git's
# classic "Please tell me who you are" -- a service account with no home
# directory (or one masked by ProtectHome) has no ~/.gitconfig to fall back
# on. .invalid is the RFC 2606 reserved TLD, guaranteed never to resolve or
# receive mail -- this is commit metadata for an automated pipeline, not a
# real mailbox.
say "git -C $HERE config user.name 'threat-feeds automation'"
run runuser -u "$SVC_USER" -- git -C "$HERE" config user.name "threat-feeds automation"
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo unknown-host)
say "git -C $HERE config user.email 'threat-feeds@${HOSTNAME_SHORT}.invalid'"
run runuser -u "$SVC_USER" -- git -C "$HERE" config user.email "threat-feeds@${HOSTNAME_SHORT}.invalid"

echo "--- systemd units ---"
say "install ops/systemd/threat-feeds-sync.{service,timer} to /etc/systemd/system/"
run install -m 0644 "$HERE/ops/systemd/threat-feeds-sync.service" /etc/systemd/system/
run install -m 0644 "$HERE/ops/systemd/threat-feeds-sync.timer" /etc/systemd/system/
say "systemctl daemon-reload"
run systemctl daemon-reload

echo "--- ops/threat_feeds_sync.sh ---"
say "install ops/threat_feeds_sync.sh to /opt/scripts/threat_feeds_sync.sh"
run install -m 0755 "$HERE/ops/threat_feeds_sync.sh" /opt/scripts/threat_feeds_sync.sh

if [ "$COMMIT" -eq 0 ]; then
    echo
    echo "Dry run only -- nothing changed. Re-run with --commit to apply."
    echo "After --commit: run once by hand (systemctl start threat-feeds-sync.service),"
    echo "read the output, THEN enable the timer -- see README.md."
fi

[ "$FAILED" -eq 0 ]
