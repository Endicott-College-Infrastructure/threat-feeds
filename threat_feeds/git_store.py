"""
Gate and commit the built blocklist to `main`, then push.

Unlike a snapshot-style capture tool's own store (a parentless orphan branch in
its own worktree, keeping dissimilar config snapshots out of code history),
this repo's only content IS the blocklist -- there's no code history to keep
separate from it. This commits directly to `main` in the working tree the caller
already has checked out.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MAX_DELTA_PCT = 40


class GateRefusalError(RuntimeError):
    """A safety gate fired. Nothing was committed or pushed."""


def check_nonempty(new_count: int) -> None:
    if new_count == 0:
        raise GateRefusalError(
            "the built list is empty. Refusing to commit an empty blocklist -- "
            "that would silently disable every device pointed at this feed."
        )


def check_delta(previous_count: int | None, new_count: int, max_delta_pct: int) -> None:
    """
    Refuse a run that shrinks or grows the entry count past max_delta_pct.

    previous_count is None on the very first run ever (no committed file yet).
    That is a bootstrap, not a delta -- it is never gated here, since there is
    nothing yet to compare against.
    """
    if previous_count is None:
        log.info(
            "no committed blocklist yet -- treating this run as the initial commit"
        )
        return
    if previous_count == 0:
        return  # nothing to compute a percentage against

    delta_pct = abs(new_count - previous_count) * 100 // previous_count
    if delta_pct > max_delta_pct:
        raise GateRefusalError(
            f"entry count moved from {previous_count} to {new_count} "
            f"({delta_pct}%), exceeding --max-delta-pct {max_delta_pct}. "
            "A feed outage or a corrupted feed should be investigated, not "
            "pushed live unattended. Only pass a higher --max-delta-pct if this "
            "change is genuinely expected."
        )


def scan_gitleaks(root: Path, *, require: bool = True) -> None:
    binary = shutil.which("gitleaks")
    if binary is None:
        if require:
            raise GateRefusalError(
                "gitleaks is not installed and the secret scan is required. "
                "Install it (see .github/workflows/secret-scan.yml for the pinned "
                "version) or pass --allow-missing-gitleaks, which is not the "
                "default for a reason."
            )
        log.error("gitleaks missing, scan skipped by request -- committing unscanned")
        return

    proc = subprocess.run(
        [binary, "dir", str(root), "--no-banner", "--redact", "--exit-code", "1"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        log.info("gitleaks found nothing in %s", root)
        return
    raise GateRefusalError(
        f"gitleaks exited {proc.returncode} scanning {root}. Nothing committed.\n"
        f"{(proc.stdout or proc.stderr or '').strip()[:2000]}"
    )


def previous_entry_count(repo: Path, blocklist_path: Path) -> int | None:
    """Entry count of the last committed blocklist, or None if never committed."""
    rel = blocklist_path.relative_to(repo)
    proc = _git(repo, ["show", f"HEAD:{rel}"], check=False)
    if proc.returncode != 0:
        return None
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def commit_and_push(
    repo: Path,
    blocklist_path: Path,
    message: str,
    *,
    remote: str = "origin",
    branch: str = "main",
    dry_run: bool = False,
) -> str | None:
    """
    Stage the blocklist, commit, and push -- assumes gates already passed.

    Returns the new commit sha, or None if there was nothing to commit or this
    was a dry run.
    """
    status = _git(repo, ["status", "--porcelain", "--", str(blocklist_path)]).stdout
    if not status.strip():
        log.info("no change to %s -- nothing to commit", blocklist_path)
        return None

    if dry_run:
        log.info("dry run: would commit and push %s", blocklist_path)
        return None

    _git(repo, ["add", "--", str(blocklist_path)])
    _git(repo, ["commit", "-q", "-m", message])
    sha = _git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    log.info("committed %s", sha[:9])

    # Not a force push: only this job writes to this branch, so a non-fast-forward
    # means something unexpected happened (a manual edit, a second runner) and a
    # human should look rather than have history silently overwritten.
    _git(repo, ["push", remote, branch])
    log.info("pushed %s to %s/%s", sha[:9], remote, branch)
    return sha


def _git(
    repo: Path, args: list[str], *, check: bool = True
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, proc.args, proc.stdout, proc.stderr
        )
    return proc
