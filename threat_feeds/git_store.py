"""
Gate and publish shaped/tiered blocklist files to an orphan `gh-pages`
branch, checked out in its own worktree.

WHY AN ORPHAN BRANCH, NOT main/docs

The single-file design committed docs/blocklist.txt to main directly. Once
this repo publishes multiple shapes/tiers -- some capped (general-200,
sip-400), some uncapped and large (general-full, sip-full, botnet-full,
churning daily) -- committing that to main forever bloats code history with
data that has no code-review value. Configuration/data history and code
history answer different questions; mixing them makes `git log` on either
useless. Modelled on a similar capture tool's own orphan-branch snapshot
store in this estate.

HOW THE ORPHAN BRANCH IS CREATED

With plumbing, not `git worktree add --orphan` (needs git 2.42; this targets
Debian stable, which may ship older):
    empty_tree = git hash-object -t tree /dev/null
    commit     = git commit-tree <empty_tree> -m ...      # no -p, parentless
    git branch gh-pages <commit>
    git worktree add <dir> gh-pages
A linked worktree shares the repo's .git config, so a git identity set once
on the main clone (see ops/install.sh) applies here too -- nothing extra
needed for this worktree specifically.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MAX_DELTA_PCT = 40
DEFAULT_BRANCH = "gh-pages"


class GateRefusalError(RuntimeError):
    """A safety gate fired. Nothing was written for this profile."""


def check_nonempty(new_count: int) -> None:
    if new_count == 0:
        raise GateRefusalError(
            "the built list is empty. Refusing to publish an empty file -- "
            "that would silently disable every consumer pointed at this feed."
        )


def check_delta(previous_count: int | None, new_count: int, max_delta_pct: int) -> None:
    """
    Refuse a run that shrinks or grows the entry count past max_delta_pct.

    previous_count is None on the very first publish of this specific file --
    that is a bootstrap, not a delta, so it is never gated here.
    """
    if previous_count is None:
        log.info("no previously published file -- treating this as the initial publish")
        return
    if previous_count == 0:
        return  # nothing to compute a percentage against

    delta_pct = abs(new_count - previous_count) * 100 // previous_count
    if delta_pct > max_delta_pct:
        raise GateRefusalError(
            f"entry count moved from {previous_count} to {new_count} "
            f"({delta_pct}%), exceeding --max-delta-pct {max_delta_pct}. "
            "A feed outage or a corrupted feed should be investigated, not "
            "published live unattended."
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
        log.error("gitleaks missing, scan skipped by request -- publishing unscanned")
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
        f"gitleaks exited {proc.returncode} scanning {root}. Nothing published.\n"
        f"{(proc.stdout or proc.stderr or '').strip()[:2000]}"
    )


class GhPagesStore:
    """
    Write, gate, and publish files on an orphan branch in its own worktree --
    isolated from the caller's own working tree, so a stray operation on the
    code checkout can never touch published data and vice versa.
    """

    def __init__(
        self, repo: Path, *, branch: str = DEFAULT_BRANCH, worktree: Path | None = None
    ):
        self.repo = Path(repo).resolve()
        self.branch = branch
        self._worktree = (
            Path(worktree).resolve() if worktree else self._default_worktree()
        )

    def _default_worktree(self) -> Path:
        state = os.environ.get("XDG_STATE_HOME")
        base = Path(state) if state else Path.home() / ".local" / "state"
        return base / "threat_feeds" / "worktrees" / f"{self.repo.name}_{self.branch}"

    @property
    def worktree(self) -> Path:
        return self._worktree

    def ensure_worktree(self) -> Path:
        """Create the orphan branch and its worktree if they don't exist yet."""
        if not (self.repo / ".git").exists():
            raise RuntimeError(f"{self.repo} is not a git repository")

        # Clear registrations whose directory has been deleted, otherwise
        # `worktree add` refuses with a path-already-registered error.
        self._git(["worktree", "prune"], cwd=self.repo)

        if (self._worktree / ".git").exists():
            self._assert_worktree_sane()
            return self._worktree

        self._worktree.parent.mkdir(parents=True, exist_ok=True)

        if not self._branch_exists():
            if self._remote_branch_exists():
                # A fresh clone of an already-published repo: track the real
                # remote history instead of creating a second, divergent
                # orphan root -- that would make every future push a
                # non-fast-forward rejection against the branch that's
                # actually live.
                self._git(
                    ["branch", "--track", self.branch, f"origin/{self.branch}"],
                    cwd=self.repo,
                )
                log.info(
                    "created local %s tracking origin/%s", self.branch, self.branch
                )
            else:
                empty_tree = self._git(
                    ["hash-object", "-t", "tree", "/dev/null"], cwd=self.repo
                ).strip()
                commit = self._git(
                    [
                        "commit-tree",
                        empty_tree,
                        "-m",
                        (
                            "[Agent] Initialize gh-pages\n\n"
                            "Parentless on purpose: published data history and code "
                            "history answer different questions."
                        ),
                    ],
                    cwd=self.repo,
                ).strip()
                self._git(["branch", self.branch, commit], cwd=self.repo)
                log.info("created orphan branch %s at %s", self.branch, commit[:7])

        self._git(["worktree", "add", str(self._worktree), self.branch], cwd=self.repo)
        log.info("checked out %s in %s", self.branch, self._worktree)
        self._assert_worktree_sane()
        return self._worktree

    def _branch_exists(self) -> bool:
        try:
            self._git(
                ["rev-parse", "--verify", f"refs/heads/{self.branch}"], cwd=self.repo
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _remote_branch_exists(self) -> bool:
        try:
            self._git(["fetch", "origin", self.branch], cwd=self.repo)
        except subprocess.CalledProcessError:
            return False
        try:
            self._git(
                ["rev-parse", "--verify", f"refs/remotes/origin/{self.branch}"],
                cwd=self.repo,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _assert_worktree_sane(self) -> None:
        """
        Refuse to touch a worktree that is not the branch and directory we
        think. Cheap, and the failure it prevents is publishing data onto a
        code branch -- or worse, into the caller's own checkout.
        """
        current = self._git(["branch", "--show-current"], cwd=self._worktree).strip()
        if current != self.branch:
            raise RuntimeError(
                f"{self._worktree} is on branch {current!r}, expected {self.branch!r}. "
                "Refusing to write anything here."
            )
        top = Path(
            self._git(["rev-parse", "--show-toplevel"], cwd=self._worktree).strip()
        )
        if top.resolve() != self._worktree:
            raise RuntimeError(
                f"git reports toplevel {top} but expected {self._worktree}. "
                "Refusing to write anything here."
            )

    def previous_line_count(self, relative_path: str) -> int | None:
        """Entry count of the last published version of this file, or None if never published."""
        path = self._worktree / relative_path
        if not path.is_file():
            return None
        return len(
            [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        )

    def write(self, relative_path: str, content: str) -> None:
        path = self._worktree / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def discard_uncommitted(self) -> None:
        """
        Reset the worktree to HEAD and remove untracked files. Used when a
        later gate (gitleaks) fires after some files were already written --
        leaves the worktree clean for the next run rather than half-written.
        """
        self._git(["checkout", "--", "."], cwd=self._worktree)
        self._git(["clean", "-fd"], cwd=self._worktree)

    def changed_files(self) -> list[str]:
        raw = self._git(
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=self._worktree,
        )
        return [entry[3:] for entry in raw.split("\0") if len(entry) > 3]

    def commit_and_push(
        self, message: str, *, remote: str = "origin", dry_run: bool = False
    ) -> str | None:
        """
        Stage everything changed, commit, and push -- assumes gates already
        passed. Returns the new commit sha, or None if nothing changed or
        this was a dry run.
        """
        self._assert_worktree_sane()
        changed = self.changed_files()
        if not changed:
            log.info("no changes to publish")
            return None
        log.info("changed files: %s", ", ".join(changed))

        if dry_run:
            log.info("dry run: would commit and push %d file(s)", len(changed))
            return None

        self._git(["add", "-A"], cwd=self._worktree)
        self._git(["commit", "-q", "-m", message], cwd=self._worktree)
        sha = self._git(["rev-parse", "HEAD"], cwd=self._worktree).strip()
        log.info("committed %s", sha[:9])

        # Not a force push: only this job writes to this branch, so a
        # non-fast-forward means something unexpected happened and a human
        # should look rather than have history silently overwritten.
        self._git(["push", remote, self.branch], cwd=self._worktree)
        log.info("pushed %s to %s/%s", sha[:9], remote, self.branch)
        return sha

    def _git(self, args: list[str], *, cwd: Path) -> str:
        # GIT_DIR, GIT_WORK_TREE, and GIT_INDEX_FILE are removed: an inherited
        # value would silently redirect every operation here at some other
        # repository or worktree.
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")
        }
        proc = subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(
                proc.returncode, proc.args, proc.stdout, proc.stderr
            )
        return proc.stdout
