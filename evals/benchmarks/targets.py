"""Materialized pinned Git targets of benchmark cases."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path


def target_repository(target: Mapping[str, str]) -> Path:
    """Return the local repository path of a Git target without touching it."""
    if url := target.get("url"):
        name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
        digest = sha256(url.encode("utf-8")).hexdigest()[:12]
        return Path.home() / ".cache" / "cyberjury" / "benchmark-targets" / f"{name}-{digest}"
    return Path(target["local_path"])


def git_target_root(target: Mapping[str, str]) -> Path:
    """Resolve a Git target to a local root, syncing a URL target and its pinned commits in the user cache."""
    root = target_repository(target)
    if url := target.get("url"):
        _sync_clone(url, root)
        for ref in (target.get("base"), target.get("commit")):
            if ref:
                _ensure_commit(root, ref)
    return root


@contextmanager
def source_root(target: Mapping[str, str]) -> Iterator[Path]:
    """Check out the exact source commit of a Git target."""
    root = git_target_root(target)
    temporary = Path(tempfile.mkdtemp(prefix="cyberjury-eval-target-"))
    try:
        _git("-C", str(root), "worktree", "add", "--detach", "--quiet", str(temporary), target["commit"])
        yield temporary
    finally:
        _git("-C", str(root), "worktree", "remove", "--force", str(temporary), check=False)
        shutil.rmtree(temporary, ignore_errors=True)


def _git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)
    if check and completed.returncode != 0:
        detail = (completed.stderr or "").strip() or f"exit status {completed.returncode}"
        raise RuntimeError(f"git {' '.join(arguments)} failed: {detail}")
    return completed


def _ensure_commit(root: Path, ref: str) -> None:
    if _git("-C", str(root), "cat-file", "-e", f"{ref}^{{commit}}", check=False).returncode != 0:
        _git("-C", str(root), "fetch", "origin", ref)


def _sync_clone(url: str, root: Path) -> None:
    if (root / ".git").is_dir():
        _git("-C", str(root), "fetch", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*")
        return
    root.parent.mkdir(parents=True, exist_ok=True)
    _git("clone", "--filter=blob:none", "--no-checkout", url, str(root))
