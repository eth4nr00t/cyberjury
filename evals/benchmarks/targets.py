"""Materialize the pinned git targets of benchmark cases."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path


def target_repository(target: Mapping[str, str]) -> Path:
    """Return the local repository path of a git target without touching it."""
    if url := target.get("url"):
        name = Path(url.rstrip("/").removesuffix(".git")).name or "repo"
        digest = sha256(url.encode("utf-8")).hexdigest()[:12]
        return Path.home() / ".cache" / "cyberjury" / "benchmark-targets" / f"{name}-{digest}"
    return Path(target["local_path"])


def git_target_root(target: Mapping[str, str]) -> Path:
    """Resolve a git target to a local repository root, cloning or updating a URL target in the user cache."""
    root = target_repository(target)
    if url := target.get("url"):
        _sync_clone(url, root)
    return root


def ensure_git_target_refs(target: Mapping[str, str], root: Path) -> None:
    """Fetch exact commit targets that are not advertised by branch or tag refs."""
    if not target.get("url"):
        return
    for ref in (target.get("base"), target.get("commit")):
        if ref:
            _ensure_commit(root, ref)


@contextmanager
def source_root(target: Mapping[str, str]) -> Iterator[Path]:
    """Check out the exact source commit of a git target."""
    root = git_target_root(target)
    ensure_git_target_refs(target, root)
    temporary = Path(tempfile.mkdtemp(prefix="cyberjury-eval-target-"))
    try:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(temporary), target["commit"]],
            check=True,
            capture_output=True,
            text=True,
        )
        yield temporary
    finally:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "remove", "--force", str(temporary)],
            check=False,
            capture_output=True,
            text=True,
        )
        shutil.rmtree(temporary, ignore_errors=True)


def _ensure_commit(root: Path, ref: str) -> None:
    exists = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if exists.returncode == 0:
        return
    subprocess.run(
        ["git", "-C", str(root), "fetch", "origin", ref],
        capture_output=True,
        text=True,
        check=True,
    )


def _sync_clone(url: str, root: Path) -> None:
    if (root / ".git").is_dir():
        subprocess.run(
            ["git", "-C", str(root), "fetch", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*"],
            capture_output=True,
            text=True,
            check=True,
        )
        return
    root.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(root)],
        capture_output=True,
        text=True,
        check=True,
    )
