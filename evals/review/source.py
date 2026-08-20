"""Materialize pinned benchmark source revisions for review adapters."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from pathlib import Path

from evals.benchmarks.cases import ensure_git_target_refs, git_target_root


@contextmanager
def source_root(target: Mapping[str, object]) -> Iterator[Path | None]:
    """Check out the exact source revision required by a git target."""
    if target.get("type") != "git":
        with nullcontext(None) as root:
            yield root
        return
    root = git_target_root(dict(target))
    if root is None:
        with nullcontext(None) as source:
            yield source
        return
    ensure_git_target_refs(dict(target), root)
    with target_tree(root, target.get("ref")) as source:
        yield source


def review_scope(root: Path, target: Mapping[str, object]) -> Path:
    """Resolve a benchmark path inside its checked out repository."""
    path = str(target.get("path") or "").strip()
    if target.get("type") == "git" and not (target.get("url") or target.get("root")):
        return root
    if not path or path == ".":
        return root
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(f"target path {path!r} must stay inside the repository")
    scoped = (root / rel).resolve()
    if not scoped.is_dir():
        raise ValueError(f"target path {path!r} does not exist in the checked out repository")
    return scoped


@contextmanager
def target_tree(root: Path, ref: object) -> Iterator[Path]:
    """Use a disposable worktree for a pinned revision."""
    if not ref:
        yield root
        return
    temporary = Path(tempfile.mkdtemp(prefix="cyberjury-eval-target-"))
    try:
        subprocess.run(
            ["git", "-C", str(root), "worktree", "add", "--detach", "--quiet", str(temporary), str(ref)],
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
