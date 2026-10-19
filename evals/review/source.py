"""Materialize pinned benchmark source commits in disposable worktrees."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from evals.benchmarks.cases import ensure_git_target_refs, git_target_root


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
