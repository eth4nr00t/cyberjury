"""Materialize Repository Review benchmark targets."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cyberjury.profiles.base import ReviewProfile
from evals.benchmarks.contract import RepositoryCase
from evals.benchmarks.prepare import PrepareTarget, prepare_git_scope, prepare_target
from evals.review.source import review_scope, source_root


@dataclass(frozen=True, kw_only=True)
class CaseTarget:
    """Checked out repository root and selected review scope."""

    root: Path
    scope: Path


@contextmanager
def materialize(case: RepositoryCase, profile: ReviewProfile) -> Iterator[CaseTarget]:
    """Materialize the exact source revision required by one repository case."""
    if case.target.get("type") == "explorer":
        with _explorer_target(case) as target:
            yield target
        return
    with source_root(case.target) as root:
        if root is None:
            raise ValueError(f"repository benchmark {case.id!r} has no materializable source")
        scope = review_scope(root, case.target)
        _prepare_git_target(case, profile, root, scope)
        yield CaseTarget(root=root, scope=scope)


def _prepare_git_target(case: RepositoryCase, profile: ReviewProfile, root: Path, scope: Path) -> None:
    if profile.name != "evm":
        return
    prepared = prepare_git_scope(case.id, case.target, root, scope, verify=False)
    if not prepared.ok:
        raise RuntimeError(f"EVM target preparation failed: {prepared.detail}")


@contextmanager
def _explorer_target(case: RepositoryCase) -> Iterator[CaseTarget]:
    name = case.id.replace(":", "-")
    with tempfile.TemporaryDirectory(prefix="cyberjury-eval-explorer-") as temporary:
        root = Path(temporary)
        prepared = prepare_target(name, cast(PrepareTarget, case.target), root)
        if not prepared.ok:
            raise RuntimeError(f"explorer target preparation failed: {prepared.detail}")
        source = root / name
        yield CaseTarget(root=source, scope=review_scope(source, case.target))
