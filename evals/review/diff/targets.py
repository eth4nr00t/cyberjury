"""Materialize Diff Review benchmark targets and grounding."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cyberjury.profiles.base import ReviewProfile
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import DiffGroundingOptions
from evals.benchmarks.cases import DiffCase
from evals.benchmarks.prepare import prepare_git_scope
from evals.review.source import review_scope, source_root


@dataclass(frozen=True, kw_only=True)
class CaseTarget:
    """Checked out source and grounding for one diff case."""

    root: Path
    grounding: DiffGroundingOptions


@contextmanager
def materialize(case: DiffCase, profile: ReviewProfile, diff: str) -> Iterator[CaseTarget]:
    """Materialize the source revision and its review context."""
    with source_root(case.target) as root:
        if root is None:
            raise ValueError(f"diff case {case.name!r} requires a repository target")
        review_root = review_scope(root, case.target)
        _prepare_evm_target(case, root, review_root)
        yield CaseTarget(root=root, grounding=_grounding(root, review_root, profile, diff))


def _prepare_evm_target(case: DiffCase, root: Path, review_root: Path) -> None:
    if case.profile != "evm":
        return
    prepared = prepare_git_scope(case.name, case.target, root, review_root, verify=False)
    if not prepared.ok:
        raise RuntimeError(f"EVM target preparation failed: {prepared.detail}")


def _grounding(
    root: Path,
    review_root: Path,
    profile: ReviewProfile,
    diff: str,
) -> DiffGroundingOptions:
    collector = build_diff_context_collector(root, profile, facts_root=review_root, review_diff=diff)
    return DiffGroundingOptions(
        prepare_diff=collector.prepare,
        source_snapshot=getattr(collector, "source_snapshot", None),
    )
