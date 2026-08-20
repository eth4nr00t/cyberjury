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

    root: Path | None
    grounding: DiffGroundingOptions


@contextmanager
def materialize(case: DiffCase, profile: ReviewProfile, diff: str) -> Iterator[CaseTarget]:
    """Materialize the source revision and its review context."""
    with source_root(case.target) as root:
        review_root = review_scope(root, case.target) if root is not None else None
        _prepare_evm_target(case, root, review_root)
        yield CaseTarget(root=root, grounding=_grounding(case, root, review_root, profile, diff))


def _prepare_evm_target(case: DiffCase, root: Path | None, review_root: Path | None) -> None:
    if root is None or review_root is None or case.profile != "evm" or case.review_context != "repository":
        return
    prepared = prepare_git_scope(case.name, case.target, root, review_root, verify=False)
    if not prepared.ok:
        raise RuntimeError(f"EVM target preparation failed: {prepared.detail}")


def _grounding(
    case: DiffCase,
    root: Path | None,
    review_root: Path | None,
    profile: ReviewProfile,
    diff: str,
) -> DiffGroundingOptions:
    if case.review_context != "repository":
        return DiffGroundingOptions()
    if case.context or root is None:
        return DiffGroundingOptions(context=case.context)
    collector = build_diff_context_collector(root, profile, facts_root=review_root, review_diff=diff)
    return DiffGroundingOptions(prepare_diff=collector.prepare)
