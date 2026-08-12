"""Adapt repository units to shared role rounds and convergence."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace

from cyberjury.review.engine import (
    ReviewCycle,
    ReviewPlan,
    extend_review_outcome,
    review_plan,
    run_review_units,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.reviewer import UnitReviewer, review_round, reviewer_label
from cyberjury.review.repository.union import Accumulator, Candidate


def _known_for_unit(findings: list[Candidate], unit: Unit) -> list[Candidate]:
    files = set(unit.files)
    return [candidate for candidate in findings if not candidate.file or candidate.file in files]


def run_passes(
    units: list[Unit],
    reviewer: UnitReviewer | Sequence[UnitReviewer],
    *,
    challenger: UnitReviewer | None = None,
    judge: UnitReviewer | None = None,
    plan: ReviewPlan | None = None,
    converge_after: int = 2,
    min_rounds: int = 2,
    max_passes: int = 24,
    shared_context: str = "",
    concurrency: int = 8,
    on_pass: Callable[[int, str, int, int], None] | None = None,
    on_unit: Callable[[str, float], None] | None = None,
    on_judgment: Callable[[str, int, int, str, float], None] | None = None,
    persist: Callable[[list[Candidate]], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Run role passes over the worklist until the union converges or `max_passes`."""
    if (challenger is None) != (judge is None):
        raise ValueError("challenger and judge reviewers must be configured together")
    reviewers = [reviewer] if isinstance(reviewer, UnitReviewer) else list(reviewer)
    if not reviewers:
        raise ValueError("at least one finder reviewer is required")
    labels = [reviewer_label(rv, f"model-{k}") for k, rv in enumerate(reviewers)]
    plan = plan or review_plan(
        "adversarial",
        max_rounds=max_passes,
        min_rounds=min_rounds,
        converge_after=converge_after,
        stop_on_failure=False,
    )
    floor = max(plan.min_rounds, len(reviewers))
    if floor != plan.min_rounds or plan.stop_on_failure:
        plan = replace(plan, min_rounds=floor, stop_on_failure=False)
    acc = accumulator if accumulator is not None else Accumulator(converge_after=plan.converge_after)
    if acc.converge_after != plan.converge_after:
        raise ValueError("the accumulator and review plan must use the same convergence threshold")
    initial_errors = acc.errors

    def review_unit(round_no: int, unit: Unit, known_findings: list[Candidate]) -> ReviewCycle[Candidate]:
        reviewer_index = (round_no - 1) % len(reviewers)
        known = _known_for_unit(known_findings, unit)

        def report_judgment(index: int, total: int, label: str, seconds: float) -> None:
            if on_judgment is not None:
                on_judgment(unit.name, index, total, label, seconds)

        return review_round(
            unit,
            reviewers[reviewer_index],
            finder_label=labels[reviewer_index],
            challenger=challenger,
            judge=judge,
            shared_context=shared_context,
            known=known,
            on_judgment=report_judgment if on_judgment is not None else None,
        )

    def record(round_no: int, new_count: int, union_size: int, _cycle: ReviewCycle[Candidate]) -> None:
        if persist is not None:
            persist(acc.findings)
        if on_pass is not None:
            on_pass(round_no, labels[(round_no - 1) % len(reviewers)], new_count, union_size)

    outcome = run_review_units(
        units,
        plan=plan,
        execute=review_unit,
        accumulator=acc.finding_accumulator,
        failure_for=lambda index, total, unit, reason: ReviewUnitFailure(
            index=index,
            total=total,
            paths=tuple(unit.files) or (unit.name,),
            reason=reason,
        ),
        convergence=acc.convergence,
        concurrency=concurrency,
        on_unit=(lambda unit, seconds: on_unit(unit.name, seconds)) if on_unit is not None else None,
        on_round=record,
    )
    acc.errors = initial_errors + outcome.errors
    acc.unit_failures = outcome.failures
    acc.outcome = extend_review_outcome(outcome, findings=outcome.findings, errors=initial_errors)
    failed_paths = {failure.paths for failure in outcome.failures}
    acc.failed_units = {unit.name for unit in units if (tuple(unit.files) or (unit.name,)) in failed_paths}
    return acc
