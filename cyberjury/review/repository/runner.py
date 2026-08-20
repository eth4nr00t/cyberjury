"""Adapt repository units to shared role rounds and convergence."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace

from cyberjury.review.context import merge_grounding_coverage
from cyberjury.review.engine import (
    ReviewCycle,
    ReviewPlan,
    extend_review_outcome,
    review_plan,
    run_review_units,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.repository.context import Unit, gather_context
from cyberjury.review.repository.reviewer import UnitReviewer, review_round, reviewer_label
from cyberjury.review.repository.union import Accumulator, Candidate
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


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
    converge_after: int = DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge,
    min_rounds: int = DEFAULT_REVIEW_SETTINGS.repository.min_adversarial_rounds,
    max_passes: int = DEFAULT_REVIEW_SETTINGS.repository.default_max_rounds,
    shared_context: str = "",
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    on_pass: Callable[[int, str, int, int], None] | None = None,
    on_unit: Callable[[str, float], None] | None = None,
    on_judgment: Callable[[str, int, int, str, float], None] | None = None,
    persist: Callable[[list[Candidate]], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Run repository units under `plan`, or build a plan from the round arguments.

    An explicit plan owns the stopping and convergence policy.
    """
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
    if len(reviewers) > plan.max_rounds:
        raise ValueError(f"{len(reviewers)} finder reviewers cannot run within the {plan.max_rounds} round cap")
    floor = max(plan.min_rounds, len(reviewers))
    if floor != plan.min_rounds or plan.stop_on_failure:
        plan = review_plan(
            plan.mode,
            max_rounds=plan.max_rounds,
            min_rounds=floor,
            converge_after=plan.converge_after,
            completion=plan.completion,
            stop_on_failure=False,
        )
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

        grounding = gather_context(unit)
        grounded_unit = replace(unit, grounding=grounding)
        if not grounding.coverage.complete:
            return ReviewCycle(
                findings=[],
                errors=1,
                failure_reason=grounding.coverage.failure_reason,
                grounding=grounding.coverage,
            )
        cycle = review_round(
            grounded_unit,
            reviewers[reviewer_index],
            finder_label=labels[reviewer_index],
            challenger=challenger,
            judge=judge,
            shared_context=shared_context,
            known=known,
            on_judgment=report_judgment if on_judgment is not None else None,
        )
        return replace(
            cycle,
            grounding=merge_grounding_coverage((grounding.coverage, cycle.grounding)),
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
    acc.failed_units = {
        units[failure.index - 1].name
        for failure in outcome.failures
        if failure.total == len(units) and 1 <= failure.index <= len(units)
    }
    return acc
