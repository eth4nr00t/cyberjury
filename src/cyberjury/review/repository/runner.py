"""Adapt repository units to the shared unit scheduler."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from cyberjury.review.context import merge_grounding_coverage
from cyberjury.review.engine import ReviewCycle, extend_review_outcome, run_review_units
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.navigation import bind_source_operation
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.reviewer import ModelReviewer
from cyberjury.review.repository.union import Accumulator, Candidate
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def _known_for_unit(findings: list[Candidate], unit: Unit) -> list[Candidate]:
    files = set(unit.files)
    return [candidate for candidate in findings if candidate.file in files]


def run_units(
    units: list[Unit],
    reviewer: ModelReviewer,
    *,
    shared_context: str = "",
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    on_unit: Callable[[str, float], None] | None = None,
    on_judgment: Callable[[str, str, float], None] | None = None,
    accumulator: Accumulator | None = None,
) -> Accumulator:
    """Review every grounded unit once, continue past failed units, and fold findings into one union."""
    if ungrounded := [unit.name for unit in units if unit.grounding is None]:
        raise ValueError(f"repository units lack initial grounding: {', '.join(ungrounded)}")
    acc = accumulator if accumulator is not None else Accumulator()
    initial_errors = acc.errors

    def review_unit(unit: Unit, known_findings: list[Candidate]) -> ReviewCycle[Candidate]:
        def report_judgment(judgment_label: str, seconds: float) -> None:
            if on_judgment is not None:
                on_judgment(unit.name, judgment_label, seconds)

        grounding = unit.grounding
        if grounding is None:
            raise ValueError(f"repository unit {unit.name} lacks initial grounding")
        grounding.validate_snapshot()
        if not grounding.coverage.reviewable:
            return ReviewCycle(
                findings=[],
                errors=1,
                failure_reason=grounding.coverage.failure_reason,
                grounding=grounding.coverage,
            )
        cycle = reviewer.review_unit(
            replace(unit, grounding=grounding),
            finder_label=reviewer.label,
            shared_context=shared_context,
            known=_known_for_unit(known_findings, unit),
            on_judgment=report_judgment if on_judgment is not None else None,
        )
        operation_session = grounding.navigator.session() if grounding.navigator is not None else None
        cycle = replace(
            cycle,
            findings=[bind_source_operation(candidate, operation_session) for candidate in cycle.findings],
        )
        return replace(
            cycle,
            grounding=merge_grounding_coverage((grounding.coverage, cycle.grounding)),
        )

    outcome = run_review_units(
        units,
        execute=review_unit,
        accumulator=acc.finding_accumulator,
        unit_identity=lambda unit: unit.id or unit.name,
        failure_for=lambda index, total, unit, reason: ReviewUnitFailure(
            index=index,
            total=total,
            paths=unit.files,
            reason=reason,
        ),
        concurrency=concurrency,
        on_unit=(lambda unit, seconds: on_unit(unit.name, seconds)) if on_unit is not None else None,
    )
    acc.errors = initial_errors + outcome.errors
    acc.unit_failures = list(outcome.failures)
    acc.outcome = extend_review_outcome(outcome, findings=outcome.findings, errors=initial_errors)
    acc.failed_units = {
        units[failure.index - 1].name
        for failure in outcome.failures
        if failure.total == len(units) and 1 <= failure.index <= len(units)
    }
    return acc
