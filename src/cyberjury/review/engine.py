"""Schedule review units, fold their findings into one union, and summarize the outcome."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from threading import Lock
from time import perf_counter
from typing import Protocol

from cyberjury.providers.metering import model_call_scope
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    merge_grounding_coverage,
    with_source_evidence,
)
from cyberjury.review.exchange import EvidenceJudgment
from cyberjury.review.failures import ReviewUnitFailure, exception_reason
from cyberjury.review.navigation import SourceNavigationSession
from cyberjury.review.provenance import tag_found_by
from cyberjury.review.union import FindingAccumulator

_FAILURE_REASON_LIMIT = 2000
_FAILURE_REASON_TRUNCATED = "... [failure reason truncated]"


@dataclass(frozen=True, kw_only=True)
class ReviewCycle[T]:
    """One target adapter result consumed by the shared scheduler."""

    findings: list[T]
    incomplete: list[T] = field(default_factory=list)
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()

    @property
    def clean(self) -> bool:
        """Allow judgment with visible limitations while rejecting unavailable evidence."""
        return not self.incomplete and self.errors == 0 and not self.failure_reason and self.grounding.complete


@dataclass(frozen=True, kw_only=True)
class ReviewOutcome[T]:
    """The shared completion contract for one review target."""

    findings: tuple[T, ...]
    failures: tuple[ReviewUnitFailure, ...] = ()
    incomplete: tuple[T, ...] = ()
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)

    def __post_init__(self) -> None:
        """Bound the persisted failure reason."""
        if len(self.failure_reason) > _FAILURE_REASON_LIMIT:
            end = _FAILURE_REASON_LIMIT - len(_FAILURE_REASON_TRUNCATED)
            object.__setattr__(self, "failure_reason", self.failure_reason[:end] + _FAILURE_REASON_TRUNCATED)

    @property
    def complete(self) -> bool:
        """Require no failed or incomplete judgment step."""
        return (
            not self.failures
            and not self.incomplete
            and self.errors == 0
            and not self.failure_reason
            and self.grounding.complete
        )


def extend_review_outcome[T](
    outcome: ReviewOutcome[T],
    *,
    findings: Iterable[T],
    failures: Iterable[ReviewUnitFailure] = (),
    incomplete: Iterable[T] = (),
    errors: int = 0,
    failure_reason: str = "",
    grounding: GroundingCoverage | None = None,
) -> ReviewOutcome[T]:
    """Add target postprocessing without losing the shared completion state."""
    return ReviewOutcome(
        findings=tuple(findings),
        failures=tuple(dict.fromkeys((*outcome.failures, *failures))),
        incomplete=tuple(dict.fromkeys((*outcome.incomplete, *incomplete))),
        errors=outcome.errors + errors,
        failure_reason=". ".join(reason for reason in (outcome.failure_reason, failure_reason) if reason),
        grounding=merge_grounding_coverage(
            (outcome.grounding, grounding) if grounding is not None else (outcome.grounding,)
        ),
    )


def run_grounded_judgment[T](
    context: GroundingContext,
    *,
    run_judgment: Callable[[SourceNavigationSession | None], EvidenceJudgment[T]],
    finder_label: str,
) -> ReviewCycle[T]:
    """Run one grounded judgment per unit and keep candidates produced before a failure."""
    navigation = context.navigator.session() if context.navigator is not None else None
    try:
        judgment = run_judgment(navigation)
    except Exception as exc:
        judgment = EvidenceJudgment(findings=[], failure_reason=exception_reason(exc))
    final = with_source_evidence(context, judgment.source_evidence)
    return ReviewCycle(
        findings=tag_found_by(judgment.findings, finder_label),
        errors=int(bool(judgment.failure_reason)),
        failure_reason=judgment.failure_reason,
        grounding=merge_grounding_coverage((final.coverage, judgment.grounding)),
        source_evidence=final.source_evidence,
    )


class ReviewUnit(Protocol):
    """A planned unit the scheduler identifies and attributes failures to."""

    @property
    def id(self) -> str:
        """The content bound unit plan id."""

    @property
    def paths(self) -> tuple[str, ...]:
        """The source paths the unit reviews."""


def run_review_units[U: ReviewUnit, T](
    units: list[U],
    *,
    execute: Callable[[U], ReviewCycle[T]],
    accumulator: FindingAccumulator[T],
    concurrency: int = 1,
    restore: Callable[[U], ReviewCycle[T] | None] | None = None,
    on_unit: Callable[[U, ReviewCycle[T], float], None] | None = None,
) -> ReviewOutcome[T]:
    """Review every open unit once, continue past failed units, and record each failure."""
    if not units:
        raise ValueError("at least one review unit is required")
    unit_ids = tuple(unit.id for unit in units)
    if any(not identity for identity in unit_ids):
        raise ValueError("review unit identities must be nonempty")
    if len(set(unit_ids)) != len(unit_ids):
        raise ValueError("review unit identities must be unique")
    earlier = {unit.id: cycle for unit in units if restore is not None and (cycle := restore(unit)) is not None}
    unit_lock = Lock()

    def invoke(unit: U) -> ReviewCycle[T]:
        started = perf_counter()
        try:
            with model_call_scope(unit_id=unit.id):
                cycle = execute(unit)
        except Exception as exc:
            cycle = ReviewCycle(findings=[], errors=1, failure_reason=exception_reason(exc))
        if unit.id in earlier:
            cycle = replace(cycle, findings=[*earlier[unit.id].findings, *cycle.findings])
        if on_unit is not None:
            with unit_lock:
                on_unit(unit, cycle, round(perf_counter() - started, 3))
        return cycle

    open_units = [unit for unit in units if unit.id not in earlier or not earlier[unit.id].clean]
    if concurrency > 1 and len(open_units) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            executed = dict(zip((unit.id for unit in open_units), pool.map(invoke, open_units), strict=True))
    else:
        executed = {unit.id: invoke(unit) for unit in open_units}
    results = [executed[unit.id] if unit.id in executed else earlier[unit.id] for unit in units]

    for result in results:
        accumulator.add(result.findings)
    failures = tuple(
        ReviewUnitFailure(
            index=index,
            total=len(units),
            paths=unit.paths,
            reason=result.failure_reason or result.grounding.failure_reason or "review unit failed",
        )
        for index, (unit, result) in enumerate(zip(units, results, strict=True), 1)
        if not result.clean
    )
    incomplete = tuple(dict.fromkeys(item for result in results for item in result.incomplete))
    errors = sum(result.errors or int(not result.clean) for result in results)
    grounding = merge_grounding_coverage(tuple(result.grounding for result in results))
    return ReviewOutcome(
        findings=tuple(accumulator.findings),
        failures=failures,
        incomplete=incomplete,
        errors=errors,
        failure_reason=grounding.failure_reason,
        grounding=grounding,
    )
