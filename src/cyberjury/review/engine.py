"""Schedule review units, fold their findings into one union, and summarize the outcome."""

from __future__ import annotations

from collections.abc import Callable
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
from cyberjury.review.finding import Finding
from cyberjury.review.navigation import SourceNavigationSession
from cyberjury.review.union import FindingAccumulator


class ReviewUnit(Protocol):
    """One planned review unit of any target: its plan id, the paths it reviews, and its initial grounding."""

    @property
    def id(self) -> str:
        """The content bound unit plan id."""

    @property
    def paths(self) -> tuple[str, ...]:
        """The source paths the unit reviews."""

    @property
    def grounding(self) -> GroundingContext | None:
        """The unit's initial evidence envelope, once grounded."""


@dataclass(frozen=True, kw_only=True)
class ReviewCycle:
    """One target adapter result consumed by the shared scheduler."""

    findings: list[Finding]
    incomplete: list[Finding] = field(default_factory=list)
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()

    @property
    def clean(self) -> bool:
        """Allow judgment with visible limitations while rejecting unavailable evidence."""
        return not self.incomplete and not self.failure_reason and self.grounding.complete


@dataclass(frozen=True, kw_only=True)
class ReviewOutcome:
    """The finding union of one review, its failed units, and the findings without a valid location."""

    findings: tuple[Finding, ...]
    failures: tuple[ReviewUnitFailure, ...] = ()
    incomplete: tuple[Finding, ...] = ()

    @property
    def complete(self) -> bool:
        """Require every unit to finish clean."""
        return not self.failures


def run_grounded_judgment(
    context: GroundingContext,
    *,
    run_judgment: Callable[[SourceNavigationSession | None], EvidenceJudgment],
) -> ReviewCycle:
    """Run one grounded judgment per unit and keep candidates produced before a failure."""
    navigation = context.navigator.session() if context.navigator is not None else None
    try:
        judgment = run_judgment(navigation)
    except Exception as exc:
        judgment = EvidenceJudgment(findings=[], failure_reason=exception_reason(exc))
    final = with_source_evidence(context, judgment.source_evidence)
    return ReviewCycle(
        findings=judgment.findings,
        failure_reason=judgment.failure_reason,
        grounding=merge_grounding_coverage((final.coverage, judgment.grounding)),
        source_evidence=final.source_evidence,
    )


def run_review_units[U: ReviewUnit](
    units: list[U],
    *,
    execute: Callable[[U], ReviewCycle],
    concurrency: int,
    restore: Callable[[U], ReviewCycle | None],
    on_unit: Callable[[U, ReviewCycle, float], None],
) -> ReviewOutcome:
    """Review every open unit once, continue past failed units, and record each failure."""
    earlier = {unit.id: cycle for unit in units if (cycle := restore(unit)) is not None}
    unit_lock = Lock()

    def invoke(unit: U) -> ReviewCycle:
        started = perf_counter()
        try:
            with model_call_scope(unit_id=unit.id):
                cycle = execute(unit)
        except Exception as exc:
            cycle = ReviewCycle(findings=[], failure_reason=exception_reason(exc))
        if unit.id in earlier:
            cycle = replace(cycle, findings=[*earlier[unit.id].findings, *cycle.findings])
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

    accumulator = FindingAccumulator()
    for result in results:
        accumulator.add(result.findings)
    return ReviewOutcome(
        findings=tuple(accumulator.findings),
        failures=tuple(
            ReviewUnitFailure(
                index=index,
                total=len(units),
                paths=unit.paths,
                reason=result.failure_reason or result.grounding.failure_reason,
            )
            for index, (unit, result) in enumerate(zip(units, results, strict=True), 1)
            if not result.clean
        ),
        incomplete=tuple(dict.fromkeys(item for result in results for item in result.incomplete)),
    )
