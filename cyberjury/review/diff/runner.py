"""Run diff batches through one target-neutral review cycle contract."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from cyberjury.finding import Finding
from cyberjury.review.diff.model import DiffUnit, diff_units
from cyberjury.review.engine import (
    FindingAccumulator,
    PendingWorkRecord,
    ReviewCycle,
    ReviewOutcome,
    ReviewSchedule,
    run_review_units,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def _path_key(path: str) -> str:
    normalized = path.removeprefix("./")
    return normalized[2:] if normalized[:2] in ("a/", "b/") else normalized


def _known_for_unit(findings: list[Finding], unit: DiffUnit) -> list[Finding]:
    paths = {_path_key(path) for path in unit.paths}
    return [
        finding
        for finding in findings
        if _path_key(finding.change_anchor.file if finding.change_anchor is not None else finding.file) in paths
    ]


def run_batches(
    diff: str,
    execute: Callable[[int, DiffUnit, list[Finding]], ReviewCycle[Finding]],
    *,
    execute_pending: (
        Callable[[int, DiffUnit, list[Finding], tuple[PendingWorkRecord, ...]], ReviewCycle[Finding]] | None
    ) = None,
    plan: ReviewSchedule,
    accumulator: FindingAccumulator[Finding],
    prepare: Callable[[str], list[DiffUnit]] | None = None,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency,
    on_batch: Callable[[int, int, float], None] | None = None,
) -> ReviewOutcome[Finding]:
    """Execute every diff batch and preserve all incomplete batch evidence."""
    units = diff_units(diff) if prepare is None else prepare(diff)
    completed = 0
    progress_lock = Lock()

    def execute_unit(round_no: int, unit: DiffUnit, known: list[Finding]) -> ReviewCycle[Finding]:
        return execute(round_no, unit, _known_for_unit(known, unit))

    def execute_unit_pending(
        round_no: int,
        unit: DiffUnit,
        known: list[Finding],
        pending: tuple[PendingWorkRecord, ...],
    ) -> ReviewCycle[Finding]:
        if execute_pending is None:
            raise AssertionError("pending execution adapter requires a callback")
        return execute_pending(round_no, unit, _known_for_unit(known, unit), pending)

    def report_unit(_unit: DiffUnit, seconds: float) -> None:
        nonlocal completed
        if on_batch is None:
            return
        with progress_lock:
            completed += 1
            on_batch(completed, len(units), seconds)

    outcome = run_review_units(
        units,
        plan=plan,
        execute=execute_unit,
        execute_pending=execute_unit_pending if execute_pending is not None else None,
        accumulator=accumulator,
        failure_for=lambda _index, _total, unit, reason: ReviewUnitFailure(
            index=unit.index,
            total=unit.total,
            paths=unit.paths,
            reason=reason,
        ),
        concurrency=concurrency,
        on_unit=report_unit,
    )
    return outcome
