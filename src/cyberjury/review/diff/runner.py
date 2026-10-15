"""Run diff batches through one target-neutral review cycle contract."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from cyberjury.finding import Finding
from cyberjury.review.diff.model import DiffUnit
from cyberjury.review.engine import FindingAccumulator, ReviewCycle, ReviewOutcome, run_review_units
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def run_batches(
    diff: str,
    execute: Callable[[DiffUnit], ReviewCycle[Finding]],
    *,
    accumulator: FindingAccumulator[Finding],
    prepare: Callable[[str], list[DiffUnit]],
    concurrency: int = DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency,
    on_batch: Callable[[int, int, float], None] | None = None,
) -> ReviewOutcome[Finding]:
    """Execute every diff batch and preserve all incomplete batch evidence."""
    units = prepare(diff)
    completed = 0
    progress_lock = Lock()

    def report_unit(_unit: DiffUnit, seconds: float) -> None:
        nonlocal completed
        if on_batch is None:
            return
        with progress_lock:
            completed += 1
            on_batch(completed, len(units), seconds)

    return run_review_units(
        units,
        execute=lambda unit, _known: execute(unit),
        accumulator=accumulator,
        unit_identity=lambda unit: unit.id or f"diff-unit-{unit.index}",
        failure_for=lambda _index, _total, unit, reason: ReviewUnitFailure(
            index=unit.index,
            total=unit.total,
            paths=unit.paths,
            reason=reason,
        ),
        concurrency=concurrency,
        on_unit=report_unit,
    )
