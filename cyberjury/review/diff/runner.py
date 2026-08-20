"""Run diff batches through one target-neutral review cycle contract."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock

from cyberjury.finding import Finding
from cyberjury.review.diff.model import DiffUnit, diff_units
from cyberjury.review.engine import FindingAccumulator, ReviewCycle, ReviewOutcome, ReviewPlan, run_review_units
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS


def _path_key(path: str) -> str:
    normalized = path.removeprefix("./")
    return normalized[2:] if normalized[:2] in ("a/", "b/") else normalized


def _known_for_unit(findings: list[Finding], unit: DiffUnit) -> list[Finding]:
    paths = {_path_key(path) for path in unit.paths}
    return [finding for finding in findings if not finding.file or _path_key(finding.file) in paths]


def run_batches(
    diff: str,
    execute: Callable[[int, DiffUnit, list[Finding]], ReviewCycle[Finding]],
    *,
    plan: ReviewPlan,
    accumulator: FindingAccumulator[Finding],
    failures: list[ReviewUnitFailure] | None = None,
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
    if failures is not None:
        failures.extend(outcome.failures)
    return outcome
