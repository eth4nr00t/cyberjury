"""Review prepared units, group their union into issues, and build the result artifacts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cyberjury.record import Record, RecordError, error_message, utc_timestamp
from cyberjury.review.engine import ReviewCycle, ReviewOutcome, ReviewUnit, run_review_units
from cyberjury.review.finder import ReviewTarget, UnitFinder
from cyberjury.review.finding import Finding
from cyberjury.review.issues import IssueLinks, group_issues, link_issues
from cyberjury.review.items import ItemStore
from cyberjury.review.prepare import PreparedReview
from cyberjury.review.recorder import Recorder
from cyberjury.review.result import FindingsArtifact, findings_artifact
from cyberjury.review.seats import ReviewSeats

_UNIT_FINDINGS_SCHEMA = "cyberjury.unit-findings/v1"


class NoReviewableSourceError(ValueError):
    """The target holds no source file a review can read."""


@dataclass(frozen=True, kw_only=True)
class ReviewRun:
    """One review result for the caller to report."""

    outcome: ReviewOutcome
    findings: FindingsArtifact


def _unit_cycle(record: Record, payload: object) -> ReviewCycle:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema", "findings"}
        or payload["schema"] != _UNIT_FINDINGS_SCHEMA
    ):
        raise ValueError("unit findings payload is invalid")
    if not isinstance(payload["findings"], list):
        raise ValueError("unit findings payload findings must be a list")
    return ReviewCycle(
        findings=[Finding.from_dict(item) for item in payload["findings"]],
        failure_reason=record.error.message if record.error is not None else "",
    )


def _incomplete_reason(outcome: ReviewOutcome) -> str:
    failure = outcome.failures[0]
    more = f" and {len(outcome.failures) - 1} more" if len(outcome.failures) > 1 else ""
    return f"review unit {failure.index}/{failure.total} failed for {', '.join(failure.paths)}{more}: {failure.reason}"


def _unit_item_writer[U: ReviewUnit](
    recorder: Recorder, unit_store: ItemStore
) -> Callable[[U, ReviewCycle, float], None]:
    def write(unit: U, cycle: ReviewCycle, seconds: float) -> None:
        item = Record(
            id=f"review/{unit.id}",
            status="ok" if cycle.clean else "failed",
            started_at=utc_timestamp(datetime.now(UTC) - timedelta(seconds=seconds)),
            duration_seconds=seconds,
            metrics={
                "findings": len(cycle.findings),
                "unlocated": len(cycle.incomplete),
                **recorder.unit_usage(unit.id),
            },
            attributes={"paths": ", ".join(unit.paths)},
            artifacts=(unit_store.artifact(unit.id),),
            error=None
            if cycle.clean
            else RecordError(
                code="model", message=error_message(cycle.failure_reason or "unit review did not complete")
            ),
        )
        unit_store.save(
            item, {"schema": _UNIT_FINDINGS_SCHEMA, "findings": [finding.to_dict() for finding in cycle.findings]}
        )
        recorder.item(item)

    return write


def _review_units[U: ReviewUnit](
    units: list[U],
    *,
    target: ReviewTarget[U],
    seats: ReviewSeats,
    concurrency: int,
    root: Path,
    review: Path,
    recorder: Recorder,
) -> ReviewOutcome:
    with recorder.stage("review", usage=True) as measure:
        if not units and target.covers_all_files:
            raise NoReviewableSourceError(f"no readable production source files found in {root.name}")
        unit_store = ItemStore(review, "review", payload="findings")
        earlier = {unit.id: unit_store.restore(unit.id, _unit_cycle) for unit in units}
        finder = UnitFinder(target, provider=seats.finder, model=seats.finder_model)
        outcome: ReviewOutcome = (
            run_review_units(
                units,
                execute=finder.review_unit,
                concurrency=concurrency,
                restore=lambda unit: earlier.get(unit.id),
                on_unit=_unit_item_writer(recorder, unit_store),
            )
            if units
            else ReviewOutcome(findings=())
        )
        measure.metrics.update(
            items=len(units),
            restored=sum(1 for cycle in earlier.values() if cycle is not None and cycle.clean),
            failed=len(outcome.failures),
            unlocated=len(outcome.incomplete),
            findings=len(outcome.findings),
        )
        if not outcome.complete:
            measure.incomplete(_incomplete_reason(outcome))
    return outcome


def _link_findings(
    findings: list[Finding],
    *,
    seats: ReviewSeats,
    concurrency: int,
    root: Path,
    review: Path,
    recorder: Recorder,
) -> IssueLinks:
    with recorder.stage("link", usage=True) as measure:
        issue_links = link_issues(
            findings,
            seats.issue_judge,
            str(root),
            store=ItemStore(review, "link"),
            concurrency=concurrency,
            recorder=recorder,
        )
        measure.metrics.update(
            items=issue_links.judged + issue_links.restored + len(issue_links.errors),
            restored=issue_links.restored,
            failed=len(issue_links.errors),
        )
        if issue_links.errors:
            measure.incomplete(issue_links.errors[0])
    return issue_links


def run_review[U: ReviewUnit](
    prepared: PreparedReview[U],
    *,
    target: ReviewTarget[U],
    seats: ReviewSeats,
    concurrency: int,
    review: Path,
    recorder: Recorder,
) -> ReviewRun:
    """Review every open unit once, group the union into issues, and build the result, one stage each."""
    shared = prepared.shared
    outcome = _review_units(
        list(prepared.units),
        target=target,
        seats=seats,
        concurrency=concurrency,
        root=shared.root,
        review=review,
        recorder=recorder,
    )
    findings = list(outcome.findings)
    issue_links = _link_findings(
        findings, seats=seats, concurrency=concurrency, root=shared.root, review=review, recorder=recorder
    )
    with recorder.stage("result") as measure:
        issues = group_issues(findings, issue_links.links)
        machine_findings = findings_artifact(findings, issues)
        measure.metrics.update(
            findings=len(machine_findings.findings),
            issues=len(machine_findings.issues),
            **{severity.lower(): count for severity, count in machine_findings.summary.items()},
        )
        measure.bind(machine_findings)
    return ReviewRun(outcome=outcome, findings=machine_findings)
