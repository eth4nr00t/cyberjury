"""Review prepared units, group their union into issues, and build the result artifacts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from cyberjury.record import Record, RecordError, error_message, utc_timestamp
from cyberjury.review.context import GroundingCoverage
from cyberjury.review.engine import ReviewCycle, ReviewOutcome, extend_review_outcome, run_review_units
from cyberjury.review.finder import GroundedUnit, ReviewTarget, UnitFinder
from cyberjury.review.finding import Finding
from cyberjury.review.issues import IssueLinks, group_issues, link_issues
from cyberjury.review.items import ItemStore
from cyberjury.review.prepare import SharedGrounding
from cyberjury.review.recorder import Recorder
from cyberjury.review.result import FindingsArtifact, findings_artifact
from cyberjury.review.seats import ReviewSeats
from cyberjury.review.union import finding_accumulator

_UNIT_FINDINGS_SCHEMA = "cyberjury.unit-findings/v1"


class NoReviewableSourceError(ValueError):
    """The target holds no source file a review can read."""


class ReviewWork[U](Protocol):
    """The grounded units a run reviews and their shared grounding."""

    @property
    def shared(self) -> SharedGrounding:
        """Return the grounding every unit shares."""
        ...

    @property
    def units(self) -> tuple[U, ...]:
        """Return the grounded units in plan order."""
        ...


@dataclass(frozen=True, kw_only=True)
class ReviewRun:
    """One review result for the caller to report."""

    outcome: ReviewOutcome[Finding]
    findings: FindingsArtifact


def _unit_cycle(record: Record, payload: object) -> ReviewCycle[Finding]:
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
        errors=int(record.status != "ok"),
    )


def _incomplete_reason(outcome: ReviewOutcome[Finding]) -> str:
    if outcome.failure_reason:
        return outcome.failure_reason
    if outcome.failures:
        failure = outcome.failures[0]
        more = f" and {len(outcome.failures) - 1} more" if len(outcome.failures) > 1 else ""
        return (
            f"review unit {failure.index}/{failure.total} failed for {', '.join(failure.paths)}{more}: {failure.reason}"
        )
    if outcome.incomplete:
        return f"{len(outcome.incomplete)} findings have no location inside the reviewed source"
    return "review is incomplete"


def _unit_item_writer[U: GroundedUnit](
    recorder: Recorder, unit_store: ItemStore | None
) -> Callable[[U, ReviewCycle[Finding], float], None]:
    def write(unit: U, cycle: ReviewCycle[Finding], seconds: float) -> None:
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
            artifacts=(unit_store.artifact(unit.id),) if unit_store is not None else (),
            error=None
            if cycle.clean
            else RecordError(
                code="model", message=error_message(cycle.failure_reason or "unit review did not complete")
            ),
        )
        if unit_store is not None:
            unit_store.save(
                item,
                {"schema": _UNIT_FINDINGS_SCHEMA, "findings": [finding.to_dict() for finding in cycle.findings]},
            )
        recorder.item(item)

    return write


def _review_units[U: GroundedUnit](
    units: list[U],
    *,
    target: ReviewTarget[U],
    seats: ReviewSeats,
    concurrency: int,
    root: Path,
    review: Path | None,
    recorder: Recorder,
) -> ReviewOutcome[Finding]:
    with recorder.stage("review", usage=True) as measure:
        if not units and target.covers_all_files:
            raise NoReviewableSourceError(f"no readable production source files found in {root.name}")
        unit_store = ItemStore(review, "review", payload="findings") if review is not None else None
        earlier = {unit.id: unit_store.restore(unit.id, _unit_cycle) for unit in units} if unit_store else {}
        finder = UnitFinder(target, provider=seats.finder, model=seats.finder_model, label=seats.finder_label)
        outcome: ReviewOutcome[Finding] = (
            run_review_units(
                units,
                execute=finder.review_unit,
                accumulator=finding_accumulator(),
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
    review: Path | None,
    recorder: Recorder,
) -> IssueLinks:
    if seats.issue_judge is None:
        recorder.skip("link", "no issue judge in a dry run")
        return IssueLinks()
    with recorder.stage("link", usage=True) as measure:
        issue_links = link_issues(
            findings,
            seats.issue_judge,
            str(root),
            store=ItemStore(review, "link") if review is not None else None,
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


def run_review[U: GroundedUnit](
    prepared: ReviewWork[U],
    *,
    target: ReviewTarget[U],
    seats: ReviewSeats,
    concurrency: int,
    review: Path | None = None,
    recorder: Recorder | None = None,
) -> ReviewRun:
    """Review every open unit once, group the union into issues, and build the result, one stage each."""
    recorder = recorder or Recorder()
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
        outcome = extend_review_outcome(
            outcome,
            findings=findings,
            grounding=(
                GroundingCoverage(limitations=tuple(item.identity for item in shared.facts.limitations))
                if target.covers_all_files
                else None
            ),
        )
        machine_findings = findings_artifact(outcome.findings, issues)
        measure.metrics.update(
            findings=len(machine_findings.findings),
            issues=len(machine_findings.issues),
            **{severity.lower(): count for severity, count in machine_findings.summary},
        )
        measure.bind(machine_findings)
    return ReviewRun(outcome=outcome, findings=machine_findings)
