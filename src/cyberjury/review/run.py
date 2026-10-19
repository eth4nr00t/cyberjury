"""Review prepared units, group their union into issues, and build the result artifacts.

With a work directory, each completed unit and issue link decision is saved as soon as it
finishes, so a resume, even after a crash, repeats only open work.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cyberjury.review.checkpoint import CheckpointStore
from cyberjury.review.context import GroundingCoverage
from cyberjury.review.engine import ReviewCycle, ReviewOutcome, extend_review_outcome, run_review_units
from cyberjury.review.finder import GroundedUnit, ReviewTarget, UnitFinder
from cyberjury.review.finding import Finding
from cyberjury.review.issues import IssueLinks, group_issues, link_issues
from cyberjury.review.prepare import SharedGrounding
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact, SkippedFile, findings_artifact
from cyberjury.review.seats import ReviewSeats
from cyberjury.review.union import finding_accumulator

type Progress = Callable[[int, int, float], None]

_UNIT_SCHEMA = "cyberjury.unit-review/v1"
_ISSUE_LINK_SCHEMA = "cyberjury.issue-link-decision/v1"


class ReviewWork[U](Protocol):
    """The grounded units a run reviews, their shared grounding, and the files kept out of review."""

    @property
    def shared(self) -> SharedGrounding:
        """Return the grounding every unit shares."""
        ...

    @property
    def units(self) -> tuple[U, ...]:
        """Return the grounded units in plan order."""
        ...

    @property
    def skipped_files(self) -> tuple[SkippedFile, ...]:
        """Return the target files not sent to model review."""
        ...


@dataclass(frozen=True, kw_only=True)
class ReviewRun:
    """One review result for the caller to bind and report."""

    outcome: ReviewOutcome[Finding]
    findings: FindingsArtifact
    outcome_artifact: OutcomeArtifact
    issue_link_errors: tuple[str, ...] = ()


def _unit_cycle(value: object) -> ReviewCycle[Finding]:
    if not isinstance(value, dict) or set(value) != {"clean", "findings"}:
        raise ValueError("unit review record fields are invalid")
    if not isinstance(value["clean"], bool) or not isinstance(value["findings"], list):
        raise ValueError("unit review record values are invalid")
    return ReviewCycle(
        findings=[Finding.from_dict(item) for item in value["findings"]],
        errors=int(not value["clean"]),
    )


def run_review[U: GroundedUnit](
    prepared: ReviewWork[U],
    *,
    target: ReviewTarget[U],
    seats: ReviewSeats,
    concurrency: int,
    work: Path | None = None,
    on_unit: Progress | None = None,
) -> ReviewRun:
    """Review every open unit once, group the union into issues, and build the result.

    Issues group the findings without removing any. The issue link judgment runs only
    when the review has an issue judge. A failed link judgment leaves its findings in separate
    issues and is reported, not counted as an incomplete review.
    """
    shared = prepared.shared
    units = list(prepared.units)
    if not units and target.covers_all_files:
        raise ValueError(f"no readable production source files found under {shared.root}")
    unit_store = CheckpointStore(work / "units", _UNIT_SCHEMA) if work is not None else None
    earlier = {unit.id: unit_store.restore(unit.id, _unit_cycle) for unit in units} if unit_store else {}
    finder = UnitFinder(target, provider=seats.finder, model=seats.finder_model, label=seats.finder_label)
    open_count = sum(1 for unit in units if earlier.get(unit.id) is None or not earlier[unit.id].clean)
    done = 0

    def record(unit: U, cycle: ReviewCycle[Finding], seconds: float) -> None:
        nonlocal done
        if unit_store is not None:
            unit_store.save(
                unit.id,
                {"clean": cycle.clean, "findings": [finding.to_dict() for finding in cycle.findings]},
            )
        done += 1
        if on_unit is not None:
            on_unit(done, open_count, seconds)

    outcome: ReviewOutcome[Finding] = (
        run_review_units(
            units,
            execute=finder.review_unit,
            accumulator=finding_accumulator(),
            concurrency=concurrency,
            restore=lambda unit: earlier.get(unit.id),
            on_unit=record,
        )
        if units
        else ReviewOutcome(findings=())
    )
    findings = list(outcome.findings)
    issue_links = (
        link_issues(
            findings,
            seats.issue_judge,
            str(shared.root),
            checkpoint=CheckpointStore(work / "issue-links", _ISSUE_LINK_SCHEMA) if work is not None else None,
            concurrency=concurrency,
        )
        if seats.issue_judge is not None
        else IssueLinks()
    )
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
    return ReviewRun(
        issue_link_errors=issue_links.errors,
        outcome=outcome,
        findings=machine_findings,
        outcome_artifact=OutcomeArtifact.create(
            target=target.kind,
            source_revision=shared.snapshot.snapshot_id,
            findings=machine_findings,
            outcome=outcome,
            skipped_files=prepared.skipped_files,
        ),
    )
