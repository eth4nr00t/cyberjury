"""Prepare one review target: facts, navigation, bounded units, and their receipts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from cyberjury.review.context import GroundingContext
from cyberjury.review.detection import Detection
from cyberjury.review.engine import ReviewUnit
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.recorder import Progress, Recorder
from cyberjury.review.result import SkippedFile, SkippedFiles
from cyberjury.review.selection import FileSelection, select_files
from cyberjury.review.syntax.facts import extract_syntax_facts, syntax_backend_id
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord
from cyberjury.sources.snapshot import SourceSnapshot


@dataclass(frozen=True, kw_only=True)
class SharedGrounding:
    """Facts derived context every unit of one review grounds against."""

    snapshot: SourceSnapshot
    detection: Detection
    selection: FileSelection
    facts: Facts
    navigator: SourceNavigator | None

    @property
    def root(self) -> Path:
        """Return the private source root every unit reads."""
        return self.snapshot.root


@dataclass(frozen=True, kw_only=True)
class ReviewPlan[U: ReviewUnit]:
    """One target's planned units, their plan records, and the files it does not review."""

    units: Sequence[U]
    records: Sequence[UnitPlanRecord]
    skipped_files: tuple[SkippedFile, ...] = ()


@dataclass(frozen=True, kw_only=True)
class PreparedReview[U: ReviewUnit]:
    """The grounded units of one review and the grounding they share."""

    shared: SharedGrounding
    units: tuple[U, ...]


def extract_facts(
    snapshot: SourceSnapshot, selection: FileSelection, *, progress: Progress
) -> tuple[Facts, FactsReceipt]:
    """Extract syntax facts with loud failure and bind them to the backend identity."""
    try:
        facts = extract_syntax_facts(snapshot.root, selection.review_files, progress=progress)
    except Exception as exc:
        raise BackendUnavailable(f"facts extraction failed, so this review has no grounding: {exc}") from exc
    return facts, FactsReceipt.create(backend_id=syntax_backend_id(), facts=facts)


def prepare_review[U: ReviewUnit](
    snapshot: SourceSnapshot,
    *,
    plan: Callable[[SharedGrounding], ReviewPlan[U]],
    ground: Callable[[U, SharedGrounding], GroundingContext],
    detection: Detection,
    has_reviewable_source: bool = True,
    recorder: Recorder,
) -> PreparedReview[U]:
    """Extract facts and navigation when the target has reviewable source, then plan and ground, one stage each."""
    with recorder.stage("facts") as measure:
        selection = select_files(snapshot.root, snapshot.files, detection)
        if has_reviewable_source:
            facts, receipt = extract_facts(snapshot, selection, progress=measure.progress)
            navigator = SourceNavigator.from_facts(
                snapshot.root,
                source_files=selection.navigation_files,
                relationship_evidence=facts.relationships,
                documentation_files=selection.documentation_files,
                dependency_files=selection.dependency_files,
            )
        else:
            facts = Facts()
            receipt = FactsReceipt.create(backend_id=syntax_backend_id(), facts=facts)
            navigator = None
        measure.metrics.update(limitations=len(facts.limitations))
        measure.bind(receipt)
    shared = SharedGrounding(
        snapshot=snapshot,
        detection=detection,
        selection=selection,
        facts=facts,
        navigator=navigator,
    )
    with recorder.stage("plan") as measure:
        planned = plan(shared)
        unit_plan = UnitPlanReceipt.create(facts=receipt, units=tuple(planned.records))
        measure.metrics.update(items=len(unit_plan.units), skipped_files=len(planned.skipped_files))
        measure.bind(unit_plan)
        measure.bind(SkippedFiles(planned.skipped_files))
    with recorder.stage("grounding") as measure:
        units = tuple(replace(unit, id=record.id) for unit, record in zip(planned.units, unit_plan.units, strict=True))
        units = tuple(replace(unit, grounding=ground(unit, shared)) for unit in units)
        grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=tuple(unit.grounding for unit in units))
        measure.metrics.update(items=len(units))
        measure.bind(grounding)
    return PreparedReview(shared=shared, units=units)
