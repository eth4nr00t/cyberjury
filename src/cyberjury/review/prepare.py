"""Prepare one review target: facts, navigation, bounded units, and their receipts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from cyberjury.review.context import GroundingContext
from cyberjury.review.detection import Detection, detection_for
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.recorder import Recorder
from cyberjury.review.result import SkippedFile, SkippedFiles
from cyberjury.review.selection import FileSelection, select_files
from cyberjury.review.syntax.facts import extract_syntax_facts, syntax_backend_id
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord
from cyberjury.sources.snapshot import SourceSnapshot


class PlannedUnit(Protocol):
    """A target unit the shared stage can bind to its plan id and initial grounding."""

    id: str
    grounding: GroundingContext | None


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
class ReviewPlan[U: PlannedUnit]:
    """One target's planned units, their plan records, and the paths they must own."""

    units: Sequence[U]
    records: Sequence[UnitPlanRecord]
    expected_owned_paths: tuple[str, ...]
    skipped_files: tuple[SkippedFile, ...] = ()


@dataclass(frozen=True, kw_only=True)
class PreparedReview[U: PlannedUnit]:
    """Grounded units and the receipts bound before any model work."""

    shared: SharedGrounding
    facts: FactsReceipt
    unit_plan: UnitPlanReceipt
    grounding: GroundingReceipt
    units: tuple[U, ...]
    skipped_files: tuple[SkippedFile, ...]


def extract_facts(
    snapshot: SourceSnapshot, selection: FileSelection, detection: Detection
) -> tuple[Facts, FactsReceipt]:
    """Extract syntax facts with loud failure and bind them to the backend identity."""
    try:
        facts = extract_syntax_facts(snapshot.root, snapshot.files, selection.navigation_files, detection)
    except Exception as exc:
        raise BackendUnavailable(f"facts extraction failed, so this review has no grounding: {exc}") from exc
    return facts, FactsReceipt.create(backend_id=syntax_backend_id(), facts=facts)


def prepare_review[U: PlannedUnit](
    snapshot: SourceSnapshot,
    *,
    plan: Callable[[SharedGrounding], ReviewPlan[U]],
    ground: Callable[[U, SharedGrounding], GroundingContext],
    detection: Detection | None = None,
    has_reviewable_source: bool = True,
    recorder: Recorder | None = None,
) -> PreparedReview[U]:
    """Extract facts and navigation when the target has reviewable source, then plan and ground, one stage each.

    A caller that already detected the snapshot's languages passes that detection instead of detecting again.
    """
    recorder = recorder or Recorder()
    with recorder.stage("facts") as measure:
        if detection is None:
            detection = detection_for(snapshot.root, snapshot.files)
        selection = select_files(snapshot.root, snapshot.files, detection)
        if has_reviewable_source:
            facts, receipt = extract_facts(snapshot, selection, detection)
            navigator = SourceNavigator.from_facts(
                snapshot.root,
                source_files=selection.navigation_files,
                import_files=facts.import_files,
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
        unit_plan = UnitPlanReceipt.create(
            facts=receipt,
            units=tuple(planned.records),
            expected_owned_paths=planned.expected_owned_paths,
        )
        measure.metrics.update(items=len(unit_plan.units), skipped_files=len(planned.skipped_files))
        measure.bind(unit_plan)
        measure.bind(SkippedFiles(planned.skipped_files))
    with recorder.stage("grounding") as measure:
        units = tuple(replace(unit, id=record.id) for unit, record in zip(planned.units, unit_plan.units, strict=True))
        units = tuple(replace(unit, grounding=ground(unit, shared)) for unit in units)
        grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=tuple(unit.grounding for unit in units))
        measure.metrics.update(items=len(units))
        measure.bind(grounding)
    return PreparedReview(
        shared=shared,
        facts=receipt,
        unit_plan=unit_plan,
        grounding=grounding,
        units=units,
        skipped_files=planned.skipped_files,
    )
