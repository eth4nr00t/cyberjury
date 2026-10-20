"""Prepare one review target: facts, navigation, bounded units, and their receipts.

Diff Review and Repository Review share this stage. A target supplies only how it plans
its units and how it grounds one unit.
"""

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
from cyberjury.review.result import SkippedFile
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
) -> PreparedReview[U]:
    """Extract facts, build navigation, plan and ground every unit, and bind their receipts."""
    detection = detection_for(snapshot.root, snapshot.files)
    selection = select_files(snapshot.root, snapshot.files, detection)
    facts, receipt = extract_facts(snapshot, selection, detection)
    shared = SharedGrounding(
        snapshot=snapshot,
        detection=detection,
        selection=selection,
        facts=facts,
        navigator=SourceNavigator.from_facts(
            snapshot.root,
            source_files=selection.navigation_files,
            import_files=facts.import_files,
            relationship_evidence=facts.relationships,
            documentation_files=selection.documentation_files,
            dependency_files=selection.dependency_files,
        ),
    )
    planned = plan(shared)
    unit_plan = UnitPlanReceipt.create(
        facts=receipt,
        units=tuple(planned.records),
        expected_owned_paths=planned.expected_owned_paths,
    )
    units = tuple(replace(unit, id=record.id) for unit, record in zip(planned.units, unit_plan.units, strict=True))
    units = tuple(replace(unit, grounding=ground(unit, shared)) for unit in units)
    return PreparedReview(
        shared=shared,
        facts=receipt,
        unit_plan=unit_plan,
        grounding=GroundingReceipt.create(unit_plan=unit_plan, contexts=tuple(unit.grounding for unit in units)),
        units=units,
        skipped_files=planned.skipped_files,
    )
