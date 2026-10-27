"""Repository Review preparation: bounded units over every readable production source file."""

from __future__ import annotations

from cyberjury.review.detection import detection_for
from cyberjury.review.prepare import PreparedReview, ReviewPlan, SharedGrounding, prepare_review
from cyberjury.review.recorder import Recorder
from cyberjury.review.repository.context import ground_repository_unit
from cyberjury.review.repository.model import RepositoryUnit, build_units, repository_unit_plan_record
from cyberjury.sources.snapshot import SourceSnapshot


def plan_repository_units(shared: SharedGrounding) -> ReviewPlan[RepositoryUnit]:
    """Cover every readable production source file and record the files that cannot be reviewed."""
    units = build_units(shared.root, shared.selection.review_files, shared.facts.relationships.definitions)
    return ReviewPlan(
        units=units,
        records=tuple(repository_unit_plan_record(unit) for unit in units),
        skipped_files=shared.selection.skipped_files,
    )


def prepare_repository_review(snapshot: SourceSnapshot, *, recorder: Recorder) -> PreparedReview[RepositoryUnit]:
    """Extract facts, plan bounded units, and ground every unit of one captured repository source."""
    return prepare_review(
        snapshot,
        plan=plan_repository_units,
        ground=ground_repository_unit,
        detection=detection_for(snapshot.root, snapshot.files),
        recorder=recorder,
    )
