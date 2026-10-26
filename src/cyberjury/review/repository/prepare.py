"""Prepare a Repository Review: bounded units over every readable production source file."""

from __future__ import annotations

from cyberjury.review.prepare import PreparedReview, ReviewPlan, SharedGrounding, prepare_review
from cyberjury.review.recorder import Recorder
from cyberjury.review.repository.context import Unit, ground_repository_unit
from cyberjury.review.repository.model import build_units, repository_unit_plan_record
from cyberjury.sources.snapshot import SourceSnapshot


def plan_repository_units(shared: SharedGrounding) -> ReviewPlan[Unit]:
    """Cover every readable production source file and record the files that cannot be reviewed."""
    review_files = shared.selection.review_files
    units = build_units(shared.root, review_files, shared.facts.relationships.definitions)
    return ReviewPlan(
        units=units,
        records=tuple(repository_unit_plan_record(unit) for unit in units),
        expected_owned_paths=review_files,
        skipped_files=shared.selection.skipped_files,
    )


def prepare_repository_review(snapshot: SourceSnapshot, *, recorder: Recorder | None = None) -> PreparedReview[Unit]:
    """Extract facts, plan bounded units, and ground every unit of one captured repository source."""
    return prepare_review(snapshot, plan=plan_repository_units, ground=ground_repository_unit, recorder=recorder)
