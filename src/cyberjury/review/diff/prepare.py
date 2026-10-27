"""Diff review preparation over the source snapshot of its head revision."""

from __future__ import annotations

from cyberjury.review.detection import detection_for
from cyberjury.review.diff.context import ground_diff_unit
from cyberjury.review.diff.model import (
    DiffUnit,
    diff_unit_plan_record,
    strip_unreviewable_files,
)
from cyberjury.review.diff.planning import build_diff_units
from cyberjury.review.prepare import PreparedReview, ReviewPlan, SharedGrounding, prepare_review
from cyberjury.review.recorder import Recorder
from cyberjury.review.result import SkippedFile
from cyberjury.sources.snapshot import SourceSnapshot


def plan_diff_units(diff: str, shared: SharedGrounding, skipped: tuple[SkippedFile, ...]) -> ReviewPlan[DiffUnit]:
    """Plan deterministic diff units that together own every reviewable changed path."""
    units = build_diff_units(
        diff,
        root=shared.root,
        definitions=shared.facts.relationships.definitions,
    )
    return ReviewPlan(
        units=units,
        records=tuple(diff_unit_plan_record(unit) for unit in units),
        skipped_files=skipped,
    )


def prepare_diff_review(diff: str, snapshot: SourceSnapshot, *, recorder: Recorder) -> PreparedReview[DiffUnit]:
    """Plan and ground the reviewable part of one diff against the snapshot of its head source."""
    detection = detection_for(snapshot.root, snapshot.files)
    review_diff, skipped = strip_unreviewable_files(diff, detection, root=snapshot.root)
    return prepare_review(
        snapshot,
        detection=detection,
        plan=lambda shared: plan_diff_units(review_diff, shared, skipped),
        ground=ground_diff_unit,
        has_reviewable_source=bool(review_diff.strip()),
        recorder=recorder,
    )
