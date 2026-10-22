"""Prepare a Diff Review over the source snapshot of its head revision."""

from __future__ import annotations

from cyberjury.review.detection import detection_for
from cyberjury.review.diff.context import ground_diff_unit, plan_diff_units
from cyberjury.review.diff.model import DiffUnit, has_diff_hunk, strip_unreviewable_files
from cyberjury.review.prepare import PreparedReview, prepare_review
from cyberjury.sources.snapshot import SourceSnapshot


def prepare_diff_review(diff: str, snapshot: SourceSnapshot) -> PreparedReview[DiffUnit]:
    """Plan and ground the reviewable part of one diff against the snapshot of its head source."""
    review_diff, skipped = strip_unreviewable_files(diff, detection_for(snapshot.root, snapshot.files))
    if review_diff.strip() and not has_diff_hunk(review_diff):
        raise ValueError("diff review input is nonempty but contains no unified diff hunk")
    return prepare_review(
        snapshot,
        plan=lambda shared: plan_diff_units(review_diff, shared, skipped),
        ground=ground_diff_unit,
    )
