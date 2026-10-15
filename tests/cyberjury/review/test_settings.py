"""Central settings stay immutable and replaceable for experiments."""

from dataclasses import FrozenInstanceError, replace

import pytest

from cyberjury.review.settings import (
    DiffReviewSettings,
)


def test_review_settings_are_immutable_but_replaceable_for_experiments():
    """An experiment replaces a complete settings value without mutating a live run."""
    baseline = DiffReviewSettings()

    with pytest.raises(FrozenInstanceError):
        baseline.target_patch_chars_per_unit = 1

    changed = replace(baseline, target_patch_chars_per_unit=1)
    assert changed.target_patch_chars_per_unit == 1
    assert baseline.target_patch_chars_per_unit == 60_000
