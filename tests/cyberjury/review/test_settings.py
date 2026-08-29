"""Central settings stay immutable and reject invalid relationships."""

from dataclasses import FrozenInstanceError, replace
from math import inf, nan

import pytest

from cyberjury.review.settings import DiffReviewSettings, RepositoryReviewSettings, ReviewExecutionSettings


def test_review_settings_are_immutable_but_replaceable_for_experiments():
    """An experiment replaces a complete settings value without mutating a live run."""
    baseline = DiffReviewSettings()

    with pytest.raises(FrozenInstanceError):
        baseline.target_patch_chars_per_unit = 1

    changed = replace(baseline, target_patch_chars_per_unit=1)
    assert changed.target_patch_chars_per_unit == 1
    assert baseline.target_patch_chars_per_unit == 60_000


def test_review_settings_reject_nonpositive_values():
    """A zero review bound cannot silently disable one part of a review."""
    with pytest.raises(ValueError, match="must be positive"):
        DiffReviewSettings(max_related_context_fraction=0)


def test_diff_settings_reject_an_invalid_fraction():
    """Related context cannot consume more than the complete prompt budget."""
    with pytest.raises(ValueError, match="cannot exceed 1"):
        DiffReviewSettings(max_related_context_fraction=1.1)


def test_repository_settings_reject_an_overlap_without_forward_progress():
    """Hard split overlap must leave each source window able to advance."""
    with pytest.raises(ValueError, match="must be smaller"):
        RepositoryReviewSettings(max_source_chars_per_unit=2_000, hard_split_overlap_chars=2_000)


@pytest.mark.parametrize("value", [True, 1.5])
def test_integer_review_settings_reject_non_integer_values(value):
    with pytest.raises(ValueError, match="positive integers"):
        ReviewExecutionSettings(default_adversarial_rounds=value)


@pytest.mark.parametrize("value", [nan, inf])
def test_float_review_settings_reject_nonfinite_values(value):
    with pytest.raises(ValueError, match="positive and finite"):
        DiffReviewSettings(max_related_context_fraction=value)
