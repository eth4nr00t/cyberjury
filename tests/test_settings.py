"""Central settings stay immutable and reject invalid relationships."""

from dataclasses import FrozenInstanceError, replace

import pytest

from cyberjury.providers.settings import ProviderSettings
from cyberjury.review.settings import DiffReviewSettings, RepositoryReviewSettings


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


def test_provider_settings_reject_a_backoff_range_in_reverse():
    """The initial retry delay must respect the operator's maximum delay."""
    with pytest.raises(ValueError, match="cannot exceed"):
        ProviderSettings(retry_initial_delay_seconds=2, retry_max_delay_seconds=1)
