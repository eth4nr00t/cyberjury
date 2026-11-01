"""Severity ranking accepts canonical levels."""

import pytest

from cyberjury.severity import severity_rank


def test_index_ranks_canonical_levels_and_rejects_free_text():
    """CRITICAL ranks 0 and LOW ranks 3, while "critical risk" raises KeyError."""
    assert severity_rank("CRITICAL") == 0
    assert severity_rank("LOW") == 3
    with pytest.raises(KeyError):
        severity_rank("critical risk")
