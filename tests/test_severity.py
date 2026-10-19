"""Severity ranking accepts canonical levels."""

import pytest

from cyberjury.severity import index


def test_index_ranks_canonical_levels_and_rejects_free_text():
    assert index("CRITICAL") == 0
    assert index("LOW") == 3
    with pytest.raises(KeyError):
        index("critical risk")
