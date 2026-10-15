"""Severity ranking accepts canonical levels and damps grade jitter."""

import pytest

from cyberjury.severity import index, median


def test_index_ranks_canonical_levels_and_rejects_free_text():
    assert index("CRITICAL") == 0
    assert index("LOW") == 3
    with pytest.raises(KeyError):
        index("critical risk")


def test_median_damps_jitter_to_the_middle_grade():
    assert median(["LOW", "HIGH", "MEDIUM"]) == "MEDIUM"
    assert median(["CRITICAL", "CRITICAL", "MEDIUM"]) == "CRITICAL"
    assert median([]) == "MEDIUM"


def test_median_of_one_vote_keeps_the_model_grade():
    assert median(["LOW"]) == "LOW"
    assert median(["CRITICAL"]) == "CRITICAL"


def test_median_of_an_even_count_takes_the_upper_middle():
    assert median(["MEDIUM", "HIGH"]) == "HIGH"
    assert median(["LOW", "MEDIUM"]) == "MEDIUM"
