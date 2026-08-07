"""Severity stabilization.

the median damps grade jitter to a stable middle level, and the level names are read
from free text the same way everywhere.
"""

from cyberjury.review.repository.severity import median, normalize


def test_normalize_reads_the_level_from_free_text():
    """Exercise the normalize reads the level from free text case."""
    assert normalize("HIGH") == "HIGH"
    assert normalize("critical risk") == "CRITICAL"
    assert normalize("") == "MEDIUM"
    assert normalize("nonsense") == "MEDIUM"


def test_median_damps_jitter_to_the_middle_grade():
    """Exercise the median damps jitter to the middle grade case."""
    assert median(["LOW", "HIGH", "MEDIUM"]) == "MEDIUM"
    assert median(["CRITICAL", "CRITICAL", "MEDIUM"]) == "CRITICAL"
    assert median([]) == "MEDIUM"


def test_median_of_one_vote_keeps_the_model_grade():
    """Exercise the median of one vote keeps the model grade case."""
    assert median(["LOW"]) == "LOW"
    assert median(["CRITICAL"]) == "CRITICAL"


def test_median_of_an_even_count_takes_the_upper_middle():
    """Exercise the median of an even count takes the upper middle case."""
    assert median(["MEDIUM", "HIGH"]) == "HIGH"
    assert median(["LOW", "MEDIUM"]) == "MEDIUM"
