"""Severity stabilization normalizes free text and damps grade jitter."""

from cyberjury.severity import median, normalize


def test_normalize_reads_the_level_from_free_text():
    assert normalize("HIGH") == "HIGH"
    assert normalize("critical risk") == "CRITICAL"
    assert normalize("") == "MEDIUM"
    assert normalize("nonsense") == "MEDIUM"


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
