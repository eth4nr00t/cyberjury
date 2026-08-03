"""Severity stabilization: the median damps grade jitter to a stable middle level, and
the level names are read from free text the same way everywhere."""

from cyberjury.review.repository.severity import median, normalize


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
    # severity is the model's, the median only converges repeats, it never overrides a grade
    assert median(["LOW"]) == "LOW"
    assert median(["CRITICAL"]) == "CRITICAL"


def test_median_of_an_even_count_takes_the_upper_middle():
    # an evenly split vote rounds toward the higher severity, so ranking never understates risk
    assert median(["MEDIUM", "HIGH"]) == "HIGH"
    assert median(["LOW", "MEDIUM"]) == "MEDIUM"
