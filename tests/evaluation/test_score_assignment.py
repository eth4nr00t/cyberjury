"""One to one score assignment tests."""

import pytest

from evals.score.assignment import maximum_weight_assignment


def test_assignment_maximizes_cardinality_before_total_weight():
    assignment = maximum_weight_assignment(((9, 1), (8, 0)))

    assert assignment == {0: 1, 1: 0}


def test_assignment_maximizes_weight_at_the_best_cardinality():
    assignment = maximum_weight_assignment(((4, 3), (4, 0)))

    assert assignment == {0: 1, 1: 0}


def test_assignment_rejects_a_ragged_quality_matrix():
    with pytest.raises(ValueError, match="assignment weights must form a rectangular matrix"):
        maximum_weight_assignment(((1, 2), (1,)))
