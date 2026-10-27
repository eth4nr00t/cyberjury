"""Benchmark checks keep the exact form their benchmark.yaml rows declare."""

import pytest

from evals.benchmarks.contract import case_checks


@pytest.mark.parametrize(
    "row",
    [
        {
            "id": "record-owner-missing-permission",
            "root_cause": "Record.save does not check the record owner",
            "locations": [{"file": "models/records.py", "line": 1}, {"file": "views.py", "symbol": "Record.save"}],
        },
        {
            "id": "record-owner-missing-permission",
            "root_cause": "Record.save does not check the record owner",
            "locations": [{"file": "models/records.py", "symbol": "Record.owner"}],
            "change_anchors": [{"file": "producers/input.py", "line": 12, "side": "new"}],
        },
    ],
)
def test_a_check_row_round_trips_through_its_check(row):
    """A repository row without anchors and a diff row with anchors serialize back to the same row."""
    (check,) = case_checks([row])

    assert check.to_dict() == row
