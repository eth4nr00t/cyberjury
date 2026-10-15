"""Backtest comparison reports exact quality and stability changes."""

from __future__ import annotations

import pytest

from evals.backtest.compare import compare


def test_compare_reports_flips():
    before = {"target": "t", "recall": 0.5, "precision_known": 1.0, "found": ["a"], "false_positives": []}
    after = {"target": "t", "recall": 1.0, "precision_known": 0.5, "found": ["a", "b"], "false_positives": ["fp"]}
    d = compare(before, after)
    assert d["newly_found"] == ["b"]
    assert d["newly_missed"] == []
    assert d["newly_false_positive"] == ["fp"]


def test_compare_reports_subthreshold_catch_rate_move():
    before = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 3}}
    after = {"target": "diff", "runs": 3, "found": ["a"], "found_freq": {"a": 2}}
    d = compare(before, after)
    assert d["newly_missed"] == []
    assert d["catch_rate_changed"] == [{"id": "a", "before": 1.0, "after": round(2 / 3, 3)}]


def test_compare_rejects_different_targets_and_denominators():
    with pytest.raises(ValueError, match="same nonempty target"):
        compare({"target": "a"}, {"target": "b"})
    with pytest.raises(ValueError, match="different findings denominators"):
        compare({"target": "a", "n_findings": 1}, {"target": "a", "n_findings": 2})
