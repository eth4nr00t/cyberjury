"""Backtest comparison reports exact quality and stability changes."""

from __future__ import annotations

from evals.backtest.compare import compare, compare_by


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


def test_compare_by_attributes_project_diff_answer_key_checks(tmp_path, monkeypatch, public_only):
    public_only(tmp_path, monkeypatch)
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["get-issue-returns-untrusted-issue-body-to-model"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["prompt-injection"] == ["get-issue-returns-untrusted-issue-body-to-model"]
