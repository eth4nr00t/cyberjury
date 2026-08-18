"""Backtest comparison, aggregation, and gate tests."""

from __future__ import annotations

import json

from evals.backtest.compare import compare, compare_by
from evals.score.result import RepeatedResult

from .support import (
    _arm,
    _public_only,
    _run,
)


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


def test_compare_by_attributes_project_diff_answer_key_checks(tmp_path, monkeypatch):
    _public_only(tmp_path, monkeypatch)
    before = {"target": "diff", "found": [], "false_positives": []}
    after = {"target": "diff", "found": ["get-issue-returns-untrusted-issue-body-to-model"], "false_positives": []}
    d = compare_by(before, after, "vulnerability")
    assert d["newly_found"]["prompt-injection"] == ["get-issue-returns-untrusted-issue-body-to-model"]


def test_gate_passes_clean_and_fails_on_regression():
    from evals.backtest.gate import gate

    base = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    good = {"target": "t", "found": ["a", "b"], "false_positives": [], "precision_known": 1.0, "errors": 0}
    assert gate(good, base, structural=False) == []
    bad = {"target": "t", "found": ["a"], "false_positives": ["safe-x"], "precision_known": 0.5, "errors": 0}
    fails = gate(bad, base, precision_floor=0.8, structural=False)
    assert any("newly missed" in f for f in fails)
    assert any("false positive" in f for f in fails)
    assert any("precision" in f for f in fails)


def test_gate_fails_on_errors_but_not_on_extra_alone():
    from evals.backtest.gate import gate

    assert gate({"target": "t", "errors": 2}, structural=False)
    assert (
        gate({"target": "t", "found": ["a"], "false_positives": [], "errors": 0, "extra": ["x", "y"]}, structural=False)
        == []
    )


def test_gate_preserves_benchmark_contract_error(monkeypatch):
    from evals.backtest.gate import gate
    from evals.benchmarks import coverage

    def fail_validation() -> None:
        raise ValueError("knowledge.vulnerabilities has unknown id")

    monkeypatch.setattr(coverage, "coverage_problems", fail_validation)
    assert gate({"target": "t"}, structural=True) == [
        "benchmark contract validation failed: knowledge.vulnerabilities has unknown id"
    ]


def test_repeated_result_to_markdown_shows_runs_and_flaky():
    sr = RepeatedResult.from_runs(
        "diff",
        [
            _run("diff", ["a"], ["b"], [], 2),
            _run("diff", ["a", "b"], [], [], 2),
        ],
    )
    md = sr.to_markdown()
    assert "runs: 2" in md
    assert "flaky: b 1/2" in md


def test_repeated_result_folds_runs_by_strict_majority():
    from evals.score.result import RepeatedResult

    runs = [
        _run(
            "diff",
            ["a", "b"],
            ["c"],
            [],
            3,
            n_reports=2,
            file_found=["a"],
            file_missed=["b", "c"],
            extra=["unkeyed"],
        ),
        _run(
            "diff",
            ["a", "b"],
            ["c"],
            [],
            3,
            n_reports=2,
            file_found=["a", "b"],
            file_missed=["c"],
            extra=["unkeyed"],
        ),
        _run(
            "diff",
            ["a", "c"],
            ["b"],
            ["safe-x"],
            3,
            n_reports=3,
            errors=1,
            file_found=["a"],
            file_missed=["b", "c"],
            extra=["flaky-extra"],
        ),
    ]
    sr = RepeatedResult.from_runs("diff", runs)
    assert sr.runs == 3
    assert sr.found == ["a", "b"]
    assert sr.missed == ["c"]
    assert sr.false_positives == []
    assert sr.errors == 1
    assert sr.n_reports == 7
    assert sr.found_freq == {"a": 3, "b": 2, "c": 1}
    assert sr.file_found == ["a"]
    assert sr.file_missed == ["b", "c"]
    assert sr.file_found_freq == {"a": 3, "b": 1, "c": 0}
    assert sr.extra == ["unkeyed"]
    assert sr.extra_freq == {"unkeyed": 2, "flaky-extra": 1}
    d = sr.to_dict()
    assert d["recall"] == round(2 / 3, 4)
    assert d["found_freq"]["b"] == 2
    assert d["file_recall"] == round(1 / 3, 4)
    assert d["extra"] == ["unkeyed"]


def test_repeated_result_to_dict_is_compare_compatible():
    from evals.backtest.compare import compare
    from evals.score.result import RepeatedResult

    before = RepeatedResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = RepeatedResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_with_arms_folds_in_each_arm_cost_and_marks_a_clean_pair_comparable(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", requests=700))
    assert d["comparable"] is True
    assert d["before_cost"]["model_requests"] == 100
    assert d["after_cost"]["model_requests"] == 700
    assert d["before_cost"]["seconds"] == 60.0


def test_a_failed_review_in_either_arm_disqualifies_the_comparison(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a"), _arm(tmp_path / "b", errors=2))
    assert d["comparable"] is False
    assert any("after arm records 2 errors" in r for r in d["not_comparable_because"])


def test_a_finding_kept_without_a_completed_verification_disqualifies_too(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a", incomplete=1), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 incomplete" in r for r in d["not_comparable_because"])


def test_an_incomplete_run_status_disqualifies_an_arm(tmp_path):
    from evals.backtest.metrics import with_arms

    d = with_arms({}, _arm(tmp_path / "a", complete=False), _arm(tmp_path / "b"))
    assert d["comparable"] is False
    assert any("before arm records 1 run_incomplete" in r for r in d["not_comparable_because"])


def test_incomplete_run_status_counts_each_run_record(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", complete=False)
    _arm(ws / "nested", complete=False)
    got = _arm_artifacts(ws)
    assert got["completeness"]["run_incomplete"] == 2


def test_an_arm_that_wrote_no_record_is_not_read_as_a_clean_zero(tmp_path):
    from evals.backtest.metrics import with_arms

    empty = tmp_path / "empty"
    empty.mkdir()
    d = with_arms({}, _arm(tmp_path / "a"), empty)
    assert d["comparable"] is False
    assert any("wrote no _run.json" in r for r in d["not_comparable_because"])


def test_both_stages_spend_is_summed_rather_than_one_overwriting_the_other(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", requests=100)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 0, "incomplete": 2, "usage": {"model_requests": 40}}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)
    assert got["cost"]["model_requests"] == 140
    assert got["completeness"]["incomplete"] == 2


def test_a_failed_call_counts_once_per_stage_but_a_kept_finding_counts_once(tmp_path):
    from evals.backtest.metrics import _arm_artifacts

    ws = _arm(tmp_path / "a", verify_errors=2, incomplete=1, unlocatable=1)
    (ws / "leaf" / "_finalize.json").write_text(
        json.dumps({"verify_errors": 2, "incomplete": 1, "unlocatable": 1}), encoding="utf-8"
    )
    got = _arm_artifacts(ws)["completeness"]
    assert got["verify_errors"] == 4
    assert got["incomplete"] == 1
    assert got["unlocatable"] == 1


def test_the_displayed_cost_components_account_for_the_displayed_total(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    leaf = tmp_path / "a" / "leaf"
    leaf.mkdir(parents=True)
    (leaf / "_run.json").write_text(
        json.dumps(
            {
                "errors": 0,
                "usage": {
                    "model_requests": 10,
                    "total_input_tokens": 1000,
                    "uncached_input_tokens": 200,
                    "cache_read_tokens": 750,
                    "cache_write_tokens": 50,
                    "output_tokens": 100,
                },
            }
        ),
        encoding="utf-8",
    )
    rendered = format_arms(with_arms({}, tmp_path / "a", None)).splitlines()
    line = next(row for row in rendered if "total_input_tokens=" in row)
    shown = dict(p.split("=") for p in line.split() if "=" in p)
    components = ("uncached_input_tokens", "cache_read_tokens", "cache_write_tokens")
    assert int(shown["total_input_tokens"]) == sum(int(shown[k]) for k in components)


def test_a_stage_elapsed_falls_back_to_its_own_record_when_no_timeline_exists(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    text = format_arms(with_arms({}, _arm(tmp_path / "a", seconds=60.0), _arm(tmp_path / "b", seconds=90.0)))
    assert "60.0s" in text
    assert "90.0s" in text
    assert "?s" not in text
    assert "seconds x1.50" in text


def test_format_arms_reports_the_cost_ratio_and_the_verdict(tmp_path):
    from evals.backtest.metrics import format_arms, with_arms

    d = with_arms({}, _arm(tmp_path / "a", requests=100), _arm(tmp_path / "b", requests=800))
    text = format_arms(d)
    assert "model_requests x8.00" in text
    assert "the comparison stands" in text
