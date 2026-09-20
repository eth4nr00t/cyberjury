"""Repeated score results fold runs by strict majority without losing failures."""

from __future__ import annotations

import pytest

from evals.backtest.compare import compare
from evals.score.result import CaseGateResult, CaseRunResult, RepeatedResult, Result


def _run(target, found, missed, fps, n_findings, n_reports=0, errors=0, file_found=(), file_missed=(), extra=()):
    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        extra=list(extra),
        file_found=list(file_found),
        file_missed=list(file_missed),
        n_findings=n_findings,
        n_file_findings=len(file_found) + len(file_missed),
        n_reports=n_reports,
        errors=errors,
    )


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


def test_repeated_result_rejects_mismatched_run_contracts():
    base = _run("diff", ["a"], ["b"], [], 2, file_found=["a"], file_missed=["b"])
    mismatches = [
        (_run("other", ["a"], ["b"], [], 2, file_found=["a"], file_missed=["b"]), "target"),
        (_run("diff", ["a"], ["b"], [], 3, file_found=["a"], file_missed=["b"]), "denominator"),
        (_run("diff", ["a"], ["c"], [], 2, file_found=["a"], file_missed=["b"]), "findings check ids"),
        (_run("diff", ["a"], ["b"], [], 2, file_found=["a"], file_missed=["c"]), "file findings check ids"),
    ]

    for mismatch, message in mismatches:
        with pytest.raises(ValueError, match=message):
            RepeatedResult.from_runs("diff", [base, mismatch])


def test_repeated_result_keeps_a_failed_run_with_partial_check_ids():
    complete = _run("diff", ["a"], ["b"], [], 2)
    failed = _run("diff", [], [], [], 2, errors=1)

    result = RepeatedResult.from_runs("diff", [complete, failed])

    assert result.found_freq == {"a": 1, "b": 0}
    assert result.errors == 1


def test_repeated_result_to_dict_is_compare_compatible():
    from evals.score.result import RepeatedResult

    before = RepeatedResult.from_runs("diff", [_run("diff", ["a"], ["b"], [], 2)]).to_dict()
    after = RepeatedResult.from_runs("diff", [_run("diff", ["a", "b"], [], [], 2)]).to_dict()
    d = compare(before, after)
    assert d["newly_found"] == ["b"]


def test_case_gate_does_not_stitch_findings_across_runs():
    repeated = RepeatedResult.from_runs(
        "diff",
        [
            _run("diff", ["a"], ["b"], [], 2),
            _run("diff", ["b"], ["a"], [], 2),
            _run("diff", ["a", "b"], [], [], 2),
        ],
    )
    repeated.case_gate = CaseGateResult(
        expected_cases=("project:case",),
        runs=3,
        required_passes=2,
        case_runs=(
            CaseRunResult(case="project:case", run=1, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=2, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=3, complete=True, found=2, missed=0),
        ),
    )

    assert repeated.recall == 1.0
    assert repeated.case_gate.passed is False
    assert repeated.case_gate.failed_cases == ("project:case",)
    assert repeated.to_dict()["case_gate"]["cases"][0]["passes"] == 1


def test_case_gate_requires_two_complete_whole_case_passes():
    gate = CaseGateResult(
        expected_cases=("project:case",),
        runs=3,
        required_passes=2,
        case_runs=(
            CaseRunResult(case="project:case", run=1, complete=True, found=2, missed=0),
            CaseRunResult(case="project:case", run=2, complete=False, errors=1, error="provider failed"),
            CaseRunResult(case="project:case", run=3, complete=True, found=2, missed=0),
        ),
    )

    assert gate.passed is False
    assert gate.pass_count("project:case") == 2
    assert gate.to_dict()["cases"][0]["passed"] is False


def test_case_gate_rejects_empty_findings_case_results():
    gate = CaseGateResult(
        expected_cases=("project:case",),
        runs=3,
        required_passes=2,
        case_runs=tuple(CaseRunResult(case="project:case", run=run, complete=True) for run in range(1, 4)),
    )

    assert gate.passed is False
    assert gate.pass_count("project:case") == 0
