"""Repeated score results fold runs by strict majority without losing failures."""

from __future__ import annotations

import pytest

from evals.backtest.compare import compare
from evals.score.result import RepeatedResult
from tests.evals.backtest.factories import result as _run


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
