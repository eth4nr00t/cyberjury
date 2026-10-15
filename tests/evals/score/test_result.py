"""Repeated score results fold runs by strict majority without losing failures."""

from __future__ import annotations

import pytest

from evals.backtest.compare import compare
from evals.score.result import RepeatedResult, Result


def _run(target, found, missed, fps, n_findings, n_reports=0, errors=0, extra=()):
    return Result(
        target=target,
        found=list(found),
        missed=list(missed),
        false_positives=list(fps),
        extra=list(extra),
        n_findings=n_findings,
        n_reports=n_reports,
        errors=errors,
    )


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
            extra=["unkeyed"],
        ),
        _run(
            "diff",
            ["a", "b"],
            ["c"],
            [],
            3,
            n_reports=2,
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
    assert sr.extra == ["unkeyed"]
    assert sr.extra_freq == {"unkeyed": 2, "flaky-extra": 1}
    d = sr.to_dict()
    assert d["recall"] == round(2 / 3, 4)
    assert d["found_freq"]["b"] == 2
    assert d["extra"] == ["unkeyed"]


def test_repeated_result_rejects_mismatched_run_contracts():
    base = _run("diff", ["a"], ["b"], [], 2)
    mismatches = [
        (_run("other", ["a"], ["b"], [], 2), "target"),
        (_run("diff", ["a"], ["b"], [], 3), "denominator"),
        (_run("diff", ["a"], ["c"], [], 2), "findings check ids"),
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
