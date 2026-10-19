"""The report recomputes reviewed recall, precision, and cost from attempts, ledgers, and receipts."""

from __future__ import annotations

import json

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.metering import (
    MeteringProvider,
    UsageMeter,
    model_call_context,
    model_call_scope,
    record_model_parse,
)
from evals.adjudication import Adjudication
from evals.benchmarks.cases import load_cases
from evals.report import format_summary, regressions, summarize

A, B = "candidate-" + "a" * 20, "candidate-" + "b" * 20
_CREDIT = ("supported", ("create-missing-owner",))


class _Fake(Provider):
    def complete(self, *, system, messages, model, max_tokens, cache=False, cache_prefix="", response_schema=None):
        return CompletionResult(text="{}", usage=Usage(input_tokens=7, cache_read_tokens=5, output_tokens=3))


def _receipt(path):
    meter = UsageMeter()
    with model_call_scope(unit_id="unit-one"), model_call_context(role="finder", trigger="initial_judgment"):
        MeteringProvider(_Fake(), meter).complete(
            system="system", messages=[Message(role="user", content="source")], model="test", max_tokens=100
        )
        record_model_parse()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meter.document()), encoding="utf-8")


@pytest.fixture
def cases(benchmark_project):
    return load_cases([benchmark_project.benchmark])


def test_report_counts_recall_per_run_and_check_precision_and_cost(
    tmp_path, cases, write_attempt, write_ledger, benchmark_project
):
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A, B)), {A: _CREDIT, B: ("duplicate", ())})
    write_ledger(write_attempt(runs, 2, (B,)), {B: ("not_actionable", ())})
    write_attempt(runs, 3, (), complete=False)
    _receipt(tmp_path / "calls" / "run-01-model-calls.json")

    summary = summarize(cases, runs, [tmp_path / "calls"])

    check = f"{benchmark_project.diff_case}:create-missing-owner"
    assert summary["recall"] == {"found": 1, "total": 2}
    assert summary["recall_by_run"] == {1: {"found": 1, "total": 1}, 2: {"found": 0, "total": 1}}
    assert summary["checks"] == {check: {"found": 1, "attempts": 2}}
    assert summary["verdicts"] == {"duplicate": 1, "needs_review": 0, "not_actionable": 1, "supported": 1}
    assert summary["precision"] == 0.5
    assert summary["failed"] == [f"{benchmark_project.diff_case} attempt 3: finder failed"]
    assert summary["cost"]["total"]["requests"] == 1
    assert summary["cost"]["stages"]["initial_judgment finder"]["cache_read_tokens"] == 5
    text = format_summary("run", summary)
    assert f"{check} 1/2" in text
    assert "requests 1, failed 0, input tokens 12 (cache read 5), output tokens 3" in text
    assert "report precision 50.0% = supported 1 / (supported 1 + not_actionable 1), over 3 reports" in text
    assert "excluded from precision: duplicate 1, needs_review 0" in text
    assert "precision = supported / (supported + not_actionable)" in text
    assert regressions(summary, None, precision_floor=0.6) == [
        "changed arm has 1 failed attempts",
        "report precision 50% is below the floor 60%",
    ]


def test_report_withholds_precision_and_fails_while_work_is_open(tmp_path, cases, write_attempt, write_ledger):
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A,)), {A: ("needs_review", ())})
    write_attempt(runs, 2, (B,))

    summary = summarize(cases, runs)

    assert summary["precision"] is None
    assert len(summary["unadjudicated"]) == 1
    assert regressions(summary, None, precision_floor=0.9) == [
        "changed arm has 1 attempts without a ledger",
        "changed arm has 1 reports still needing source assessment",
    ]


def test_report_rejects_a_ledger_that_no_longer_matches_its_attempt(tmp_path, cases, write_attempt, write_ledger):
    runs = tmp_path / "runs"
    attempt = write_attempt(runs, 1, (A,))
    write_ledger(attempt, {A: _CREDIT})
    attempt.write_text(attempt.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify this attempt"):
        summarize(cases, runs)


def _arm(*found_by_run: tuple[str, ...]) -> dict:
    adjudications = [
        Adjudication(
            case="p:diff-1",
            attempt=number,
            found=found,
            missed=tuple(sorted({"first", "second"} - set(found))),
            pending=(),
            counts={},
        )
        for number, found in enumerate(found_by_run, 1)
    ]
    return {
        "failed": [],
        "unadjudicated": [],
        "verdicts": {"needs_review": 0},
        "precision": 1.0,
        "ledger_rounds": [("round-" + "0" * 16, "f" * 64)],
        "adjudications": adjudications,
    }


def test_baseline_comparison_uses_reviewed_majority_and_lost_detections():
    baseline = _arm(("first", "second"), ("first",), ("second",))

    assert regressions(_arm(("second",), ("first", "second"), ("first",)), baseline, precision_floor=0) == []
    dropped = regressions(_arm(("first",), ("second",), ("second",)), baseline, precision_floor=0)
    assert dropped == ["p:diff-1 check newly missed, it was caught at baseline: first"]
    lost = regressions(_arm((), (), ()), _arm(("first",), (), ()), precision_floor=0)
    assert lost == ["p:diff-1 check lost every reviewed detection: first"]


def test_baseline_comparison_requires_comparable_arms():
    baseline = _arm(("first",), ("first",))

    assert regressions(
        _arm(
            ("first",),
        ),
        baseline,
        precision_floor=0,
    ) == ["p:diff-1 baseline and changed arms use different run counts"]
    other = _arm(("first",), ("first",))
    other["adjudications"] = [
        Adjudication(case="p:diff-2", attempt=item.attempt, found=item.found, missed=item.missed, pending=(), counts={})
        for item in other["adjudications"]
    ]
    assert regressions(other, baseline, precision_floor=0) == ["baseline and changed arms cover different cases"]
