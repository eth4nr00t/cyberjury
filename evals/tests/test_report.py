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
from evals.benchmarks.cases import load_cases
from evals.report import failures, format_summary, summarize

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
    text = format_summary(summary)
    assert f"{check} 1/2" in text
    assert "requests 1, failed 0, input tokens 12 (cache read 5), output tokens 3" in text
    assert "report precision 50.0% = supported 1 / (supported 1 + not_actionable 1), over 3 reports" in text
    assert "excluded from precision: duplicate 1, needs_review 0" in text
    assert "precision = supported / (supported + not_actionable)" in text
    assert failures(summary, precision_floor=0.6) == [
        "1 failed attempts",
        "report precision 50% is below the floor 60%",
    ]


def test_report_withholds_precision_and_fails_while_work_is_open(tmp_path, cases, write_attempt, write_ledger):
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A,)), {A: ("needs_review", ())})
    write_attempt(runs, 2, (B,))

    summary = summarize(cases, runs)

    assert summary["precision"] is None
    assert len(summary["unadjudicated"]) == 1
    assert failures(summary, precision_floor=0.9) == [
        "1 attempts without a ledger",
        "1 reports still needing source assessment",
    ]


def test_report_fails_a_run_that_mixes_rubrics():
    summary = {
        "failed": [],
        "unadjudicated": [],
        "verdicts": {"needs_review": 0},
        "precision": 1.0,
        "ledger_rounds": [("round-" + "0" * 16, "e" * 64), ("round-" + "1" * 16, "f" * 64)],
    }

    assert failures(summary, precision_floor=0) == ["run mixes ledgers adjudicated under different rubrics"]


def test_report_rejects_a_ledger_that_no_longer_matches_its_attempt(tmp_path, cases, write_attempt, write_ledger):
    runs = tmp_path / "runs"
    attempt = write_attempt(runs, 1, (A,))
    write_ledger(attempt, {A: _CREDIT})
    attempt.write_text(attempt.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify this attempt"):
        summarize(cases, runs)
