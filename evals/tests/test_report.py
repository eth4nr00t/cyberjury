"""The report recomputes reviewed recall, precision, and cost from attempts, ledgers, and receipts."""

from __future__ import annotations

import json
from dataclasses import replace

from cyberjury.providers.base import CompletionResult, Provider, Usage
from cyberjury.providers.metering import (
    MeteringProvider,
    UsageMeter,
    model_call_context,
    model_call_scope,
    record_model_parse,
)
from evals.report import failures, format_summary, summarize
from tests.support import EMPTY_SCHEMA

A, B = "candidate-" + "a" * 20, "candidate-" + "b" * 20
_CREDIT = ("supported", ("create-missing-owner",))


class _Fake(Provider):
    def complete(self, **_kwargs):
        return CompletionResult(text="{}", usage=Usage(input_tokens=7, cache_read_tokens=5, output_tokens=3))


def _receipt(path):
    meter = UsageMeter()
    with model_call_scope(unit_id="unit-one"), model_call_context(role="finder", trigger="initial_judgment"):
        MeteringProvider(_Fake(), meter).complete(
            system="system",
            prompt="source",
            model="test",
            max_tokens=100,
            response_schema=EMPTY_SCHEMA,
        )
        record_model_parse()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meter.document()), encoding="utf-8")


def test_report_counts_recall_per_run_and_check_precision(
    tmp_path, cases, write_attempt, write_ledger, benchmark_project
):
    """Three runs give recall 1/2, precision 0.5, and one failed attempt."""
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A, B)), {A: _CREDIT, B: ("duplicate", ())})
    write_ledger(write_attempt(runs, 2, (B,)), {B: ("not_actionable", ())})
    write_attempt(runs, 3, (), complete=False)

    summary = summarize(cases, runs)

    check = f"{benchmark_project.diff_case}:create-missing-owner"
    assert summary.recall == {"found": 1, "total": 2}
    assert summary.recall_by_run == {1: {"found": 1, "total": 1}, 2: {"found": 0, "total": 1}}
    assert summary.checks == {check: {"found": 1, "attempts": 2}}
    assert summary.verdicts == {"duplicate": 1, "needs_review": 0, "not_actionable": 1, "supported": 1}
    assert summary.precision == 0.5
    assert summary.failed == [f"{benchmark_project.diff_case} attempt 3: finder failed"]
    text = format_summary(summary)
    assert f"{check} 1/2" in text
    assert "report precision 50.0% = supported 1 / (supported 1 + not_actionable 1), reports 3" in text
    assert "excluded from precision: duplicate 1, needs_review 0" in text


def test_report_sums_cost_from_model_call_receipts(tmp_path, cases, write_attempt, write_ledger):
    """One receipt gives one metered request with 5 cache reads under initial_judgment finder."""
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A,)), {A: _CREDIT})
    _receipt(tmp_path / "calls" / "run-01-model-calls.json")

    summary = summarize(cases, runs, [tmp_path / "calls"])

    assert summary.cost["total"]["requests"] == 1
    assert summary.cost["stages"]["initial_judgment finder"]["cache_read_tokens"] == 5
    text = format_summary(summary)
    assert "  model calls, receipts 1: requests 1, failed 0, input tokens 12 (cache read 5, cache write 0)" in text
    assert "    initial_judgment finder: requests 1, failed 0, input tokens 12" in text


def test_report_fails_failed_attempts_and_precision_below_the_floor(tmp_path, cases, write_attempt, write_ledger):
    """One failed attempt and precision 50% under a 60% floor produce two failures."""
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A, B)), {A: _CREDIT, B: ("not_actionable", ())})
    write_attempt(runs, 2, (), complete=False)

    assert failures(summarize(cases, runs), precision_floor=0.6) == [
        "1 failed attempts",
        "report precision 50% is below the floor 60%",
    ]


def test_report_withholds_precision_and_fails_while_work_is_open(tmp_path, cases, write_attempt, write_ledger):
    """A needs_review verdict and a ledgerless attempt leave precision None and produce two failures."""
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A,)), {A: ("needs_review", ())})
    write_attempt(runs, 2, (B,))

    summary = summarize(cases, runs)

    assert summary.precision is None
    assert len(summary.unadjudicated) == 1
    assert failures(summary, precision_floor=0.9) == [
        "1 attempts without a ledger",
        "1 reports still needing source assessment",
    ]


def test_report_fails_a_run_that_mixes_rubrics(tmp_path, cases, write_attempt, write_ledger):
    """Two ledger rounds with different rubric hashes fail with run mixes ledgers under different rubrics."""
    runs = tmp_path / "runs"
    write_ledger(write_attempt(runs, 1, (A,)), {A: _CREDIT})
    summary = replace(
        summarize(cases, runs),
        ledger_rounds=[("round-" + "0" * 16, "e" * 64), ("round-" + "1" * 16, "f" * 64)],
    )

    assert failures(summary, precision_floor=0) == ["run mixes ledgers adjudicated under different rubrics"]
