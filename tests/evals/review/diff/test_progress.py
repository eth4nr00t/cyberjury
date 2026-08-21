"""Diff benchmark progress events remain live and machine readable."""

from __future__ import annotations

import json

import pytest

from cyberjury.providers.base import Provider
from cyberjury.review.diff.engine import DiffReviewOptions
from evals.benchmarks.cases import DiffCase
from evals.review.diff import execution, run_diff_cases


def test_run_diff_cases_reports_case_progress(monkeypatch, diff_options, diff_result):
    def fake_review(diff: str, *, provider: Provider, model: str, options: DiffReviewOptions):
        if "BROKEN" in diff:
            raise RuntimeError("backend stalled")
        assert options.execution.on_judgment is not None
        options.execution.on_judgment(1, 1, "general review", 0.1)
        return diff_result()

    events = []
    monkeypatch.setattr(execution, "run_diff_review", fake_review)
    result = run_diff_cases(
        [
            DiffCase(name="ok", category="", diff="diff --git CLEAN"),
            DiffCase(name="bad", category="", diff="diff --git BROKEN"),
        ],
        options=diff_options(),
        progress=events.append,
    )

    assert result.errors == 1
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
        "case_started",
        "case_failed",
    ]
    assert events[0]["case"] == "ok"
    assert events[0]["index"] == 1
    assert events[0]["total"] == 2
    assert events[0]["profile"] == "web"
    assert events[1]["judgment_label"] == "general review"
    assert events[2]["reports"] == 0
    assert events[4]["error"] == "RuntimeError: backend stalled"


def test_diff_progress_writer_emits_stderr_and_appends_sidecar_events(tmp_path, capsys):
    from evals.cli import _diff_progress_writer

    output_path = tmp_path / "result.json"
    sidecar = tmp_path / "result.cases.jsonl"
    sidecar.write_text("stale\n", encoding="utf-8")
    write = _diff_progress_writer(str(output_path))
    common = {
        "case": "project:task",
        "index": 1,
        "total": 2,
        "mode": "standard",
        "model": "m",
        "profile": "web",
        "run": 1,
        "runs": 1,
    }
    write({"event": "case_started", **common})
    write(
        {
            "event": "case_judgment_finished",
            **common,
            "elapsed_seconds": 0.75,
            "judgment": 1,
            "judgments": 2,
            "judgment_label": "sql-injection",
            "judgment_seconds": 0.7,
        }
    )
    write(
        {
            "event": "case_finished",
            **common,
            "elapsed_seconds": 1.25,
            "reports": 1,
            "found": 1,
            "missed": 0,
            "false_positives": 0,
            "extra": 0,
        }
    )

    output = capsys.readouterr().err
    assert "knowledge judgment 1/2 [sql-injection] finished" in output
    assert "project:task finished" in output
    events = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    assert [event["event"] for event in events] == [
        "case_started",
        "case_judgment_finished",
        "case_finished",
    ]
    assert events[2]["found"] == 1


def test_diff_progress_formatter_fails_loud_on_unknown_events():
    from evals.cli import _format_diff_progress

    with pytest.raises(ValueError, match="unknown diff progress event"):
        _format_diff_progress({"event": "unexpected", "case": "project:task", "index": 1, "total": 1})
