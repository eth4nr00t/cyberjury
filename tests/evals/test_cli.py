"""Evaluation CLI exit status respects whole-case certification."""

import json
from types import SimpleNamespace

import pytest

from evals import adjudication
from evals.cli import _emit, main
from evals.score.result import CaseGateResult, CaseRunResult, RepeatedResult, Result


def test_emit_fails_when_whole_case_gate_fails_despite_aggregate_recall(capsys):
    runs = [
        Result(target="diff", found=["a"], missed=["b"], n_findings=2),
        Result(target="diff", found=["b"], missed=["a"], n_findings=2),
        Result(target="diff", found=["a", "b"], n_findings=2),
    ]
    result = RepeatedResult.from_runs("diff", runs)
    result.case_gate = CaseGateResult(
        expected_cases=("project:case",),
        runs=3,
        required_passes=2,
        case_runs=(
            CaseRunResult(case="project:case", run=1, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=2, complete=True, found=1, missed=1),
            CaseRunResult(case="project:case", run=3, complete=True, found=2),
        ),
    )

    assert result.recall == 1.0
    assert _emit(result, None) == 1
    assert "CASE GATE FAILED" in capsys.readouterr().out


def test_gate_requires_both_adjudication_ledgers_for_a_baseline(capsys):
    with pytest.raises(SystemExit, match="2"):
        main(
            [
                "gate",
                "after.json",
                "--baseline",
                "before.json",
                "--adjudication-ledger",
                "after-ledger.json",
                "--findings-json",
                "after-findings.json",
                "--source",
                "source",
            ]
        )

    assert "baseline ledger and findings" in capsys.readouterr().err


def test_gate_compares_both_source_assessment_ledgers(tmp_path, monkeypatch, capsys):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps({"target": "sample", "found": [], "n_reports": 1}), encoding="utf-8")
    after.write_text(json.dumps({"target": "sample", "found": ["known"], "n_reports": 1}), encoding="utf-8")
    seen = []

    def assess(target, *, findings_json, ledger_json, source_root, run_status):
        seen.append((target, findings_json, ledger_json, source_root, run_status))
        return SimpleNamespace(
            to_dict=lambda: {
                "target": "sample",
                "counts": {"supported": 1},
                "pending": [],
                "known_found": ["known"] if ledger_json == "before-ledger.json" else [],
                "new_supported": [],
                "mismatched_assignments": [],
                "missing_introductions": [],
                "introduction_not_ancestor": [],
                "report_precision": 1.0,
                "machine_status_mismatch": False,
            }
        )

    monkeypatch.setattr(adjudication, "adjudicate", assess)
    status = main(
        [
            "gate",
            str(after),
            "--baseline",
            str(before),
            "--adjudication-ledger",
            "after-ledger.json",
            "--findings-json",
            "after-findings.json",
            "--baseline-adjudication-ledger",
            "before-ledger.json",
            "--baseline-findings-json",
            "before-findings.json",
            "--source",
            "source",
            "--no-structural",
        ]
    )

    assert status == 1
    assert [item[2] for item in seen] == ["after-ledger.json", "before-ledger.json"]
    assert "newly missed" in capsys.readouterr().out
