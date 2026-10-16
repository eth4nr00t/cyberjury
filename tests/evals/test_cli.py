"""The evals CLI records attempts, adjudicates them through packets and ledgers, and reports."""

from __future__ import annotations

import json

import pytest

from evals.cli import main

A = "candidate-" + "a" * 20


@pytest.fixture
def fake_diff_run(monkeypatch):
    from evals.review import diff

    def run(cases, *, workspace, runs, on_attempt, **kwargs):
        records = []
        for number in range(1, runs + 1):
            for case in cases:
                record = {"case": case.name, "attempt": number, "complete": number == 1, "error": "", "findings": []}
                if number > 1:
                    record["error"] = "finder failed"
                records.append(record)
                on_attempt(record)
        return records

    monkeypatch.setattr(diff, "run", run)


def test_diff_writes_nonoverwriting_attempts_and_summarizes_the_run(tmp_path, capsys, fake_diff_run, benchmark_project):
    runs, reviews = tmp_path / "runs", tmp_path / "reviews"
    args = ["diff", "--manifest", str(benchmark_project.manifest), "--runs", "2"]
    args += ["--attempts-dir", str(runs), "--workspace", str(reviews)]

    assert main(args) == 1

    task = runs / "demo" / benchmark_project.diff_case.split(":", 1)[1]
    assert [json.loads((task / f"attempt-0{n}.json").read_text(encoding="utf-8"))["attempt"] for n in (1, 2)] == [1, 2]
    output = capsys.readouterr().out
    assert "cases 1, runs 2, complete attempts 1/2, reports 0" in output
    assert f"failed: {benchmark_project.diff_case} attempt 2: finder failed" in output
    with pytest.raises(ValueError, match="already exists"):
        main(args)


def test_diff_rejects_an_unknown_case_before_running(tmp_path, fake_diff_run, benchmark_project):
    with pytest.raises(ValueError, match="unknown diff case"):
        main(
            [
                "diff",
                "--manifest",
                str(benchmark_project.manifest),
                "--case",
                "demo:missing",
                "--attempts-dir",
                "x",
                "--workspace",
                "y",
            ]
        )


def test_packets_ledger_and_report_measure_one_adjudicated_run(tmp_path, capsys, write_attempt, benchmark_project):
    runs, out = tmp_path / "runs", tmp_path / "adjudication"
    write_attempt(runs, 1, (A,))
    manifest = ["--manifest", str(benchmark_project.manifest)]

    assert main(["packets", str(runs), "--out", str(out), *manifest]) == 0
    (entry,) = json.loads((out / "packet-1.json").read_text(encoding="utf-8"))
    record = {
        "label": entry["reports"][0]["label"],
        "verdict": "supported",
        "canonical": None,
        "check_ids": ["object-authorization"],
        "evidence": [{"file": "views.py", "line": 2}],
        "reason": "The view saves without an ownership check at views.py:2.",
        "proof_gap": None,
    }
    (out / "result-1.json").write_text(json.dumps([{"case": entry["case"], "records": [record]}]), encoding="utf-8")
    assert main(["ledger", str(out), *manifest]) == 0
    assert main(["report", str(runs), *manifest, "--json", str(tmp_path / "report.json")]) == 0

    output = capsys.readouterr().out
    assert "ledgers written 1, rejected 0" in output
    assert "reviewed recall 1/1" in output
    assert "report precision 100.0% = supported 1 / (supported 1 + not_actionable 0), over 1 reports" in output
    assert "do not give it to adjudicators" in output
    assert "report PASS" in output
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["changed"]["recall"] == {
        "found": 1,
        "total": 1,
    }


def test_packets_say_when_references_hold_no_earlier_verdicts(tmp_path, capsys, write_attempt, benchmark_project):
    runs, earlier = tmp_path / "runs", tmp_path / "earlier"
    write_attempt(runs, 1, (A,))
    write_attempt(earlier, 1, (A,))
    manifest = ["--manifest", str(benchmark_project.manifest)]

    assert main(["packets", str(runs), "--out", str(tmp_path / "out"), "--references", str(earlier), *manifest]) == 0

    output = capsys.readouterr().out
    assert "references: no earlier verdicts were found for any case" in output
    assert f"references {benchmark_project.diff_case}: 0 earlier verdicts" in output
    assert "1 reference attempts have no ledger beside them" in output


def test_repository_records_the_next_attempt_of_a_repository_case(tmp_path, monkeypatch, capsys, benchmark_project):
    from evals import adjudication

    def record(case, directory, number):
        return {"case": case.name, "attempt": number, "complete": True, "findings": []}

    monkeypatch.setattr(adjudication, "recorded_attempt", record)
    args = ["repository", benchmark_project.repository_case, str(tmp_path), "--attempts-dir", str(tmp_path / "runs")]
    args += ["--manifest", str(benchmark_project.manifest)]

    assert main(args) == 0
    assert main(args) == 0

    assert (
        capsys.readouterr().out.splitlines()[-1]
        == f"recorded {benchmark_project.repository_case} attempt 2: 0 reports, complete True"
    )
    with pytest.raises(ValueError, match="not a repository task"):
        main([*args[:1], benchmark_project.diff_case, *args[2:]])
