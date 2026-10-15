"""Evaluation CLI commands keep source-reviewed and strict results separate."""

import json
from types import SimpleNamespace

import pytest

from evals import adjudication
from evals.backtest import calls as call_reports
from evals.cli import _emit, main
from evals.score.result import Result


def _case(name, expectation="findings"):
    from evals.benchmarks.cases import DiffCase
    from evals.benchmarks.contract import AnswerKey, KeyCheck

    checks = (KeyCheck(id="known", expectation="findings"),) if expectation == "findings" else ()
    return DiffCase(name=name, answer_key=AnswerKey(benchmark_id="project", checks=checks), expectation=expectation)


def _reviewed(directory, case, attempt, *, reviewed=("known",), pending=()):
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": adjudication.DIFF_SCHEMA,
        "case": case,
        "attempt": attempt,
        "source_commit": "a" * 40,
        "attempt_sha256": f"{case}-{attempt}",
        "ledger_sha256": "b" * 64,
        "raw_found": [],
        "raw_missed": ["known"],
        "reviewed_found": list(reviewed),
        "reviewed_missed": [] if reviewed else ["known"],
        "pending": list(pending),
        "report_counts": {"duplicate": 0, "needs_review": len(pending), "not_actionable": 0, "supported": 1},
    }
    (directory / f"{case.split(':', 1)[1]}-{attempt:02d}.json").write_text(json.dumps(document), encoding="utf-8")


def test_emit_reports_raw_misses_without_failing_and_fails_on_errors(capsys):
    assert _emit(Result(target="diff", found=["a"], n_findings=1), None) == 0
    assert _emit(Result(target="diff", missed=["a"], n_findings=1), None) == 0
    assert "raw unmatched: a" in capsys.readouterr().out
    assert _emit(Result(target="diff", missed=["a"], n_findings=1, errors=1), None) == 1


def test_calls_cli_flags_model_changes_during_stage_comparison(monkeypatch, capsys):
    def load(path):
        model = "before-model" if path == "before.json" else "after-model"
        return {
            "schema": call_reports.SCHEMA,
            "source_sha256": "a" * 64 if path == "before.json" else "b" * 64,
            "models": [model],
            "stages": [
                {
                    "trigger": "initial_judgment",
                    "role": "finder",
                    "models": [model],
                    "requests": 1,
                    "max_prompt_chars": 20,
                    "total_input_tokens": 10,
                }
            ],
        }

    monkeypatch.setattr(call_reports, "load_model_call_summary", load)

    assert main(["calls", "after.json", "--baseline", "before.json"]) == 0
    output = capsys.readouterr().out
    assert "requests 1 -> 1" in output
    assert "max prompt chars 20 -> 20" in output
    assert "model sets differ" in output


def test_diff_cli_writes_a_separate_validated_model_call_artifact(tmp_path, monkeypatch):
    from cyberjury.providers.base import Message
    from cyberjury.providers.metering import MeteringProvider, model_call_context, record_model_parse
    from cyberjury.providers.mock import MockProvider
    from evals.benchmarks import cases
    from evals.review import diff

    selected_case = _case("project:diff-2")
    monkeypatch.setattr(cases, "diff_cases", lambda: [_case("project:diff-1"), selected_case])

    def fake_run(selected, *, meter, **kwargs):
        assert selected == [selected_case]
        with model_call_context(role="finder", trigger="initial_judgment", unit_id="unit-one") as context:
            MeteringProvider(MockProvider(default="{}"), meter).complete(
                system="system", messages=[Message(role="user", content="source")], model="mock", max_tokens=100
            )
            record_model_parse("direct")
            context.navigation("not_requested")
        return Result(target="diff")

    monkeypatch.setattr(diff, "run", fake_run)
    output = tmp_path / "model-calls.json"

    assert main(["diff", "--case", selected_case.name, "--calls-json", str(output)]) == 0
    summary = call_reports.load_model_call_summary(output)
    assert summary["stages"][0]["requests"] == 1
    assert summary["stages"][0]["max_prompt_chars"] == len("systemsource")


def test_diff_cli_rejects_an_unknown_case_before_running(tmp_path, monkeypatch):
    from evals.benchmarks import cases
    from evals.review import diff

    monkeypatch.setattr(cases, "diff_cases", lambda: [])
    monkeypatch.setattr(diff, "run", lambda *args, **kwargs: pytest.fail("review should not run"))

    with pytest.raises(ValueError, match="unknown diff case"):
        main(["diff", "--case", "missing", "--calls-json", str(tmp_path / "calls.json")])


def test_diff_cli_writes_one_nonoverwriting_attempt_per_case_and_run(tmp_path, monkeypatch):
    from evals.benchmarks import cases
    from evals.review import diff

    monkeypatch.setattr(cases, "diff_cases", lambda: [_case("project:diff-1")])

    def fake_run(selected, *, on_attempt, runs, **kwargs):
        for number in range(1, runs + 1):
            on_attempt(number, {"case": "project:diff-1", "attempt": number, "complete": True})
        return Result(target="diff")

    monkeypatch.setattr(diff, "run", fake_run)
    directory = tmp_path / "attempts"
    args = ["diff", "--runs", "2", "--attempts-dir", str(directory)]

    assert main(args) == 0
    for number in (1, 2):
        path = directory / "project" / "diff-1" / f"attempt-{number:02d}.json"
        assert json.loads(path.read_text(encoding="utf-8"))["attempt"] == number
    with pytest.raises(ValueError, match="already exists"):
        main(args)


def test_diff_cli_writes_one_nonoverwriting_call_artifact_per_run(tmp_path, monkeypatch, capsys):
    from cyberjury.providers.base import Message
    from cyberjury.providers.metering import MeteringProvider, model_call_context, record_model_parse
    from cyberjury.providers.mock import MockProvider
    from evals.benchmarks import cases
    from evals.review import diff

    monkeypatch.setattr(cases, "diff_cases", lambda: [])

    def fake_run(selected, *, meter, on_run_calls, **kwargs):
        provider = MeteringProvider(MockProvider(default="{}"), meter)
        for number in (1, 2):
            boundary = len(meter.call_snapshot())
            with model_call_context(role="finder", trigger="initial_judgment", unit_id=f"unit-{number}") as context:
                provider.complete(
                    system="system", messages=[Message(role="user", content="source")], model="mock", max_tokens=100
                )
                record_model_parse("direct")
                context.navigation("not_requested")
            on_run_calls(number, meter.document_from(boundary))
        return Result(target="diff")

    monkeypatch.setattr(diff, "run", fake_run)
    directory = tmp_path / "calls"
    aggregate = tmp_path / "all-calls.json"
    args = ["diff", "--runs", "2", "--calls-dir", str(directory), "--calls-json", str(aggregate)]

    assert main(args) == 0
    assert call_reports.load_model_call_summary(aggregate)["usage"]["model_requests"] == 2
    for number in (1, 2):
        path = directory / f"run-{number:02d}-model-calls.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        assert call_reports.load_model_call_summary(path)["usage"]["model_requests"] == 1
        assert document["calls"][0]["unit_id"] == f"unit-{number}"
    with pytest.raises(SystemExit, match="2"):
        main(args)
    assert "already exists" in capsys.readouterr().err


def test_diff_cli_rejects_output_paths_inside_per_run_receipts(tmp_path, capsys):
    directory = tmp_path / "calls"
    receipt = str(directory / "run-01-model-calls.json")

    with pytest.raises(SystemExit, match="2"):
        main(["diff", "--calls-dir", str(directory), "--json", receipt])
    assert "must differ from per-run receipts" in capsys.readouterr().err

    with pytest.raises(SystemExit, match="2"):
        main(["diff", "--calls-dir", str(directory), "--calls-json", receipt])
    assert "must differ from per-run receipts" in capsys.readouterr().err


def test_diff_cli_rejects_the_same_score_and_call_output_path(tmp_path, capsys):
    output = str(tmp_path / "result.json")

    with pytest.raises(SystemExit, match="2"):
        main(["diff", "--json", output, "--calls-json", output])

    assert "different output paths" in capsys.readouterr().err

    alias = tmp_path / "nested"
    alias.mkdir()
    with pytest.raises(SystemExit, match="2"):
        main(["diff", "--json", output, "--calls-json", str(alias / ".." / "result.json")])

    assert "different output paths" in capsys.readouterr().err


def test_gate_refuses_a_result_without_source_assessment(capsys):
    with pytest.raises(SystemExit, match="2"):
        main(["gate", "after.json"])

    assert "raw location matches never gate" in capsys.readouterr().err


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


def test_reviewed_gate_compares_saved_adjudications_and_reports_raw_beside_reviewed(tmp_path, capsys):
    before = tmp_path / "before"
    after = tmp_path / "after"
    for number in (1, 2):
        _reviewed(before, "sample:diff-1", number)
        _reviewed(after, "sample:diff-1", number, reviewed=() if number == 1 else ("known",))

    assert main(["gate", str(before), "--baseline", str(before)]) == 0
    assert main(["gate", str(after), "--baseline", str(before)]) == 1
    output = capsys.readouterr().out
    assert "newly missed" in output
    assert "source reviewed 1/2, strict raw 0/2" in output


def test_reviewed_gate_rejects_a_strict_baseline_and_repository_options(tmp_path, capsys):
    reviewed = tmp_path / "reviewed"
    _reviewed(reviewed, "sample:diff-1", 1)

    with pytest.raises(SystemExit, match="2"):
        main(["gate", str(reviewed), "--baseline", "before.json"])
    assert "must also be a directory" in capsys.readouterr().err
    with pytest.raises(SystemExit, match="2"):
        main(["gate", str(reviewed), "--require-introductions"])
    assert "no repository assessment options" in capsys.readouterr().err


def test_certify_cli_requires_reviewed_passes_for_every_findings_case(tmp_path, monkeypatch, capsys):
    from evals.benchmarks import cases

    monkeypatch.setattr(cases, "diff_cases", lambda: [_case("sample:diff-1"), _case("sample:diff-2", "clean")])
    reviewed = tmp_path / "reviewed"
    for number in (1, 2, 3):
        _reviewed(reviewed, "sample:diff-1", number, reviewed=() if number == 3 else ("known",))
    receipt = tmp_path / "certify.json"

    assert main(["certify", str(reviewed), "--json", str(receipt)]) == 0
    assert json.loads(receipt.read_text(encoding="utf-8"))["cases"][0]["passes"] == [1, 2]
    assert "source reviewed 1/1 cases passed" in capsys.readouterr().out
    assert main(["certify", str(reviewed), "--required-passes", "3"]) == 1


def test_adjudicate_cli_reports_strict_assignment_disagreement_as_a_note(monkeypatch, capsys):
    def assess(target, *, findings_json, ledger_json, source_root, run_status):
        return SimpleNamespace(
            target=target,
            counts={"supported": 1},
            extra_dispositions={},
            known_found=("known",),
            known_missed=(),
            introduction_check_count=1,
            new_supported=(),
            mismatched_assignments=(("known", "", "candidate-" + "a" * 20),),
            report_precision=1.0,
            independent_verified=None,
            missing_introductions=(),
            introduction_not_ancestor=(),
            pending=(),
        )

    monkeypatch.setattr(adjudication, "adjudicate", assess)
    args = ["adjudicate", "sample", "--findings-json", "f.json", "--ledger", "l.json", "--source", "src"]

    assert main(args) == 0
    assert "NOTE: strict location assignments differ from source assessment 1" in capsys.readouterr().out


def test_diff_adjudication_cli_keeps_strict_and_reviewed_results_separate(monkeypatch, capsys):
    seen = []

    def assess(manifest, name, *, attempt_json, ledger_json, source_root):
        seen.append((manifest, name, attempt_json, ledger_json, source_root))
        return SimpleNamespace(
            case=name,
            attempt=1,
            raw_found=(),
            reviewed_found=("check",),
            reviewed_missed=(),
            pending=(),
            to_dict=lambda: {},
        )

    monkeypatch.setattr(adjudication, "adjudicate_diff", assess)

    status = main(
        [
            "adjudicate-diff",
            "sample:diff-1",
            "--manifest",
            "benchmark.yaml",
            "--attempt-json",
            "attempt.json",
            "--ledger",
            "ledger.json",
            "--source",
            "source",
        ]
    )

    assert status == 0
    assert seen == [("benchmark.yaml", "sample:diff-1", "attempt.json", "ledger.json", "source")]
    assert "raw strict matches 0/1" in capsys.readouterr().out


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
        ]
    )

    assert status == 1
    assert [item[2] for item in seen] == ["after-ledger.json", "before-ledger.json"]
    assert "newly missed" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["certify", "reviewed", "--run", "3"],
        ["gate", "after.json", "--baseline-adj", "ledger.json"],
        ["repository", "paperless-ngx", "--find", "findings.json"],
    ],
)
def test_cli_rejects_abbreviated_flags(argv, capsys):
    with pytest.raises(SystemExit, match="2"):
        main(argv)

    assert "unrecognized arguments" in capsys.readouterr().err
