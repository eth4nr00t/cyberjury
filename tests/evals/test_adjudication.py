"""Source assessments must identify every report without trusting location matches."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.result import FindingRecord, FindingsArtifact, OutcomeArtifact
from evals import adjudication
from evals.benchmarks.cases import DiffCase
from evals.benchmarks.contract import AnswerKey, ExpectedLocation, KeyCheck, RepositoryCase

_GRADE = {"severity": "HIGH", "confidence": 0.9}


def _finding(identity: str, line: int) -> FindingRecord:
    return FindingRecord(
        id=identity,
        category="missing-authorization",
        severity="HIGH",
        file="views.py",
        line=line,
        entrypoint="POST /objects",
        summary=f"Claim at line {line}",
        evidence="",
        attack_path="An authorized caller reaches the operation",
        recommendation="",
        status="confirmed",
        evidence_refs=(),
        supporting_reviewers=(),
    )


def _record(identity: str, verdict: str, *, canonical: str | None = None, checks: tuple[str, ...] = ()) -> dict:
    return {
        "candidate_id": identity,
        "verdict": verdict,
        "canonical_id": canonical,
        "check_ids": list(checks),
        "reason": "Source review identifies the authorization control",
        "proof_gap": "Need the caller's authorization scope" if verdict == "needs_review" else "",
        "evidence": [{"file": "views.py", "line": 2}],
    }


@pytest.fixture
def case_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "views.py").write_text("def create():\n    return save()\n", encoding="utf-8")
    first = "candidate-" + "a" * 20
    second = "candidate-" + "b" * 20
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(FindingsArtifact.create((_finding(first, 2), _finding(second, 2))).to_dict()),
        encoding="utf-8",
    )
    commit = "a" * 40
    check = KeyCheck(
        id="object-authorization",
        expectation="findings",
        applies_to=("repository-aaaaaaa",),
        locations=(ExpectedLocation(file="views.py", line=2),),
    )
    key = AnswerKey(benchmark_id="sample", checks=(check,))
    case = RepositoryCase(
        id="sample",
        kind="repository",
        answer_key=tmp_path / "answer-key.yaml",
        provenance="public",
        target={"ref": commit},
        task_id="repository-aaaaaaa",
    )
    monkeypatch.setattr(adjudication, "find_repository_case", lambda name: case)
    monkeypatch.setattr(adjudication, "load_answer_key", lambda path, task_id=None: key)
    monkeypatch.setattr(adjudication, "_source_commit", lambda root: commit)
    ledger = {
        "schema": adjudication.SCHEMA,
        "target": "sample",
        "source_commit": commit,
        "findings_sha256": hashlib.sha256(findings.read_bytes()).hexdigest(),
        "records": [
            _record(first, "not_actionable"),
            _record(second, "supported", checks=("object-authorization",)),
        ],
    }
    ledger_path = tmp_path / "adjudication.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    return source, findings, ledger_path, ledger, first, second


def _adjudicate(case_files):
    source, findings, ledger_path, *_ = case_files
    return adjudication.adjudicate("sample", findings_json=findings, ledger_json=ledger_path, source_root=source)


def test_adjudication_exposes_a_location_match_to_the_wrong_candidate(case_files):
    result = _adjudicate(case_files)

    assert result.counts["supported"] == 1
    assert result.counts["not_actionable"] == 1
    assert result.extra_dispositions["supported"] == 1
    assert result.matched_dispositions["not_actionable"] == 1
    assert result.known_found == ("object-authorization",)
    assert result.new_supported == ()
    assert result.ledger_sha256 == hashlib.sha256(case_files[2].read_bytes()).hexdigest()
    assert result.introduction_check_count == 0
    assert result.mismatched_assignments == (("object-authorization", case_files[4], case_files[5]),)
    assert result.report_precision == 0.5


def test_one_source_supported_report_can_cover_two_independent_checks(case_files, monkeypatch):
    key = AnswerKey(
        benchmark_id="sample",
        checks=tuple(
            KeyCheck(
                id=check_id,
                expectation="findings",
                applies_to=("repository-aaaaaaa",),
                locations=(ExpectedLocation(file="views.py", line=2),),
            )
            for check_id in ("object-authorization", "owner-write")
        ),
    )
    monkeypatch.setattr(adjudication, "load_answer_key", lambda path, task_id=None: key)
    records = list(case_files[3]["records"])
    records[1] = _record(case_files[5], "supported", checks=("object-authorization", "owner-write"))
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    result = _adjudicate(case_files)

    assert result.known_found == ("object-authorization", "owner-write")
    assert result.known_missed == ()
    assert len(result.cross_path_checks) == 2
    assert all(check["source_supported_candidate"] == case_files[5] for check in result.cross_path_checks)


def test_adjudication_rejects_a_retired_single_check_ledger(case_files):
    ledger = dict(case_files[3], schema="cyberjury.eval-adjudication/v1")
    case_files[2].write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ValueError, match="target or source does not match"):
        _adjudicate(case_files)


def test_adjudication_rejects_the_same_check_claimed_by_two_candidates(case_files):
    records = [
        _record(case_files[4], "supported", checks=("object-authorization",)),
        _record(case_files[5], "supported", checks=("object-authorization",)),
    ]
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="one benchmark check"):
        _adjudicate(case_files)


def test_adjudication_rejects_duplicate_check_ids_in_one_record(case_files):
    records = list(case_files[3]["records"])
    records[1] = _record(case_files[5], "supported", checks=("object-authorization", "object-authorization"))
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="check_ids must be unique"):
        _adjudicate(case_files)


def test_pending_source_assessment_has_no_report_precision(case_files):
    records = list(case_files[3]["records"])
    records[0] = _record(case_files[4], "needs_review")
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    result = _adjudicate(case_files)

    assert result.report_precision is None
    assert result.to_dict()["report_precision"] is None


def test_legacy_confirmed_labels_disagree_with_zero_independent_votes(case_files):
    artifact = FindingsArtifact.from_dict(json.loads(case_files[1].read_text(encoding="utf-8")))
    revision = "c" * 64
    outcome = OutcomeArtifact.create(
        target="repository",
        source_revision=revision,
        findings=artifact,
        outcome=ReviewOutcome(findings=()),
    )
    (case_files[1].parent / "outcome.json").write_text(json.dumps(outcome.to_dict()), encoding="utf-8")
    status = {"verified": 0, "source_revision": revision}
    digest = hashlib.sha256(json.dumps(status, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    run_status = case_files[1].parent / "_run.json"
    run_status.write_text(json.dumps({**status, "content_sha256": digest}), encoding="utf-8")

    result = adjudication.adjudicate(
        "sample",
        findings_json=case_files[1],
        ledger_json=case_files[2],
        source_root=case_files[0],
        run_status=run_status,
    )

    assert result.machine_confirmed == 2
    assert result.independent_verified == 0
    assert result.machine_status_mismatch is True


def test_adjudication_accepts_a_location_match_to_a_reviewed_duplicate(case_files):
    records = [
        _record(case_files[4], "duplicate", canonical=case_files[5]),
        _record(case_files[5], "supported", checks=("object-authorization",)),
    ]
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    result = _adjudicate(case_files)

    assert result.mismatched_assignments == ()
    assert result.cross_path_checks[0]["location_canonical_candidate"] == case_files[5]


def test_adjudication_requires_exact_findings_content(case_files):
    case_files[1].write_text(case_files[1].read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify these findings"):
        _adjudicate(case_files)


def test_adjudication_requires_every_candidate(case_files):
    ledger = dict(case_files[3], records=case_files[3]["records"][:1])
    case_files[2].write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ValueError, match="cover every finding"):
        _adjudicate(case_files)


def test_adjudication_rejects_duplicate_cycles(case_files):
    first, second = case_files[4:]
    records = [_record(first, "duplicate", canonical=second), _record(second, "duplicate", canonical=first)]
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="cycle"):
        _adjudicate(case_files)


def test_adjudication_rejects_missing_source_evidence(case_files):
    records = list(case_files[3]["records"])
    records[1] = dict(records[1], evidence=[{"file": "views.py", "line": 99}])
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="evidence line does not exist"):
        _adjudicate(case_files)


def test_adjudication_rejects_an_unreviewed_check_assignment(case_files):
    records = list(case_files[3]["records"])
    records[0] = dict(records[0], check_ids=["object-authorization"])
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="cannot credit"):
        _adjudicate(case_files)


@pytest.fixture
def diff_case_files(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "views.py").write_text("def route():\n    return process()\n", encoding="utf-8")
    commit = "b" * 40
    case_name = "sample:diff-aaaaaaa-1"
    candidate_id = "candidate-" + "c" * 20
    key = AnswerKey(
        benchmark_id="sample",
        checks=(
            KeyCheck(id="first", expectation="findings"),
            KeyCheck(id="second", expectation="findings"),
        ),
    )
    case = DiffCase(name=case_name, target={"ref": commit}, answer_key=key)
    monkeypatch.setattr(adjudication, "load_project_diff_cases", lambda manifest: [case])
    monkeypatch.setattr(adjudication, "_source_commit", lambda root: commit)
    attempt = {
        "case": case_name,
        "attempt": 1,
        "complete": True,
        "findings": [
            {"candidate_id": candidate_id, "category": "access-control", "file": "views.py", "line": 2, **_GRADE}
        ],
        "expected_checks": json.loads(json.dumps([asdict(check) for check in key.checks])),
        "result": {
            "target": case_name,
            "errors": 0,
            "found": [],
            "missed": [f"{case_name}:first", f"{case_name}:second"],
            "n_findings": 2,
            "n_reports": 1,
            "extra": ["views.py:2:0"],
            "false_positives": [],
        },
    }
    attempt_path = tmp_path / "attempt.json"
    attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
    ledger = {
        "schema": adjudication.DIFF_SCHEMA,
        "case": case_name,
        "attempt": 1,
        "source_commit": commit,
        "attempt_sha256": hashlib.sha256(attempt_path.read_bytes()).hexdigest(),
        "records": [_record(candidate_id, "supported", checks=("first", "second"))],
    }
    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    return source, attempt_path, ledger_path, ledger, case_name, candidate_id


def _adjudicate_diff(diff_case_files):
    source, attempt, ledger, _data, case_name, _candidate_id = diff_case_files
    return adjudication.adjudicate_diff(
        "manifest.yaml",
        case_name,
        attempt_json=attempt,
        ledger_json=ledger,
        source_root=source,
    )


def test_diff_source_assessment_preserves_raw_misses_and_credits_multiple_checks(diff_case_files):
    result = _adjudicate_diff(diff_case_files)

    assert result.raw_found == ()
    assert result.raw_missed == ("first", "second")
    assert result.reviewed_found == ("first", "second")
    assert result.reviewed_missed == ()
    assert result.report_counts["supported"] == 1
    assert result.to_dict()["review_complete"] is True
    assert result.report_precision == 1.0


def test_diff_source_assessment_rejects_an_incomplete_attempt(diff_case_files):
    attempt = json.loads(diff_case_files[1].read_text(encoding="utf-8"))
    attempt["complete"] = False
    diff_case_files[1].write_text(json.dumps(attempt), encoding="utf-8")

    with pytest.raises(ValueError, match="not a complete run"):
        _adjudicate_diff(diff_case_files)


def test_diff_source_assessment_rejects_a_different_attempt_hash(diff_case_files):
    ledger = dict(diff_case_files[3], attempt_sha256="0" * 64)
    diff_case_files[2].write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify"):
        _adjudicate_diff(diff_case_files)


def test_diff_source_assessment_rejects_a_changed_answer_key(diff_case_files):
    attempt = json.loads(diff_case_files[1].read_text(encoding="utf-8"))
    attempt["expected_checks"][0]["id"] = "different"
    diff_case_files[1].write_text(json.dumps(attempt), encoding="utf-8")

    with pytest.raises(ValueError, match="answer key differs"):
        _adjudicate_diff(diff_case_files)


def test_diff_source_assessment_rejects_a_false_raw_score(diff_case_files):
    attempt = json.loads(diff_case_files[1].read_text(encoding="utf-8"))
    attempt["result"]["extra"] = []
    diff_case_files[1].write_text(json.dumps(attempt), encoding="utf-8")

    with pytest.raises(ValueError, match="does not match replayed findings"):
        _adjudicate_diff(diff_case_files)


def test_diff_source_assessment_rejects_duplicate_check_credits(diff_case_files):
    records = list(diff_case_files[3]["records"])
    second = "candidate-" + "d" * 20
    attempt = json.loads(diff_case_files[1].read_text(encoding="utf-8"))
    attempt["findings"].append(
        {"candidate_id": second, "category": "access-control", "file": "views.py", "line": 2, **_GRADE}
    )
    attempt["result"]["n_reports"] = 2
    attempt["result"]["extra"].append("views.py:2:1")
    diff_case_files[1].write_text(json.dumps(attempt), encoding="utf-8")
    records.append(_record(second, "supported", checks=("first",)))
    ledger = dict(
        diff_case_files[3],
        attempt_sha256=hashlib.sha256(diff_case_files[1].read_bytes()).hexdigest(),
        records=records,
    )
    diff_case_files[2].write_text(json.dumps(ledger), encoding="utf-8")

    with pytest.raises(ValueError, match="one benchmark check"):
        _adjudicate_diff(diff_case_files)


def test_introduction_lineage_requires_an_ancestor_of_the_repository_snapshot(tmp_path, monkeypatch):
    root = tmp_path / "source"
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    path = root / "views.py"
    path.write_text("first\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "views.py"], check=True)
    commit_args = ["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm"]
    subprocess.run([*commit_args, "base"], check=True)
    base = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    path.write_text("second\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "views.py"], check=True)
    subprocess.run([*commit_args, "introduction"], check=True)
    introduced = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    task_id = f"diff-{introduced[:7]}-1"
    manifest = {
        "tasks": [{"id": task_id, "kind": "diff", "expectation": "findings", "revision": {"commit": introduced}}]
    }
    monkeypatch.setattr(adjudication.registry, "load_project_manifest", lambda path: manifest)
    case = SimpleNamespace(manifest=tmp_path / "benchmark.yaml")

    assert adjudication._introduction_lineage(case, root, introduced, {task_id}) == ()
    assert adjudication._introduction_lineage(case, root, base, {task_id}) == (task_id,)


def test_attempt_written_by_evals_diff_is_accepted_by_adjudicate_diff(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from cyberjury.finding import Finding
    from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
    from evals.benchmarks import cases
    from evals.cli import main
    from evals.review.diff import execution

    source = tmp_path / "source"
    source.mkdir()
    (source / "views.py").write_text("def route():\n    return process()\n", encoding="utf-8")
    commit = "b" * 40
    case_name = "sample:diff-aaaaaaa-1"
    check = KeyCheck(
        id="route-authorization",
        expectation="findings",
        applies_to=("diff-aaaaaaa-1",),
        locations=(ExpectedLocation(file="views.py", line=2),),
    )
    case = DiffCase(
        name=case_name, target={"ref": commit}, answer_key=AnswerKey(benchmark_id="sample", checks=(check,))
    )
    seat = ProviderSeat(provider="openai", model="mock", api_key="key")
    configuration = ProviderConfiguration(base=seat, finder=seat, skeptic=seat, confirmer=seat, retries=0, timeout=10)
    finding = Finding(file="views.py", line=2, category="missing-authorization", description="route skips the check")

    @contextmanager
    def checkout(target):
        yield source

    monkeypatch.setattr(cases, "diff_cases", lambda: [case])
    monkeypatch.setattr(adjudication, "load_project_diff_cases", lambda manifest: [case])
    monkeypatch.setattr(adjudication, "_source_commit", lambda root: commit)
    monkeypatch.setattr(execution, "diff_text", lambda case: "diff --git a/views.py b/views.py\n")
    monkeypatch.setattr(execution, "provider_configuration_from_env", lambda **kwargs: configuration)
    monkeypatch.setattr(
        execution,
        "review_diff_checkout",
        lambda diff, **kwargs: SimpleNamespace(
            result=SimpleNamespace(outcome=SimpleNamespace(findings=[finding], degraded=False))
        ),
    )
    monkeypatch.setattr(execution, "source_root", checkout)
    attempts = tmp_path / "attempts"

    assert main(["diff", "--attempts-dir", str(attempts)]) == 0
    attempt = attempts / "sample" / "diff-aaaaaaa-1" / "attempt-01.json"
    candidate = json.loads(attempt.read_text(encoding="utf-8"))["findings"][0]["candidate_id"]
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps(
            {
                "schema": adjudication.DIFF_SCHEMA,
                "case": case_name,
                "attempt": 1,
                "source_commit": commit,
                "attempt_sha256": hashlib.sha256(attempt.read_bytes()).hexdigest(),
                "records": [_record(candidate, "supported", checks=("route-authorization",))],
            }
        ),
        encoding="utf-8",
    )

    result = adjudication.adjudicate_diff(
        "benchmark.yaml", case_name, attempt_json=attempt, ledger_json=ledger, source_root=source
    )

    assert result.raw_found == ("route-authorization",)
    assert result.reviewed_found == ("route-authorization",)
    assert result.report_counts["supported"] == 1


def test_load_diff_adjudications_groups_saved_outputs_by_case(diff_case_files, tmp_path):
    first = _adjudicate_diff(diff_case_files)
    second = replace(first, attempt=2, attempt_sha256="e" * 64, reviewed_found=("first",), reviewed_missed=("second",))
    directory = tmp_path / "reviewed"
    directory.mkdir()
    for result in (second, first):
        (directory / f"attempt-{result.attempt}.json").write_text(json.dumps(result.to_dict()), encoding="utf-8")

    loaded = adjudication.load_diff_adjudications(directory)

    assert list(loaded) == [first.case]
    assert loaded[first.case] == (first, second)
    (directory / "attempt-3.json").write_text(json.dumps(first.to_dict()), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate attempt numbers"):
        adjudication.load_diff_adjudications(directory)
