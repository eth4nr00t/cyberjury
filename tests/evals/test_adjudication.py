"""Source assessments must identify every report without trusting location matches."""

from __future__ import annotations

import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.result import FindingRecord, FindingsArtifact, OutcomeArtifact
from evals import adjudication
from evals.benchmarks.contract import AnswerKey, ExpectedLocation, KeyCheck, RepositoryCase


def _finding(identity: str, line: int) -> FindingRecord:
    return FindingRecord(
        id=identity,
        category="missing-authorization",
        decision_rule_id="authorization-object-check",
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


def _record(identity: str, verdict: str, *, canonical: str | None = None, check: str | None = None) -> dict:
    return {
        "candidate_id": identity,
        "verdict": verdict,
        "canonical_id": canonical,
        "check_id": check,
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
        knowledge=("vuln:missing-authorization",),
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
            _record(second, "supported", check="object-authorization"),
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
        outcome=ReviewOutcome(findings=(), requires_convergence=False),
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
        _record(case_files[5], "supported", check="object-authorization"),
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
    records[0] = dict(records[0], check_id="object-authorization")
    case_files[2].write_text(json.dumps(dict(case_files[3], records=records)), encoding="utf-8")

    with pytest.raises(ValueError, match="cannot credit"):
        _adjudicate(case_files)


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
