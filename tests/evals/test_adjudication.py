"""Source assessment ledgers must bind to their attempt, pinned commit, and current answer key."""

from __future__ import annotations

import json

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.result import FindingRecord, FindingsArtifact, OutcomeArtifact
from cyberjury.sources.snapshot import capture_source_snapshot
from evals.adjudication import adjudicate, load_attempt, read_json, recorded_attempt
from evals.benchmarks.cases import find_case
from tests.support import git

A, B = "candidate-" + "a" * 20, "candidate-" + "b" * 20


@pytest.fixture
def case(benchmark_project):
    return find_case(benchmark_project.diff_case, [benchmark_project.manifest])


@pytest.fixture
def attempt(tmp_path, write_attempt):
    return write_attempt(tmp_path / "runs", 1, (A, B))


def _adjudicate(case, attempt, source=None):
    loaded = load_attempt(attempt)
    return adjudicate(case, loaded, read_json(loaded.ledger_path), source)


def test_ledger_credits_checks_and_counts_verdicts(case, attempt, write_ledger, benchmark_project):
    write_ledger(attempt, {A: ("supported", ("object-authorization",)), B: ("not_actionable", ())})

    result = _adjudicate(case, attempt, benchmark_project.repo)

    assert result.found == ("object-authorization",)
    assert result.missed == ()
    assert result.pending == ()
    assert result.counts == {"duplicate": 0, "needs_review": 0, "not_actionable": 1, "supported": 1}


def test_ledger_must_assess_every_report_exactly_once(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("supported", ())})

    with pytest.raises(ValueError, match="every report of the attempt exactly once"):
        _adjudicate(case, attempt)


def test_ledger_rejects_a_check_credited_by_two_reports(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("supported", ("object-authorization",)), B: ("supported", ("object-authorization",))})

    with pytest.raises(ValueError, match="credits one check from two reports"):
        _adjudicate(case, attempt)


def test_ledger_rejects_a_check_outside_the_case(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("supported", ("invented-check",)), B: ("not_actionable", ())})

    with pytest.raises(ValueError, match="outside the case"):
        _adjudicate(case, attempt)


def test_ledger_rejects_check_credit_on_an_unsupported_report(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("not_actionable", ("object-authorization",)), B: ("not_actionable", ())})

    with pytest.raises(ValueError, match=r"ledger-v2\.schema"):
        _adjudicate(case, attempt)


def test_duplicate_must_name_a_canonical_report_that_is_not_a_duplicate(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("duplicate", ()), B: ("duplicate", ())})

    with pytest.raises(ValueError, match="not itself a duplicate"):
        _adjudicate(case, attempt)


def test_ledger_is_bound_to_the_exact_attempt_bytes(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("supported", ()), B: ("supported", ())})
    attempt.write_text(attempt.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify this attempt"):
        _adjudicate(case, attempt)


def test_ledger_is_bound_to_the_pinned_commit(case, attempt, write_ledger, benchmark_project):
    write_ledger(attempt, {A: ("supported", ()), B: ("supported", ())}, source_commit=benchmark_project.base)

    with pytest.raises(ValueError, match="does not identify this attempt"):
        _adjudicate(case, attempt)


def test_attempt_recorded_against_another_answer_key_is_rejected(case, attempt, write_ledger):
    data = json.loads(attempt.read_text(encoding="utf-8"))
    data["expected_checks"][0]["id"] = "renamed-check"
    attempt.write_text(json.dumps(data), encoding="utf-8")
    write_ledger(attempt, {A: ("supported", ()), B: ("supported", ())})

    with pytest.raises(ValueError, match="answer key differs"):
        _adjudicate(case, attempt)


def test_evidence_must_name_an_existing_line_of_the_pinned_source(case, attempt, write_ledger, benchmark_project):
    ledger = write_ledger(attempt, {A: ("supported", ()), B: ("supported", ())})
    data = json.loads(ledger.read_text(encoding="utf-8"))
    data["records"][0]["evidence"] = [{"file": "views.py", "line": 3}]
    ledger.write_text(json.dumps(data), encoding="utf-8")

    _adjudicate(case, attempt)
    with pytest.raises(ValueError, match="evidence line does not exist"):
        _adjudicate(case, attempt, benchmark_project.repo)


def test_pending_reports_are_listed(case, attempt, write_ledger):
    write_ledger(attempt, {A: ("needs_review", ()), B: ("supported", ())})

    assert _adjudicate(case, attempt).pending == (A,)


def _review_attempt(directory, reviewed_root, *, target=None):
    snapshot = capture_source_snapshot(reviewed_root)
    attempt = directory / "session" / "attempts" / ("attempt-" + "1" * 32)
    attempt.mkdir(parents=True)
    session = attempt.parent.parent
    target = target or {"kind": "repository", "repository_root": str(reviewed_root.resolve())}
    (session / "target.json").write_text(json.dumps(target), encoding="utf-8")
    (session / "snapshot.json").write_text(json.dumps(snapshot.to_dict()), encoding="utf-8")
    record = FindingRecord(
        id=A,
        title="Create saves without an owner check",
        category="missing-authorization",
        severity="HIGH",
        file="views.py",
        line=2,
        entrypoint="POST /objects",
        evidence="views.py:2 saves with no owner",
        attack_path="Any caller creates objects for another owner",
        status="candidate",
        evidence_refs=(),
        supporting_reviewers=(),
    )
    findings = FindingsArtifact.create((record,))
    outcome = OutcomeArtifact.create(
        target=target["kind"],
        source_revision=snapshot.snapshot_id,
        findings=findings,
        outcome=ReviewOutcome(findings=()),
    )
    (attempt / "findings.json").write_text(json.dumps(findings.to_dict()), encoding="utf-8")
    (attempt / "outcome.json").write_text(json.dumps(outcome.to_dict()), encoding="utf-8")
    return attempt


@pytest.fixture
def repository_case(benchmark_project):
    return find_case(benchmark_project.repository_case, [benchmark_project.manifest])


def test_recorded_repository_attempt_records_a_review_of_the_task_source(tmp_path, benchmark_project, repository_case):
    attempt = recorded_attempt(repository_case, _review_attempt(tmp_path, benchmark_project.repo), 3)

    assert attempt["case"] == repository_case.name
    assert attempt["attempt"] == 3
    assert attempt["complete"] is True
    assert [item["candidate_id"] for item in attempt["findings"]] == [A]


def test_recorded_repository_attempt_rejects_a_review_of_a_plain_directory(
    tmp_path, benchmark_project, repository_case
):
    plain = tmp_path / "plain"
    (plain / "src").mkdir(parents=True)
    (plain / "src" / "views.py").write_bytes((benchmark_project.repo / "views.py").read_bytes())

    with pytest.raises(ValueError, match="did not review the source") as error:
        recorded_attempt(repository_case, _review_attempt(tmp_path, plain), 1)

    message = str(error.value)
    assert f"the task is commit {benchmark_project.ref} scope '.'" in message
    assert "a plain directory outside any git checkout" in message
    assert "0 changed, 1 missing, and 1 extra files" in message


def test_recorded_repository_attempt_rejects_a_review_of_another_commit(tmp_path, benchmark_project, repository_case):
    other = tmp_path / "other"
    git(benchmark_project.repo, "worktree", "add", "--detach", str(other), benchmark_project.base)

    with pytest.raises(ValueError, match="did not review the source") as error:
        recorded_attempt(repository_case, _review_attempt(tmp_path, other), 1)

    message = str(error.value)
    assert f"a git checkout of commit {benchmark_project.base} scope '.'" in message
    assert "1 changed, 0 missing, and 0 extra files, for example views.py" in message


def test_recorded_repository_attempt_requires_the_review_session_snapshot(tmp_path, benchmark_project, repository_case):
    attempt = _review_attempt(tmp_path, benchmark_project.repo)
    (attempt.parent.parent / "snapshot.json").write_text(json.dumps({"snapshot_id": "0" * 64}), encoding="utf-8")

    with pytest.raises(ValueError, match="does not identify the reviewed source"):
        recorded_attempt(repository_case, attempt, 1)


def _diff_target(benchmark_project, base, ref):
    return {
        "kind": "diff",
        "repository_root": str(benchmark_project.repo),
        "git": {"patch_base_revision": base, "right_revision": ref},
    }


def test_recorded_diff_attempt_has_the_same_finding_fields_as_a_repository_attempt(
    tmp_path, benchmark_project, case, repository_case
):
    diff_target = _diff_target(benchmark_project, benchmark_project.base, benchmark_project.ref)
    diff = recorded_attempt(case, _review_attempt(tmp_path / "d", benchmark_project.repo, target=diff_target), 1)
    repository = recorded_attempt(repository_case, _review_attempt(tmp_path / "r", benchmark_project.repo), 1)

    assert diff["complete"] is True
    assert [sorted(item) for item in diff["findings"]] == [sorted(item) for item in repository["findings"]]


def test_recorded_diff_attempt_rejects_a_review_of_another_range(tmp_path, benchmark_project, case):
    other = _diff_target(benchmark_project, benchmark_project.ref, benchmark_project.ref)

    with pytest.raises(ValueError, match="did not review the change"):
        recorded_attempt(case, _review_attempt(tmp_path, benchmark_project.repo, target=other), 1)


def test_an_attempt_without_a_result_is_recorded_incomplete_with_its_failure(tmp_path, case):
    record = recorded_attempt(case, tmp_path, 2, error="provider unavailable")

    assert (record["attempt"], record["complete"], record["error"], record["findings"]) == (
        2,
        False,
        "provider unavailable",
        [],
    )
