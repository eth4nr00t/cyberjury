"""Recorded attempts must come from a review of exactly the case source."""

from __future__ import annotations

import json

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.issues import issue_id
from cyberjury.review.result import FindingRecord, FindingsArtifact, IssueRecord, OutcomeArtifact
from cyberjury.sources.snapshot import capture_source_snapshot
from evals.attempts import recorded_attempt
from evals.benchmarks.cases import find_case
from tests.support import git

A = "candidate-" + "a" * 20


@pytest.fixture
def case(benchmark_project):
    return find_case(benchmark_project.diff_case, [benchmark_project.benchmark])


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
        evidence_refs=(),
        supporting_reviewers=(),
        issue_id=issue_id((A,)),
    )
    issue = IssueRecord(
        id=record.issue_id,
        representative=record.id,
        members=(record.id,),
        linked_by=(),
    )
    findings = FindingsArtifact.create((record,), (issue,))
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
    return find_case(benchmark_project.repository_case, [benchmark_project.benchmark])


def test_recorded_repository_attempt_records_a_review_of_the_case_source(tmp_path, benchmark_project, repository_case):
    attempt = recorded_attempt(repository_case, _review_attempt(tmp_path, benchmark_project.repo), 3)

    assert attempt["case"] == repository_case.name
    assert attempt["attempt"] == 3
    assert attempt["complete"] is True
    assert [item["candidate_id"] for item in attempt["findings"]] == [A]
    assert [issue["members"] for issue in attempt["issues"]] == [[A]]


def test_recorded_repository_attempt_rejects_a_review_of_a_plain_directory(
    tmp_path, benchmark_project, repository_case
):
    plain = tmp_path / "plain"
    (plain / "src").mkdir(parents=True)
    (plain / "src" / "views.py").write_bytes((benchmark_project.repo / "views.py").read_bytes())

    with pytest.raises(ValueError, match="did not review the source") as error:
        recorded_attempt(repository_case, _review_attempt(tmp_path, plain), 1)

    message = str(error.value)
    assert f"the case is commit {benchmark_project.commit}, but" in message
    assert "a plain directory outside any git checkout" in message
    assert "0 changed, 1 missing, and 1 extra files" in message


def test_recorded_repository_attempt_rejects_a_review_of_another_commit(tmp_path, benchmark_project, repository_case):
    other = tmp_path / "other"
    git(benchmark_project.repo, "worktree", "add", "--detach", str(other), benchmark_project.base)

    with pytest.raises(ValueError, match="did not review the source") as error:
        recorded_attempt(repository_case, _review_attempt(tmp_path, other), 1)

    message = str(error.value)
    assert f"a git checkout of commit {benchmark_project.base} path '.'" in message
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
    diff_target = _diff_target(benchmark_project, benchmark_project.base, benchmark_project.commit)
    diff = recorded_attempt(case, _review_attempt(tmp_path / "d", benchmark_project.repo, target=diff_target), 1)
    repository = recorded_attempt(repository_case, _review_attempt(tmp_path / "r", benchmark_project.repo), 1)

    assert diff["complete"] is True
    assert [sorted(item) for item in diff["findings"]] == [sorted(item) for item in repository["findings"]]


def test_recorded_diff_attempt_rejects_a_review_of_another_range(tmp_path, benchmark_project, case):
    other = _diff_target(benchmark_project, benchmark_project.commit, benchmark_project.commit)

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
