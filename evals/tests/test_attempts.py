"""Recorded attempts must come from a review of exactly the case source."""

from __future__ import annotations

import json

import pytest

from cyberjury.record import Record
from cyberjury.review.issues import issue_id
from cyberjury.review.result import FindingRecord, FindingsArtifact, IssueRecord
from cyberjury.sources.snapshot import capture_source_snapshot
from cyberjury.workspace import write_record
from evals.attempts import recorded_attempt
from evals.benchmarks.cases import find_case
from tests.support import git

A = "candidate-" + "a" * 20
_ATTEMPT = "attempt-20260101-000000-11111111"


def _ok(record_id, **attributes):
    return Record(
        id=record_id, status="ok", started_at="2026-01-01T00:00:00Z", duration_seconds=1.0, attributes=attributes
    )


@pytest.fixture
def case(benchmark_project):
    """Return the benchmark project's diff case."""
    return find_case(benchmark_project.diff_case, [benchmark_project.benchmark])


def _review_attempt(directory, reviewed_root, *, target=None):
    snapshot = capture_source_snapshot(reviewed_root)
    attempt = directory / "session" / "attempts" / _ATTEMPT
    (attempt / "stages").mkdir(parents=True)
    session = attempt.parent.parent
    target = target or {"kind": "repository", "repository_root": str(reviewed_root.resolve())}
    for name, value in (("target/target.json", target), ("source/snapshot.json", snapshot.to_dict())):
        (session / name).parent.mkdir(exist_ok=True)
        (session / name).write_text(json.dumps(value), encoding="utf-8")
    write_record(attempt / "stages" / "source.json", _ok("source", snapshot=snapshot.snapshot_id))
    write_record(attempt / "record.json", _ok(_ATTEMPT))
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
    (attempt / "findings.json").write_text(json.dumps(findings.to_dict()), encoding="utf-8")
    return attempt


@pytest.fixture
def repository_case(benchmark_project):
    """Return the benchmark project's repository case."""
    return find_case(benchmark_project.repository_case, [benchmark_project.benchmark])


def test_recorded_repository_attempt_records_a_review_of_the_case_source(tmp_path, benchmark_project, repository_case):
    """A review of the pinned repo records attempt 3 as complete with finding A in a single issue."""
    attempt = recorded_attempt(repository_case, _review_attempt(tmp_path, benchmark_project.repo), 3)

    assert attempt["case"] == repository_case.name
    assert attempt["attempt"] == 3
    assert attempt["complete"] is True
    assert [item["candidate_id"] for item in attempt["findings"]] == [A]
    assert [issue["members"] for issue in attempt["issues"]] == [[A]]


def test_recorded_repository_attempt_rejects_a_review_of_a_plain_directory(
    tmp_path, benchmark_project, repository_case
):
    """A non-git copy of views.py under src/ fails, naming the plain directory and the file mismatch."""
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
    """A worktree at the base commit fails, reporting views.py as the 1 changed file."""
    other = tmp_path / "other"
    git(benchmark_project.repo, "worktree", "add", "--detach", str(other), benchmark_project.base)

    with pytest.raises(ValueError, match="did not review the source") as error:
        recorded_attempt(repository_case, _review_attempt(tmp_path, other), 1)

    message = str(error.value)
    assert f"a git checkout of commit {benchmark_project.base} path '.'" in message
    assert "1 changed, 0 missing, and 0 extra files, for example views.py" in message


def test_recorded_repository_attempt_requires_the_review_session_snapshot(tmp_path, benchmark_project, repository_case):
    """A session source/snapshot.json with an all-zero snapshot_id raises "does not identify the reviewed source"."""
    attempt = _review_attempt(tmp_path, benchmark_project.repo)
    (attempt.parent.parent / "source" / "snapshot.json").write_text(
        json.dumps({"snapshot_id": "0" * 64}), encoding="utf-8"
    )

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
    """A base..commit diff review records findings with the same keys as a repository review."""
    diff_target = _diff_target(benchmark_project, benchmark_project.base, benchmark_project.commit)
    diff = recorded_attempt(case, _review_attempt(tmp_path / "d", benchmark_project.repo, target=diff_target), 1)
    repository = recorded_attempt(repository_case, _review_attempt(tmp_path / "r", benchmark_project.repo), 1)

    assert diff["complete"] is True
    assert [sorted(item) for item in diff["findings"]] == [sorted(item) for item in repository["findings"]]


def test_recorded_diff_attempt_rejects_a_review_of_another_range(tmp_path, benchmark_project, case):
    """A diff target of commit..commit instead of base..commit raises "did not review the change"."""
    other = _diff_target(benchmark_project, benchmark_project.commit, benchmark_project.commit)

    with pytest.raises(ValueError, match="did not review the change"):
        recorded_attempt(case, _review_attempt(tmp_path, benchmark_project.repo, target=other), 1)


def test_an_attempt_without_a_result_is_recorded_incomplete_with_its_failure(tmp_path, case):
    """An attempt directory with no outputs and error "provider unavailable" records attempt 2 incomplete."""
    record = recorded_attempt(case, tmp_path, 2, error="provider unavailable")

    assert (record["attempt"], record["complete"], record["error"], record["findings"]) == (
        2,
        False,
        "provider unavailable",
        [],
    )
