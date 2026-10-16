"""Shared result artifacts enforce one strict terminal contract."""

from dataclasses import replace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.issues import Issue, issue_id
from cyberjury.review.result import (
    ChangeLocation,
    FindingRecord,
    FindingsArtifact,
    IssueRecord,
    OutcomeArtifact,
    ReviewResultArtifact,
    findings_artifact,
)

CANDIDATE = "candidate-" + "1" * 20


def finding() -> FindingRecord:
    return FindingRecord(
        id=CANDIDATE,
        title="Object access lacks an ownership check",
        category="authorization",
        severity="HIGH",
        file="src/handler.py",
        line=12,
        entrypoint="GET /objects/{id}",
        evidence="The handler loads the object by request id and returns it directly.",
        attack_path="An authenticated user supplies another user's object id.",
        status="confirmed",
        evidence_refs=("evidence-1",),
        supporting_reviewers=("finder-primary",),
        issue_id=issue_id((CANDIDATE,)),
        change_anchor=ChangeLocation(file="src/handler.py", line=12, side="new"),
    )


def single(record: FindingRecord) -> FindingsArtifact:
    issue = IssueRecord(
        id=record.issue_id,
        representative=record.id,
        members=(record.id,),
        linked_by=(),
    )
    return FindingsArtifact.create((record,), (issue,))


def test_findings_round_trip_preserves_canonical_content_identity():
    artifact = single(finding())

    restored = FindingsArtifact.from_dict(artifact.to_dict())

    assert restored == artifact
    assert restored.content_sha256 == single(finding()).content_sha256


def test_findings_accept_retained_candidate_without_an_independent_vote():
    candidate = replace(finding(), status="candidate")
    artifact = single(candidate)

    assert FindingsArtifact.from_dict(artifact.to_dict()).findings[0].status == "candidate"


def test_findings_reject_a_status_no_review_produces():
    with pytest.raises(ValueError, match="finding status is invalid"):
        replace(finding(), status="blocked")


def test_findings_reject_tampered_content():
    document = single(finding()).to_dict()
    document["findings"][0]["line"] = 13

    with pytest.raises(ValueError, match="content hash"):
        FindingsArtifact.from_dict(document)


def test_outcome_derives_completion_from_every_controlling_counter():
    findings = single(finding())
    complete = OutcomeArtifact.create(
        target="diff",
        source_revision="a" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(object(),)),
    )
    incomplete = OutcomeArtifact.create(
        target="diff",
        source_revision="a" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(object(),), incomplete=(object(),)),
    )

    assert complete.complete is True
    assert incomplete.complete is False


def test_outcome_rejects_a_forged_complete_state():
    findings = single(finding())
    artifact = OutcomeArtifact.create(
        target="repository",
        source_revision="b" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(), incomplete=(object(),)),
    )

    with pytest.raises(ValueError, match="completion contradicts"):
        replace(artifact, complete=True, content_sha256="0" * 64)


def test_cli_result_rejects_an_outcome_for_other_findings():
    findings = single(finding())
    empty = FindingsArtifact.create((), ())
    outcome = OutcomeArtifact.create(
        target="diff",
        source_revision="d" * 64,
        findings=empty,
        outcome=ReviewOutcome(findings=()),
    )

    with pytest.raises(ValueError, match="does not identify"):
        ReviewResultArtifact(
            review_id="review-" + "1" * 32,
            attempt_id="attempt-" + "2" * 32,
            findings=findings,
            outcome=outcome,
        )


def test_findings_artifact_maps_every_target_onto_the_same_fields_and_marks_only_verified_findings():
    diff = Finding(
        title="record write is unauthenticated",
        file="app.py",
        line=20,
        severity="HIGH",
        category="missing-authorization",
        entrypoint="POST /records",
        evidence="authentication was removed",
        attack_path="anyone posts a record",
        change_anchor=ChangeAnchor(file="middleware.py", line=8, side="old"),
    )
    repository = Finding(
        title="missing ownership check",
        file="views.py",
        line=3,
        severity="MEDIUM",
        category="idor",
        entrypoint="GET /records/<id>",
        evidence="views.py:3 returns any record",
        attack_path="a member reads another record",
    )

    artifact = findings_artifact(
        [diff, repository], {diff.candidate_id}, (Issue(members=(diff,)), Issue(members=(repository,)))
    )

    by_file = {record.file: record for record in artifact.findings}
    assert (by_file["app.py"].title, by_file["app.py"].evidence, by_file["app.py"].status) == (
        "record write is unauthenticated",
        "authentication was removed",
        "confirmed",
    )
    assert by_file["app.py"].change_anchor == ChangeLocation(file="middleware.py", line=8, side="old")
    assert (by_file["views.py"].title, by_file["views.py"].evidence, by_file["views.py"].status) == (
        "missing ownership check",
        "views.py:3 returns any record",
        "candidate",
    )
    assert (by_file["views.py"].entrypoint, by_file["views.py"].change_anchor) == ("GET /records/<id>", None)
    assert artifact.to_dict()["schema"] == "cyberjury.findings/v6"
    assert set(artifact.to_dict()["findings"][0]) == {
        "id",
        "title",
        "category",
        "severity",
        "file",
        "line",
        "entrypoint",
        "evidence",
        "attack_path",
        "status",
        "evidence_refs",
        "supporting_reviewers",
        "issue_id",
        "change_anchor",
    }


def test_findings_artifact_records_every_member_of_a_grouped_issue_with_its_issue_id():
    first = Finding(
        title="share link grants another user's document",
        file="serialisers.py",
        line=1602,
        severity="HIGH",
        category="idor",
        entrypoint="POST /share_links",
        evidence="serialisers.py:1602 accepts any document",
        attack_path="a member shares another user's document",
    )
    second = replace(first, title="share link creation lacks a document check")
    issue = Issue(members=(first, second), linked_by=("location",))

    artifact = findings_artifact([first, second], set(), (issue,))

    assert [record.issue_id for record in artifact.findings] == [issue.id, issue.id]
    assert artifact.issues == (
        IssueRecord(
            id=issue.id,
            representative=first.candidate_id,
            members=(first.candidate_id, second.candidate_id),
            linked_by=("location",),
        ),
    )
    assert FindingsArtifact.from_dict(artifact.to_dict()) == artifact
    assert artifact.summary == (("CRITICAL", 0), ("HIGH", 2), ("MEDIUM", 0), ("LOW", 0))


def test_findings_artifact_rejects_issues_that_do_not_partition_its_findings():
    record = finding()

    with pytest.raises(ValueError, match="partition"):
        FindingsArtifact.create((record,), ())
    with pytest.raises(ValueError, match="issue id does not match"):
        replace(single(record).issues[0], members=(record.id, "candidate-" + "2" * 20))
