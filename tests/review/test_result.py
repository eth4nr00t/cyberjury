"""Shared result artifacts enforce one strict terminal contract."""

from dataclasses import replace

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.issues import Issue, issue_id
from cyberjury.review.result import (
    ChangeAnchorRecord,
    FindingRecord,
    FindingsArtifact,
    IssueRecord,
    OutcomeArtifact,
    ReviewResultArtifact,
    findings_artifact,
)

CANDIDATE = "candidate-" + "1" * 20


def finding() -> FindingRecord:
    """Return one complete candidate finding record."""
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
        evidence_refs=("evidence-1",),
        supporting_reviewers=("finder-primary",),
        issue_id=issue_id((CANDIDATE,)),
        change_anchor=ChangeAnchorRecord(file="src/handler.py", line=12, side="new"),
    )


def single(record: FindingRecord) -> FindingsArtifact:
    """Wrap one finding record in a findings artifact with its own issue."""
    issue = IssueRecord(
        id=record.issue_id,
        representative=record.id,
        members=(record.id,),
        linked_by=(),
    )
    return FindingsArtifact.create((record,), (issue,))


def test_findings_round_trip_preserves_canonical_content_identity():
    """Serializing and parsing a one-finding artifact returns an equal artifact with the same content hash."""
    artifact = single(finding())

    restored = FindingsArtifact.from_dict(artifact.to_dict())

    assert restored == artifact
    assert restored.content_sha256 == single(finding()).content_sha256


def test_findings_reject_tampered_content():
    """Changing a serialized finding's line from 12 to 13 fails loading with a content hash error."""
    document = single(finding()).to_dict()
    document["findings"][0]["line"] = 13

    with pytest.raises(ValueError, match="content hash"):
        FindingsArtifact.from_dict(document)


def test_outcome_derives_completion_from_every_controlling_counter():
    """An outcome with no incomplete items is complete, and one incomplete item makes it incomplete."""
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
    """Replacing complete=True on an outcome that has incomplete items raises "completion contradicts"."""
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
    """Pairing a one-finding artifact with an outcome built for empty findings raises "does not identify"."""
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


def test_findings_artifact_maps_every_target_onto_the_same_fields():
    """Diff and repository findings serialize to one v1 field set, with change_anchor None for the repo one."""
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

    artifact = findings_artifact([diff, repository], (Issue(members=(diff,)), Issue(members=(repository,))))

    by_file = {record.file: record for record in artifact.findings}
    assert (by_file["app.py"].title, by_file["app.py"].evidence) == (
        "record write is unauthenticated",
        "authentication was removed",
    )
    assert by_file["app.py"].change_anchor == ChangeAnchorRecord(file="middleware.py", line=8, side="old")
    assert (by_file["views.py"].title, by_file["views.py"].evidence) == (
        "missing ownership check",
        "views.py:3 returns any record",
    )
    assert (by_file["views.py"].entrypoint, by_file["views.py"].change_anchor) == ("GET /records/<id>", None)
    assert artifact.to_dict()["schema"] == "cyberjury.findings/v1"
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
        "evidence_refs",
        "supporting_reviewers",
        "issue_id",
        "change_anchor",
    }


def test_findings_artifact_records_every_member_of_a_grouped_issue_with_its_issue_id():
    """Two findings linked by location share one issue id and round-trip, and the summary counts two HIGH."""
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

    artifact = findings_artifact([first, second], (issue,))

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
    """A finding with no issue raises "partition", and adding a foreign member raises an issue id mismatch."""
    record = finding()

    with pytest.raises(ValueError, match="partition"):
        FindingsArtifact.create((record,), ())
    with pytest.raises(ValueError, match="issue id does not match"):
        replace(single(record).issues[0], members=(record.id, "candidate-" + "2" * 20))
