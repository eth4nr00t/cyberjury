"""Shared result artifacts enforce one strict terminal contract."""

from dataclasses import replace

import pytest

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.result import (
    ChangeLocation,
    FindingRecord,
    FindingsArtifact,
    OutcomeArtifact,
    ReviewResultArtifact,
    findings_artifact,
)


def finding() -> FindingRecord:
    return FindingRecord(
        id="candidate-" + "1" * 20,
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
        change_anchor=ChangeLocation(file="src/handler.py", line=12, side="new"),
    )


def test_findings_round_trip_preserves_canonical_content_identity():
    artifact = FindingsArtifact.create((finding(),))

    restored = FindingsArtifact.from_dict(artifact.to_dict())

    assert restored == artifact
    assert restored.content_sha256 == FindingsArtifact.create((finding(),)).content_sha256


def test_findings_accept_retained_candidate_without_an_independent_vote():
    candidate = replace(finding(), status="candidate")
    artifact = FindingsArtifact.create((candidate,))

    assert FindingsArtifact.from_dict(artifact.to_dict()).findings[0].status == "candidate"


def test_findings_reject_a_status_no_review_produces():
    with pytest.raises(ValueError, match="finding status is invalid"):
        replace(finding(), status="blocked")


def test_findings_reject_tampered_content():
    document = FindingsArtifact.create((finding(),)).to_dict()
    document["findings"][0]["line"] = 13

    with pytest.raises(ValueError, match="content hash"):
        FindingsArtifact.from_dict(document)


def test_outcome_derives_completion_from_every_controlling_counter():
    findings = FindingsArtifact.create((finding(),))
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
    findings = FindingsArtifact.create((finding(),))
    artifact = OutcomeArtifact.create(
        target="repository",
        source_revision="b" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(), incomplete=(object(),)),
    )

    with pytest.raises(ValueError, match="completion contradicts"):
        replace(artifact, complete=True, content_sha256="0" * 64)


def test_cli_result_rejects_an_outcome_for_other_findings():
    findings = FindingsArtifact.create((finding(),))
    empty = FindingsArtifact.create(())
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

    artifact = findings_artifact([diff, repository], {diff.candidate_id})

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
    assert artifact.to_dict()["schema"] == "cyberjury.findings/v5"
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
        "change_anchor",
    }
