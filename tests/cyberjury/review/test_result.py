"""Shared result artifacts enforce one strict terminal contract."""

from dataclasses import replace

import pytest

from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.result import (
    ChangeLocation,
    FindingRecord,
    FindingsArtifact,
    OutcomeArtifact,
    ReviewResultArtifact,
)


def finding() -> FindingRecord:
    return FindingRecord(
        id="candidate-" + "1" * 20,
        category="authorization",
        decision_rule_id="authorization-object-scope",
        severity="HIGH",
        file="src/handler.py",
        line=12,
        entrypoint="GET /objects/{id}",
        summary="Object access lacks an ownership check",
        evidence="The handler loads the object by request id and returns it directly.",
        attack_path="An authenticated user supplies another user's object id.",
        recommendation="Scope the lookup to the authenticated principal.",
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
        outcome=ReviewOutcome(findings=(object(),), requires_convergence=False),
    )
    incomplete = OutcomeArtifact.create(
        target="diff",
        source_revision="a" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(object(),), incomplete=(object(),), requires_convergence=False),
    )

    assert complete.complete is True
    assert complete.status == "complete"
    assert incomplete.complete is False
    assert incomplete.status == "incomplete"


def test_outcome_rejects_a_forged_complete_state():
    findings = FindingsArtifact.create((finding(),))
    artifact = OutcomeArtifact.create(
        target="repository",
        source_revision="b" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(), incomplete=(object(),), requires_convergence=False),
    )

    with pytest.raises(ValueError, match="completion contradicts"):
        replace(artifact, complete=True, status="complete", content_sha256="0" * 64)


def test_cli_result_round_trip_binds_findings_to_outcome():
    findings = FindingsArtifact.create((finding(),))
    outcome = OutcomeArtifact.create(
        target="diff",
        source_revision="c" * 64,
        findings=findings,
        outcome=ReviewOutcome(findings=(object(),), requires_convergence=False),
    )
    result = ReviewResultArtifact(
        review_id="review-" + "1" * 32,
        attempt_id="attempt-" + "2" * 32,
        findings=findings,
        outcome=outcome,
    )

    assert ReviewResultArtifact.from_dict(result.to_dict()) == result


def test_cli_result_rejects_an_outcome_for_other_findings():
    findings = FindingsArtifact.create((finding(),))
    empty = FindingsArtifact.create(())
    outcome = OutcomeArtifact.create(
        target="diff",
        source_revision="d" * 64,
        findings=empty,
        outcome=ReviewOutcome(findings=(), requires_convergence=False),
    )

    with pytest.raises(ValueError, match="does not identify"):
        ReviewResultArtifact(
            review_id="review-" + "1" * 32,
            attempt_id="attempt-" + "2" * 32,
            findings=findings,
            outcome=outcome,
        )
