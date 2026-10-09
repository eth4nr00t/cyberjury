"""Issue sidecars preserve findings while binding source backed grouping."""

import hashlib
import json
from dataclasses import dataclass

import pytest

from cyberjury.review.adjudication import (
    CoverageVote,
    GroupRelation,
    RootAssessment,
)
from cyberjury.review.claims import ClaimRecord
from cyberjury.review.consolidation import (
    ConsolidationReceipt,
    CoverageDecision,
    CoverageLink,
    IssueSearchResult,
    ResidualOperation,
)
from cyberjury.review.context import SourceEvidence, SourceSpan
from cyberjury.review.grouping import IssueConsolidationResult, IssueJudgmentFailure
from cyberjury.review.issues import IssuesArtifact
from cyberjury.review.result import FindingRecord, FindingsArtifact


@dataclass(frozen=True)
class _Candidate:
    id: str
    file: str
    line: int | None
    evidence: str
    status: str = "candidate"

    @property
    def claim_records(self) -> tuple[ClaimRecord, ...]:
        return (
            ClaimRecord.create(
                self.id,
                {"file": self.file, "line": self.line, "evidence": self.evidence, "evidence_refs": ["src-shared"]},
            ),
        )


def _record(candidate: _Candidate) -> FindingRecord:
    return FindingRecord(
        id=candidate.id,
        category="missing-authorization",
        decision_rule_id="missing-authorization-action",
        severity="HIGH",
        file=candidate.file,
        line=candidate.line,
        entrypoint="POST /records",
        summary=candidate.evidence,
        evidence=candidate.evidence,
        attack_path="caller reaches the unchecked write",
        recommendation="",
        status="confirmed",
        evidence_refs=("src-shared",),
        supporting_reviewers=("finder",),
    )


def _fixture():
    root = _Candidate("candidate-" + "a" * 20, "app.py", 5, "root report")
    child = _Candidate("candidate-" + "b" * 20, "app.py", 12, "child report")
    candidates = (root, child)
    source = (
        SourceEvidence(
            id="src-shared",
            identity="app.py:1-20",
            text="1 | def handler():\n5 | check_access()\n12 | write_target()",
            source_span=SourceSpan(file="app.py", start_line=1, end_line=20),
        ),
    )
    decision = CoverageDecision(
        candidate_id=child.id,
        root_link=CoverageLink(
            root_id=root.id,
            operation_file="app.py",
            operation_line=5,
            evidence_refs=("src-shared",),
            reason="the same source control covers the child",
        ),
        reason="both reports need one access check",
    )
    receipt = ConsolidationReceipt.create(
        candidates,
        (decision,),
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )
    findings = FindingsArtifact.create(tuple(_record(item) for item in candidates))
    return candidates, source, receipt, findings


def _create(candidates, source, receipt, findings, *, unresolved=frozenset()):
    relations = tuple(
        GroupRelation(candidate_id=decision.candidate_id, root_id=decision.root_link.root_id, status="covered")
        for decision in receipt.decisions
    )
    votes = tuple(
        CoverageVote(
            role=role,
            candidate_id=relation.candidate_id,
            covered=True,
            reason="same source control",
            root_assessments=(
                RootAssessment(
                    root_id=relation.root_id,
                    relation="covers_part",
                    reason="same source control",
                    operation_file="app.py",
                    operation_line=5,
                    evidence_refs=("src-shared",),
                ),
            ),
        )
        for relation in relations
        for role in ("issue-coverage", "issue-coverage-skeptic")
    )
    return IssuesArtifact.create(
        findings,
        candidates,
        receipt,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=source,
        unresolved_ids=unresolved,
        relations=relations,
        votes=votes,
    )


def test_issue_sidecar_groups_two_reports_without_changing_findings():
    candidates, source, receipt, findings = _fixture()

    sidecar = _create(candidates, source, receipt, findings)

    assert len(findings.findings) == 2
    assert len(sidecar.issues) == 1
    assert sidecar.issues[0].representative_id == candidates[0].id
    assert sidecar.issues[0].member_ids == tuple(sorted(item.id for item in candidates))
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()
    assert "findings" not in sidecar.to_dict()


def test_unresolved_coverage_keeps_both_original_reports_visible():
    candidates, source, receipt, findings = _fixture()

    sidecar = _create(candidates, source, receipt, findings, unresolved=frozenset({candidates[1].id}))

    assert len(sidecar.issues) == 2
    assert {issue.representative_id for issue in sidecar.issues} == {item.id for item in candidates}
    assert sidecar.unresolved_ids == (candidates[1].id,)


@pytest.mark.parametrize(
    ("status", "assessment", "unresolved"),
    [("independent", "unrelated", False), ("uncertain", "uncertain", True)],
)
def test_one_retaining_vote_preserves_both_candidates(status, assessment, unresolved):
    candidates, source, receipt, findings = _fixture()
    relation = GroupRelation(candidate_id=candidates[1].id, root_id=candidates[0].id, status=status)
    vote = CoverageVote(
        role="issue-coverage",
        candidate_id=candidates[1].id,
        covered=False,
        reason="the first review does not prove complete coverage",
        root_assessments=(
            RootAssessment(
                root_id=candidates[0].id,
                relation=assessment,
                reason="the first review does not prove complete coverage",
                operation_file="",
                operation_line=0,
                evidence_refs=(),
            ),
        ),
    )
    empty = ConsolidationReceipt.create(
        candidates,
        (),
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )

    sidecar = IssuesArtifact.create(
        findings,
        candidates,
        empty,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=source,
        unresolved_ids=frozenset({candidates[1].id}) if unresolved else frozenset(),
        relations=(relation,),
        votes=(vote,),
    )

    assert len(sidecar.issues) == 2
    assert len(sidecar.votes) == 1
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()


def test_reverse_coverage_retains_both_directional_votes_and_original_findings():
    candidates, source, _receipt, findings = _fixture()
    narrow, broad = candidates
    link = CoverageLink(
        root_id=broad.id,
        operation_file="app.py",
        operation_line=12,
        evidence_refs=("src-shared",),
        reason="the broader source control covers the narrower report",
    )
    decision = CoverageDecision(
        candidate_id=narrow.id,
        root_link=link,
        reason="the reverse direction covers the original report",
    )
    relations = (
        GroupRelation(candidate_id=broad.id, root_id=narrow.id, status="uncertain"),
        GroupRelation(candidate_id=narrow.id, root_id=broad.id, status="covered"),
    )
    votes = tuple(
        CoverageVote(
            role=role,
            candidate_id=candidate_id,
            covered=covered,
            reason="source checked in this direction",
            root_assessments=(
                RootAssessment(
                    root_id=root_id,
                    relation="covers_part" if covered else "uncertain",
                    reason="source checked in this direction",
                    operation_file="app.py" if covered else "",
                    operation_line=12 if covered else 0,
                    evidence_refs=("src-shared",) if covered else (),
                ),
            ),
        )
        for candidate_id, root_id, covered in ((broad.id, narrow.id, False), (narrow.id, broad.id, True))
        for role in ("issue-coverage", "issue-coverage-skeptic")
    )
    result = IssueConsolidationResult(
        search=IssueSearchResult(neighborhoods=(), uncovered_pairs=()),
        decisions=(decision,),
        relations=relations,
        votes=votes,
        source_evidence=source,
        unresolved_ids=frozenset(),
        failures=(),
    )

    sidecar = IssuesArtifact.from_consolidation(
        findings,
        candidates,
        result,
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
    )

    assert len(findings.findings) == 2
    assert [(item.representative_id, item.member_ids) for item in sidecar.issues] == [
        (broad.id, tuple(sorted((narrow.id, broad.id))))
    ]
    assert len(sidecar.relations) == 2
    assert len(sidecar.votes) == 4
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()


def test_refuted_candidate_does_not_appear_in_final_issue_groups():
    candidates, source, receipt, _findings = _fixture()
    findings = FindingsArtifact.create((_record(candidates[0]),))

    sidecar = _create(candidates, source, receipt, findings)

    assert len(sidecar.issues) == 1
    assert sidecar.issues[0].member_ids == (candidates[0].id,)
    dropped = next(item for item in sidecar.candidates if item.candidate_id == candidates[1].id)
    assert not dropped.survived
    assert (dropped.file, dropped.line) == (candidates[1].file, candidates[1].line)
    assert dropped.claims[0].report["evidence"] == candidates[1].evidence
    assert dropped.claims[0].report["evidence_refs"] == ["src-shared"]
    assert dropped.status == "candidate"
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()


def test_unlocatable_candidate_keeps_its_empty_location_and_original_claim():
    candidates, source, receipt, findings = _fixture()
    unlocatable = _Candidate("candidate-" + "c" * 20, "", None, "location not established", "blocked")
    all_candidates = (*candidates, unlocatable)
    receipt = ConsolidationReceipt.create(
        all_candidates,
        receipt.decisions,
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )

    sidecar = _create(all_candidates, source, receipt, findings)

    record = next(item for item in sidecar.candidates if item.candidate_id == unlocatable.id)
    assert (record.file, record.line, record.status, record.survived) == ("", None, "blocked", False)
    assert record.claims[0].report["evidence"] == "location not established"
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()


def test_refuted_coverage_root_reopens_the_surviving_child():
    candidates, source, receipt, findings = _fixture()
    complete = _create(candidates, source, receipt, findings)
    result = IssueConsolidationResult(
        search=complete.search,
        decisions=receipt.decisions,
        relations=complete.relations,
        votes=complete.votes,
        source_evidence=source,
        unresolved_ids=frozenset(),
        failures=(),
    )
    surviving = FindingsArtifact.create((_record(candidates[1]),))

    reopened = IssuesArtifact.from_consolidation(
        surviving,
        candidates,
        result,
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
    )

    assert reopened.unresolved_ids == (candidates[1].id,)
    assert [(item.representative_id, item.member_ids) for item in reopened.issues] == [
        (candidates[1].id, (candidates[1].id,))
    ]
    assert IssuesArtifact.from_dict(reopened.to_dict(), findings=surviving).to_dict() == reopened.to_dict()


def test_issue_sidecar_rejects_changed_findings_evidence_and_group_membership():
    candidates, source, receipt, findings = _fixture()
    sidecar = _create(candidates, source, receipt, findings)
    payload = sidecar.to_dict()
    different = FindingsArtifact.create((_record(candidates[0]),))

    with pytest.raises(ValueError, match="does not identify the supplied findings"):
        IssuesArtifact.from_dict(payload, findings=different)
    changed_evidence = {**payload, "source_evidence": [{**payload["source_evidence"][0], "text": "changed"}]}
    with pytest.raises(ValueError, match="source evidence does not match"):
        IssuesArtifact.from_dict(changed_evidence, findings=findings)
    changed_groups = {**payload, "issues": [{**payload["issues"][0], "member_ids": [candidates[0].id]}]}
    with pytest.raises(ValueError, match="groups contradict"):
        IssuesArtifact.from_dict(changed_groups, findings=findings)
    changed_candidate = json.loads(json.dumps(payload))
    changed_candidate["candidates"][0]["line"] += 1
    with pytest.raises(ValueError, match="content hash"):
        IssuesArtifact.from_dict(changed_candidate, findings=findings)


def test_issue_sidecar_rejects_a_positive_relation_without_two_positive_votes():
    candidates, source, receipt, findings = _fixture()
    payload = json.loads(json.dumps(_create(candidates, source, receipt, findings).to_dict()))
    payload["votes"][0]["covered"] = False

    with pytest.raises(ValueError, match="lacks two positive votes"):
        IssuesArtifact.from_dict(payload, findings=findings)


def test_issue_sidecar_rejects_a_covered_relation_without_its_decision():
    candidates, source, receipt, findings = _fixture()
    complete = _create(candidates, source, receipt, findings)
    empty = ConsolidationReceipt.create(
        candidates,
        (),
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )

    with pytest.raises(ValueError, match="loses an accepted group judgment"):
        IssuesArtifact.create(
            findings,
            candidates,
            empty,
            candidate_id=lambda item: item.id,
            candidate_location=lambda item: (item.file, item.line),
            source_evidence=source,
            relations=complete.relations,
            votes=complete.votes,
        )


def test_issue_sidecar_rejects_partial_relation_with_two_full_votes():
    candidates, source, receipt, findings = _fixture()
    empty = ConsolidationReceipt.create(
        candidates,
        (),
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )
    partial_link = receipt.decisions[0].root_link
    relation = GroupRelation(
        candidate_id=candidates[1].id,
        root_id=candidates[0].id,
        status="partial",
        partial_link=partial_link,
    )
    votes = tuple(
        CoverageVote(
            role=role,
            candidate_id=candidates[1].id,
            covered=False,
            reason=partial_link.reason,
            root_assessments=(
                RootAssessment(
                    root_id=candidates[0].id,
                    relation="covers_part",
                    reason=partial_link.reason,
                    operation_file=partial_link.operation_file,
                    operation_line=partial_link.operation_line,
                    evidence_refs=partial_link.evidence_refs,
                ),
            ),
        )
        for role in ("issue-coverage", "issue-coverage-skeptic")
    )
    sidecar = IssuesArtifact.create(
        findings,
        candidates,
        empty,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=source,
        unresolved_ids=frozenset({candidates[1].id}),
        relations=(relation,),
        votes=votes,
    )
    payload = sidecar.to_dict()
    for vote in payload["votes"]:
        vote["covered"] = True
    semantic = {key: value for key, value in payload.items() if key != "content_sha256"}
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    with pytest.raises(ValueError, match="two full votes"):
        IssuesArtifact.from_dict(payload, findings=findings)


def test_issue_sidecar_preserves_a_single_retaining_partial_vote():
    candidates, source, receipt, findings = _fixture()
    empty = ConsolidationReceipt.create(
        candidates,
        (),
        source_revision=receipt.source_revision,
        adjudicator_revision=receipt.adjudicator_revision,
        candidate_id=lambda item: item.id,
        source_evidence=source,
    )
    link = receipt.decisions[0].root_link
    residual = ResidualOperation(
        file=candidates[1].file,
        line=candidates[1].line,
        evidence_refs=("src-shared",),
        reason="the child has a separately necessary operation",
    )
    relation = GroupRelation(
        candidate_id=candidates[1].id,
        root_id=candidates[0].id,
        status="partial",
        partial_link=link,
        residual_operation=residual,
    )
    vote = CoverageVote(
        role="issue-coverage",
        candidate_id=candidates[1].id,
        covered=False,
        reason=link.reason,
        root_assessments=(
            RootAssessment(
                root_id=link.root_id,
                relation="covers_part",
                reason=link.reason,
                operation_file=link.operation_file,
                operation_line=link.operation_line,
                evidence_refs=link.evidence_refs,
            ),
        ),
        residual_operation=residual,
    )
    sidecar = IssuesArtifact.create(
        findings,
        candidates,
        empty,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
        source_evidence=source,
        unresolved_ids=frozenset({candidates[1].id}),
        relations=(relation,),
        votes=(vote,),
    )

    assert len(sidecar.issues) == 2
    assert sidecar.unresolved_ids == (candidates[1].id,)
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()
    tampered = json.loads(json.dumps(sidecar.to_dict()))
    tampered["votes"][0]["covered"] = True
    semantic = {key: value for key, value in tampered.items() if key != "content_sha256"}
    tampered["content_sha256"] = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="two votes or one retaining vote"):
        IssuesArtifact.from_dict(tampered, findings=findings)


def test_issue_sidecar_rejects_votes_on_different_repair_operations():
    candidates, source, receipt, findings = _fixture()
    payload = json.loads(json.dumps(_create(candidates, source, receipt, findings).to_dict()))
    payload["votes"][1]["root_assessments"][0]["operation_line"] = 6
    semantic = {key: value for key, value in payload.items() if key != "content_sha256"}
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()

    with pytest.raises(ValueError, match="do not agree on the cited repair operation"):
        IssuesArtifact.from_dict(payload, findings=findings)


def test_failed_group_is_recorded_without_removing_its_finding():
    candidates, _source, _receipt, findings = _fixture()
    result = IssueConsolidationResult(
        search=IssueSearchResult(neighborhoods=(), uncovered_pairs=()),
        decisions=(),
        relations=(),
        votes=(),
        source_evidence=(),
        unresolved_ids=frozenset({candidates[1].id}),
        failures=(IssueJudgmentFailure(candidate_ids=(candidates[1].id,), reason="model reply failed"),),
    )

    sidecar = IssuesArtifact.from_consolidation(
        findings,
        candidates,
        result,
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
    )

    assert len(sidecar.issues) == 2
    assert sidecar.unresolved_ids == (candidates[1].id,)
    assert sidecar.to_dict()["failures"] == [{"candidate_ids": [candidates[1].id], "reason": "model reply failed"}]
    assert IssuesArtifact.from_dict(sidecar.to_dict(), findings=findings).to_dict() == sidecar.to_dict()


def test_issue_sidecar_rejects_a_failure_outside_the_original_candidate_set():
    missing_id = "candidate-" + "d" * 20
    result = IssueConsolidationResult(
        search=IssueSearchResult(neighborhoods=(), uncovered_pairs=()),
        decisions=(),
        relations=(),
        votes=(),
        source_evidence=(),
        unresolved_ids=frozenset(),
        failures=(IssueJudgmentFailure(candidate_ids=(missing_id,), reason="unrelated failure"),),
    )

    with pytest.raises(ValueError, match="unknown candidate"):
        IssuesArtifact.from_consolidation(
            FindingsArtifact.create(()),
            (),
            result,
            source_revision="a" * 64,
            adjudicator_revision="b" * 64,
            candidate_id=lambda item: item.id,
            candidate_location=lambda item: (item.file, item.line),
        )


def test_later_full_coverage_replaces_partial_work_and_reopens_if_its_root_is_refuted():
    first = _Candidate("candidate-" + "a" * 20, "app.py", 2, "first repair")
    child = _Candidate("candidate-" + "b" * 20, "app.py", 4, "complete claim")
    second = _Candidate("candidate-" + "c" * 20, "app.py", 5, "second repair")
    candidates = (first, child, second)
    source = (
        SourceEvidence(
            id="src-shared",
            identity="app.py:1-10",
            text="2 | first()\n4 | child()\n5 | second()",
            source_span=SourceSpan(file="app.py", start_line=1, end_line=10),
        ),
    )
    partial = CoverageLink(
        root_id=first.id,
        operation_file="app.py",
        operation_line=2,
        evidence_refs=("src-shared",),
        reason="only one part overlaps",
    )
    complete = CoverageLink(
        root_id=second.id,
        operation_file="app.py",
        operation_line=5,
        evidence_refs=("src-shared",),
        reason="the complete child claim uses this repair",
    )
    decision = CoverageDecision(candidate_id=child.id, root_link=complete, reason="the second root covers every claim")
    relations = (
        GroupRelation(candidate_id=child.id, root_id=first.id, status="partial", partial_link=partial),
        GroupRelation(candidate_id=child.id, root_id=second.id, status="covered"),
    )
    votes = tuple(
        CoverageVote(
            role=role,
            candidate_id=child.id,
            covered=link is complete,
            reason=link.reason,
            root_assessments=(
                RootAssessment(
                    root_id=link.root_id,
                    relation="covers_part",
                    reason=link.reason,
                    operation_file=link.operation_file,
                    operation_line=link.operation_line,
                    evidence_refs=link.evidence_refs,
                ),
            ),
        )
        for link in (partial, complete)
        for role in ("issue-coverage", "issue-coverage-skeptic")
    )
    result = IssueConsolidationResult(
        search=IssueSearchResult(neighborhoods=(), uncovered_pairs=()),
        decisions=(decision,),
        relations=relations,
        votes=votes,
        source_evidence=source,
        unresolved_ids=frozenset(),
        failures=(),
    )
    original_findings = FindingsArtifact.create(tuple(_record(item) for item in candidates))

    grouped = IssuesArtifact.from_consolidation(
        original_findings,
        candidates,
        result,
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
    )

    assert len(original_findings.findings) == 3
    assert grouped.unresolved_ids == ()
    assert [(item.representative_id, item.member_ids) for item in grouped.issues] == [
        (first.id, (first.id,)),
        (second.id, (child.id, second.id)),
    ]
    assert IssuesArtifact.from_dict(grouped.to_dict(), findings=original_findings).to_dict() == grouped.to_dict()

    surviving = FindingsArtifact.create((_record(first), _record(child)))
    reopened = IssuesArtifact.from_consolidation(
        surviving,
        candidates,
        result,
        source_revision="a" * 64,
        adjudicator_revision="b" * 64,
        candidate_id=lambda item: item.id,
        candidate_location=lambda item: (item.file, item.line),
    )

    assert reopened.unresolved_ids == (child.id,)
    assert {item.representative_id for item in reopened.issues} == {first.id, child.id}
    assert IssuesArtifact.from_dict(reopened.to_dict(), findings=surviving).to_dict() == reopened.to_dict()
