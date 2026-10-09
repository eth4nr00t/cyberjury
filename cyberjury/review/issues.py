"""Persist source bound issue groups without replacing original findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from cyberjury.review.adjudication import (
    CoverageVote,
    GroupRelation,
    agreed_execution_witness,
)
from cyberjury.review.claims import ClaimRecord
from cyberjury.review.consolidation import (
    ConsolidationReceipt,
    CoverageLink,
    IssueSearchResult,
    issue_source_from_dict,
    issue_source_to_dict,
    project_issues,
    project_receipt,
    source_evidence_sha256,
)
from cyberjury.review.context import SourceEvidence
from cyberjury.review.grouping import IssueConsolidationResult, IssueJudgmentFailure
from cyberjury.review.result import FindingsArtifact

ISSUES_SCHEMA = "cyberjury.issues/v2"


def _sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _vote_key(vote: CoverageVote) -> tuple[tuple[str, ...], str, str]:
    return tuple(root.root_id for root in vote.root_assessments), vote.role, vote.candidate_id


@dataclass(frozen=True, kw_only=True)
class CandidateRecord:
    """Retain each original report even when verification removes its finding."""

    candidate_id: str
    file: str
    line: int | None
    status: str
    claims: tuple[ClaimRecord, ...]
    survived: bool

    def __post_init__(self) -> None:
        """Reject incomplete or ambiguous original candidate records."""
        if (
            not isinstance(self.candidate_id, str)
            or not self.candidate_id
            or not isinstance(self.file, str)
            or (not self.file and self.line is not None)
            or self.status not in {"candidate", "confirmed", "blocked"}
            or (
                self.line is not None
                and (isinstance(self.line, bool) or not isinstance(self.line, int) or self.line < 1)
            )
            or not isinstance(self.claims, tuple)
            or not self.claims
            or any(not isinstance(claim, ClaimRecord) for claim in self.claims)
            or not isinstance(self.survived, bool)
        ):
            raise ValueError("issue candidate record is invalid")

    def to_dict(self) -> dict[str, object]:
        """Persist original claim contents beside the candidate location."""
        return {
            "candidate_id": self.candidate_id,
            "file": self.file,
            "line": self.line,
            "status": self.status,
            "claims": [claim.to_dict() for claim in self.claims],
            "survived": self.survived,
        }

    @classmethod
    def from_dict(cls, value: object) -> CandidateRecord:
        """Reject incomplete original candidate evidence."""
        if not isinstance(value, dict) or set(value) != {
            "candidate_id",
            "file",
            "line",
            "status",
            "claims",
            "survived",
        }:
            raise ValueError("issue candidate record has an invalid shape")
        if not isinstance(value["claims"], list):
            raise ValueError("issue candidate claims must be a list")
        return cls(**{**value, "claims": tuple(ClaimRecord.from_dict(item) for item in value["claims"])})


@dataclass(frozen=True, kw_only=True)
class IssueRecord:
    """Reference every original finding represented by one adjudicated root."""

    representative_id: str
    member_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Keep issue membership canonical and inclusive of its root."""
        if (
            not isinstance(self.representative_id, str)
            or not self.representative_id
            or not self.member_ids
            or not all(isinstance(item, str) and item for item in self.member_ids)
            or self.representative_id not in self.member_ids
            or self.member_ids != tuple(sorted(set(self.member_ids)))
        ):
            raise ValueError("issue record needs a root and canonical member ids")

    def to_dict(self) -> dict[str, object]:
        """Return references into the unchanged findings artifact."""
        return {"representative_id": self.representative_id, "member_ids": list(self.member_ids)}

    @classmethod
    def from_dict(cls, value: object) -> IssueRecord:
        """Reject malformed or widened issue membership records."""
        if not isinstance(value, dict) or set(value) != {"representative_id", "member_ids"}:
            raise ValueError("issue record has an invalid shape")
        if not isinstance(value["member_ids"], list) or not all(isinstance(item, str) for item in value["member_ids"]):
            raise ValueError("issue record member ids must be a list of strings")
        return cls(representative_id=value["representative_id"], member_ids=tuple(value["member_ids"]))


@dataclass(frozen=True, kw_only=True)
class IssuesArtifact:
    """Bind a conservative issue projection to original findings and source."""

    findings: FindingsArtifact = field(repr=False, compare=False)
    candidates: tuple[CandidateRecord, ...]
    receipt: ConsolidationReceipt
    search: IssueSearchResult
    relations: tuple[GroupRelation, ...]
    votes: tuple[CoverageVote, ...]
    failures: tuple[IssueJudgmentFailure, ...]
    source_evidence: tuple[SourceEvidence, ...]
    unresolved_ids: tuple[str, ...]
    issues: tuple[IssueRecord, ...]
    content_sha256: str
    schema: str = ISSUES_SCHEMA

    def __post_init__(self) -> None:
        """Reject stale, incomplete, or contradictory issue group projections."""
        if self.schema != ISSUES_SCHEMA or not isinstance(self.findings, FindingsArtifact):
            raise ValueError("issue artifact schema or findings are invalid")
        if (
            not isinstance(self.candidates, tuple)
            or any(not isinstance(item, CandidateRecord) for item in self.candidates)
            or self.candidates != tuple(sorted(self.candidates, key=lambda item: item.candidate_id))
            or len({item.candidate_id for item in self.candidates}) != len(self.candidates)
        ):
            raise ValueError("issue artifact original candidates must use canonical order")
        final_ids = {item.id for item in self.findings.findings}
        if final_ids.difference(item.candidate_id for item in self.candidates) or any(
            candidate.survived != (candidate.candidate_id in final_ids) for candidate in self.candidates
        ):
            raise ValueError("issue artifact candidate survival does not match findings")
        if not isinstance(self.receipt, ConsolidationReceipt):
            raise ValueError("issue artifact receipt is invalid")
        if not isinstance(self.search, IssueSearchResult):
            raise ValueError("issue artifact search receipt is invalid")
        if not isinstance(self.relations, tuple) or any(not isinstance(item, GroupRelation) for item in self.relations):
            raise ValueError("issue artifact group relations are invalid")
        if not isinstance(self.votes, tuple) or any(not isinstance(item, CoverageVote) for item in self.votes):
            raise ValueError("issue artifact judgment votes are invalid")
        if not isinstance(self.failures, tuple) or any(
            not isinstance(item, IssueJudgmentFailure) for item in self.failures
        ):
            raise ValueError("issue artifact judgment failures are invalid")
        if self.relations != tuple(sorted(self.relations, key=lambda item: (item.root_id, item.candidate_id))):
            raise ValueError("issue artifact group relations must use canonical order")
        if self.votes != tuple(sorted(self.votes, key=_vote_key)):
            raise ValueError("issue artifact judgment votes must use canonical order")
        if self.failures != tuple(sorted(self.failures, key=lambda item: item.candidate_ids)):
            raise ValueError("issue artifact judgment failures must use canonical order")
        if not isinstance(self.source_evidence, tuple) or any(
            not isinstance(item, SourceEvidence) for item in self.source_evidence
        ):
            raise ValueError("issue artifact source evidence is invalid")
        if len({item.id for item in self.source_evidence}) != len(self.source_evidence):
            raise ValueError("issue artifact source evidence ids must be unique")
        if self.source_evidence != tuple(sorted(self.source_evidence, key=lambda item: item.id)):
            raise ValueError("issue artifact source evidence must use canonical order")
        if self.receipt.evidence_sha256 != source_evidence_sha256(self.source_evidence):
            raise ValueError("issue artifact source evidence does not match its receipt")
        if (
            not isinstance(self.unresolved_ids, tuple)
            or not all(isinstance(item, str) and item for item in self.unresolved_ids)
            or self.unresolved_ids != tuple(sorted(set(self.unresolved_ids)))
        ):
            raise ValueError("issue artifact unresolved ids must use canonical order")
        if not set(self.unresolved_ids).issubset(item.id for item in self.findings.findings):
            raise ValueError("issue artifact unresolved candidates are absent from findings")
        applicable = tuple(
            decision
            for decision in self.receipt.decisions
            if decision.candidate_id in final_ids and set(decision.covered_by).issubset(final_ids)
        )
        applicable_ids = {decision.candidate_id for decision in applicable}
        covered_pairs = {
            tuple(sorted((relation.root_id, relation.candidate_id)))
            for relation in self.relations
            if relation.status == "covered"
        }
        required_unresolved = {
            relation.candidate_id
            for relation in self.relations
            if relation.status in {"partial", "residual", "uncertain", "disagreed"}
            and relation.candidate_id not in applicable_ids
            and tuple(sorted((relation.root_id, relation.candidate_id))) not in covered_pairs
        } | {identity for failure in self.failures for identity in failure.candidate_ids}
        required_unresolved.update(identity for pair in self.search.uncovered_pairs for identity in pair)
        required_unresolved.update(
            decision.candidate_id
            for decision in self.receipt.decisions
            if decision.candidate_id in final_ids and decision.candidate_id not in applicable_ids
        )
        required_unresolved.update(
            decision.candidate_id
            for decision in applicable
            if set(decision.covered_by).intersection(self.unresolved_ids)
        )
        if not required_unresolved.intersection(final_ids).issubset(self.unresolved_ids):
            raise ValueError("issue artifact loses unresolved candidate work")
        votes_by_relation: dict[tuple[str, str], list[CoverageVote]] = {}
        for vote in self.votes:
            if len(vote.root_assessments) != 1 or vote.role not in {"issue-coverage", "issue-coverage-skeptic"}:
                raise ValueError("issue artifact group vote must name one compared root")
            root_id = vote.root_assessments[0].root_id
            votes_by_relation.setdefault((root_id, vote.candidate_id), []).append(vote)
        if len({(item.root_id, item.candidate_id) for item in self.relations}) != len(self.relations):
            raise ValueError("issue artifact repeats a group comparison")
        if set(votes_by_relation) != {(item.root_id, item.candidate_id) for item in self.relations}:
            raise ValueError("issue artifact votes do not match group comparisons")
        decision_links = {
            (decision.candidate_id, decision.root_link.root_id): decision.root_link
            for decision in self.receipt.decisions
        }
        evidence_by_id = {item.id: item for item in self.source_evidence}
        for relation in self.relations:
            if relation.root_id == relation.candidate_id:
                raise ValueError("issue artifact compares a candidate with itself")
            if relation.status == "partial":
                if relation.partial_link is None or relation.partial_link.root_id != relation.root_id:
                    raise ValueError("partial issue relation needs its source link")
            elif relation.partial_link is not None:
                raise ValueError("nonpartial issue relation cannot claim a partial source link")
            if relation.status == "residual" and relation.residual_operation is None:
                raise ValueError("residual issue relation needs its source operation")
            if relation.status == "residual" and relation.candidate_id in applicable_ids:
                raise ValueError("residual issue cannot be covered by an accepted decision")
            votes = votes_by_relation[(relation.root_id, relation.candidate_id)]
            single_retained = (
                relation.status in {"partial", "residual", "independent", "uncertain"}
                and len(votes) == 1
                and votes[0].role == "issue-coverage"
                and not votes[0].covered
            )
            if not single_retained and (
                len(votes) != 2 or {vote.role for vote in votes} != {"issue-coverage", "issue-coverage-skeptic"}
            ):
                raise ValueError("issue relation needs two votes or one retaining vote")
            if single_retained and relation.status in {"partial", "independent", "uncertain"}:
                expected = {"partial": "covers_part", "independent": "unrelated", "uncertain": "uncertain"}[
                    relation.status
                ]
                if votes[0].root_assessments[0].relation != expected:
                    raise ValueError("issue retaining vote contradicts its relation")
            if relation.status == "covered" and not all(vote.covered for vote in votes):
                raise ValueError("covered issue relation lacks two positive votes")
            if relation.status in {"independent", "uncertain"} and any(vote.covered for vote in votes):
                raise ValueError("uncovered issue relation contradicts a positive vote")
            if relation.residual_operation is not None:
                residual = relation.residual_operation
                if not any(vote.residual_operation == residual and not vote.covered for vote in votes):
                    raise ValueError("issue residual lacks a retaining vote")
                if any(ref not in evidence_by_id for ref in residual.evidence_refs) or not any(
                    (span := evidence_by_id[ref].source_span) is not None
                    and span.file == residual.file
                    and span.start_line <= residual.line <= span.end_line
                    for ref in residual.evidence_refs
                ):
                    raise ValueError("issue residual has no exact repository source")
            elif any(vote.residual_operation is not None for vote in votes):
                raise ValueError("issue relation loses a retaining residual vote")
            if not single_retained and relation.status != "covered" and all(vote.covered for vote in votes):
                assessments = tuple(vote.root_assessments[0] for vote in votes)
                shared = agreed_execution_witness(assessments[0].witness, assessments[1].witness)
                if shared is not None or (
                    all(item.witness is None for item in assessments)
                    and len({(item.operation_file, item.operation_line) for item in assessments}) == 1
                ):
                    raise ValueError("two full votes require a covered issue relation")
            link = (
                relation.partial_link
                if relation.status == "partial"
                else decision_links.get((relation.candidate_id, relation.root_id))
                if relation.status == "covered"
                else None
            )
            if link is not None:
                if single_retained:
                    assessment = votes[0].root_assessments[0]
                    submitted = CoverageLink(
                        root_id=assessment.root_id,
                        operation_file=assessment.operation_file,
                        operation_line=assessment.operation_line,
                        evidence_refs=assessment.evidence_refs,
                        reason=assessment.reason,
                        witness=assessment.witness,
                    )
                    if submitted != link:
                        raise ValueError("single partial issue vote changed its source link")
                    agreed = submitted.witness
                else:
                    witnesses = tuple(vote.root_assessments[0].witness for vote in votes)
                    agreed = agreed_execution_witness(*witnesses)
                if agreed != link.witness:
                    raise ValueError("issue votes do not agree on the cited repair operation")
                for vote in votes:
                    assessment = vote.root_assessments[0]
                    if (
                        assessment.relation != "covers_part"
                        or (
                            assessment.witness is None
                            and (assessment.operation_file, assessment.operation_line)
                            != (link.operation_file, link.operation_line)
                        )
                        or not assessment.evidence_refs
                        or any(ref not in evidence_by_id for ref in assessment.evidence_refs)
                        or not any(
                            (span := evidence_by_id[ref].source_span) is not None
                            and span.file == assessment.operation_file
                            and span.start_line <= assessment.operation_line <= span.end_line
                            for ref in assessment.evidence_refs
                        )
                    ):
                        raise ValueError("issue votes do not agree on the cited repair operation")
            elif relation.status == "residual":
                for vote in votes:
                    assessment = vote.root_assessments[0]
                    if vote.residual_operation is not None and any(
                        ref not in evidence_by_id for ref in assessment.evidence_refs
                    ):
                        raise ValueError("unaccepted issue root link cites unknown source")
        if not isinstance(self.issues, tuple) or any(not isinstance(item, IssueRecord) for item in self.issues):
            raise ValueError("issue artifact issue records are invalid")
        expected = project_issues(
            self.findings.findings,
            applicable,
            candidate_id=lambda item: item.id,
            candidate_location=lambda item: (item.file, item.line),
            source_evidence=self.source_evidence,
            unresolved_ids=frozenset(self.unresolved_ids),
        )
        records = tuple(
            IssueRecord(
                representative_id=group.representative.id,
                member_ids=tuple(sorted(member.id for member in group.members)),
            )
            for group in expected
        )
        if self.issues != records:
            raise ValueError("issue artifact groups contradict their source bound decisions")
        accepted = {(decision.candidate_id, root) for decision in applicable for root in decision.covered_by}
        supported = {
            (relation.candidate_id, relation.root_id) for relation in self.relations if relation.status == "covered"
        }
        if not accepted.issubset(supported):
            raise ValueError("issue artifact accepted coverage lacks a group judgment")
        unresolved = set(self.unresolved_ids)
        complete_coverage = {
            (relation.candidate_id, relation.root_id)
            for relation in self.relations
            if relation.status == "covered"
            and relation.candidate_id in final_ids
            and relation.root_id in final_ids
            and relation.candidate_id not in unresolved
            and relation.root_id not in unresolved
        }
        if not complete_coverage.issubset(accepted):
            raise ValueError("issue artifact loses an accepted group judgment")
        if self.content_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("issue artifact content hash does not match its data")

    def validate_candidate_scope(self, candidate_ids: Iterable[str]) -> None:
        """Require every judgment and issue reference to name an input candidate."""
        known = set(candidate_ids)
        if {item.candidate_id for item in self.candidates} != known:
            raise ValueError("issue artifact original candidate scope does not match verification")
        referenced = set(self.unresolved_ids)
        for neighborhood in self.search.neighborhoods:
            referenced.update(neighborhood.candidate_ids)
        for pair in self.search.uncovered_pairs:
            referenced.update(pair)
        for decision in self.receipt.decisions:
            referenced.add(decision.candidate_id)
            referenced.update(decision.covered_by)
        for relation in self.relations:
            referenced.update((relation.root_id, relation.candidate_id))
        for vote in self.votes:
            referenced.add(vote.candidate_id)
            referenced.update(item.root_id for item in vote.root_assessments)
        for failure in self.failures:
            referenced.update(failure.candidate_ids)
        for issue in self.issues:
            referenced.update(issue.member_ids)
        if not referenced.issubset(known):
            raise ValueError("issue artifact references an unknown candidate")

    @classmethod
    def create[T](
        cls,
        findings: FindingsArtifact,
        candidates: tuple[T, ...],
        receipt: ConsolidationReceipt,
        *,
        candidate_id: Callable[[T], str],
        candidate_location: Callable[[T], tuple[str, int | None]],
        source_evidence: tuple[SourceEvidence, ...],
        unresolved_ids: frozenset[str] = frozenset(),
        search: IssueSearchResult | None = None,
        relations: tuple[GroupRelation, ...] = (),
        votes: tuple[CoverageVote, ...] = (),
        failures: tuple[IssueJudgmentFailure, ...] = (),
    ) -> IssuesArtifact:
        """Project only final survivors after validating the full candidate receipt."""
        evidence = tuple(sorted(source_evidence, key=lambda item: item.id))
        groups = project_receipt(
            candidates,
            receipt,
            source_revision=receipt.source_revision,
            adjudicator_revision=receipt.adjudicator_revision,
            candidate_id=candidate_id,
            candidate_location=candidate_location,
            source_evidence=evidence,
            unresolved_ids=unresolved_ids,
            surviving_ids=frozenset(item.id for item in findings.findings),
        )
        issues = tuple(
            IssueRecord(
                representative_id=candidate_id(group.representative),
                member_ids=tuple(sorted(candidate_id(member) for member in group.members)),
            )
            for group in groups
        )
        final_ids = {item.id for item in findings.findings}
        candidate_records = tuple(
            sorted(
                (
                    CandidateRecord(
                        candidate_id=candidate_id(item),
                        file=candidate_location(item)[0],
                        line=candidate_location(item)[1],
                        status=getattr(item, "status", "candidate"),
                        claims=item.claim_records,
                        survived=candidate_id(item) in final_ids,
                    )
                    for item in candidates
                ),
                key=lambda item: item.candidate_id,
            )
        )
        selected_search = search or IssueSearchResult(neighborhoods=(), uncovered_pairs=())
        ordered_relations = tuple(sorted(relations, key=lambda item: (item.root_id, item.candidate_id)))
        ordered_votes = tuple(sorted(votes, key=_vote_key))
        ordered_failures = tuple(sorted(failures, key=lambda item: item.candidate_ids))
        semantic = {
            "schema": ISSUES_SCHEMA,
            "findings_sha256": findings.content_sha256,
            "candidates": [item.to_dict() for item in candidate_records],
            "receipt": receipt.to_dict(),
            "search": selected_search.to_dict(),
            "relations": [item.to_dict() for item in ordered_relations],
            "votes": [item.to_dict() for item in ordered_votes],
            "failures": [item.to_dict() for item in ordered_failures],
            "source_evidence": [issue_source_to_dict(item) for item in evidence],
            "unresolved_ids": sorted(unresolved_ids),
            "issues": [item.to_dict() for item in issues],
        }
        artifact = cls(
            findings=findings,
            candidates=candidate_records,
            receipt=receipt,
            search=selected_search,
            relations=ordered_relations,
            votes=ordered_votes,
            failures=ordered_failures,
            source_evidence=evidence,
            unresolved_ids=tuple(sorted(unresolved_ids)),
            issues=issues,
            content_sha256=_sha256(semantic),
        )
        artifact.validate_candidate_scope(candidate_id(item) for item in candidates)
        return artifact

    @classmethod
    def from_consolidation[T](
        cls,
        findings: FindingsArtifact,
        candidates: tuple[T, ...],
        result: IssueConsolidationResult,
        *,
        source_revision: str,
        adjudicator_revision: str,
        candidate_id: Callable[[T], str],
        candidate_location: Callable[[T], tuple[str, int | None]],
    ) -> IssuesArtifact:
        """Use one shared projection after target specific verification finishes."""
        receipt = ConsolidationReceipt.create(
            candidates,
            result.decisions,
            source_revision=source_revision,
            adjudicator_revision=adjudicator_revision,
            candidate_id=candidate_id,
            source_evidence=result.source_evidence,
        )
        final_ids = {item.id for item in findings.findings}
        applicable = {
            decision.candidate_id
            for decision in result.decisions
            if decision.candidate_id in final_ids and set(decision.covered_by).issubset(final_ids)
        }
        covered_pairs = {
            tuple(sorted((decision.candidate_id, decision.root_link.root_id))) for decision in result.decisions
        }
        unresolved = result.unresolved_ids.intersection(final_ids)
        unresolved = unresolved | {
            relation.candidate_id
            for relation in result.relations
            if relation.status in {"partial", "uncertain", "disagreed"}
            and relation.candidate_id in final_ids
            and relation.candidate_id not in applicable
            and tuple(sorted((relation.root_id, relation.candidate_id))) not in covered_pairs
        }
        unresolved = unresolved | {
            decision.candidate_id
            for decision in result.decisions
            if decision.candidate_id in final_ids and decision.candidate_id not in applicable
        }
        unresolved = unresolved | {
            decision.candidate_id
            for decision in result.decisions
            if decision.candidate_id in applicable and set(decision.covered_by).intersection(unresolved)
        }
        return cls.create(
            findings,
            candidates,
            receipt,
            candidate_id=candidate_id,
            candidate_location=candidate_location,
            source_evidence=result.source_evidence,
            unresolved_ids=frozenset(unresolved),
            search=result.search,
            relations=result.relations,
            votes=result.votes,
            failures=result.failures,
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return the exact source and findings bound artifact content."""
        return {
            "schema": self.schema,
            "findings_sha256": self.findings.content_sha256,
            "candidates": [item.to_dict() for item in self.candidates],
            "receipt": self.receipt.to_dict(),
            "search": self.search.to_dict(),
            "relations": [item.to_dict() for item in self.relations],
            "votes": [item.to_dict() for item in self.votes],
            "failures": [item.to_dict() for item in self.failures],
            "source_evidence": [issue_source_to_dict(item) for item in self.source_evidence],
            "unresolved_ids": list(self.unresolved_ids),
            "issues": [item.to_dict() for item in self.issues],
        }

    def to_dict(self) -> dict[str, object]:
        """Return one strict JSON sidecar without copying original findings."""
        return {**self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object, *, findings: FindingsArtifact) -> IssuesArtifact:
        """Read the sidecar only alongside its exact original findings file."""
        fields = {
            "schema",
            "findings_sha256",
            "candidates",
            "receipt",
            "search",
            "relations",
            "votes",
            "failures",
            "source_evidence",
            "unresolved_ids",
            "issues",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("issue artifact has an invalid shape")
        if value["findings_sha256"] != findings.content_sha256:
            raise ValueError("issue artifact does not identify the supplied findings")
        if not all(
            isinstance(value[name], list)
            for name in ("candidates", "relations", "votes", "failures", "source_evidence", "unresolved_ids", "issues")
        ):
            raise ValueError("issue artifact collections must be lists")
        return cls(
            findings=findings,
            candidates=tuple(CandidateRecord.from_dict(item) for item in value["candidates"]),
            receipt=ConsolidationReceipt.from_dict(value["receipt"]),
            search=IssueSearchResult.from_dict(value["search"]),
            relations=tuple(GroupRelation.from_dict(item) for item in value["relations"]),
            votes=tuple(CoverageVote.from_dict(item) for item in value["votes"]),
            failures=tuple(IssueJudgmentFailure.from_dict(item) for item in value["failures"]),
            source_evidence=tuple(issue_source_from_dict(item) for item in value["source_evidence"]),
            unresolved_ids=tuple(value["unresolved_ids"]),
            issues=tuple(IssueRecord.from_dict(item) for item in value["issues"]),
            content_sha256=value["content_sha256"],
            schema=value["schema"],
        )
