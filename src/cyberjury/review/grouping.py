"""Coordinate source bound issue grouping and its resumable work."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

from cyberjury.providers.base import Provider
from cyberjury.review.adjudication import (
    CoverageVote,
    GroupAdjudicationResult,
    GroupRelation,
    adjudicate_group_coverage,
    agreed_execution_witness,
    execution_witness_matches,
    local_witness_possible,
    repair_belongs_to_root,
    residual_operation_matches,
)
from cyberjury.review.claims import ClaimRecord
from cyberjury.review.consolidation import (
    CandidateSignal,
    CoverageDecision,
    CoverageLink,
    IssueSearchResult,
    candidate_sha256,
    issue_neighborhoods,
    project_issues,
)
from cyberjury.review.context import SourceEvidence
from cyberjury.review.engine import RoleResponseError
from cyberjury.review.navigation import SourceNavigationError, SourceNavigator
from cyberjury.sources.snapshot import SourceSnapshot
from cyberjury.workspace import read_json_object, write_json_atomic

_CHECKPOINT_SCHEMA = "cyberjury.issue-group-checkpoint/v2"
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def issue_policy_revision(configuration_sha256: str) -> str:
    """Bind reusable issue votes to the configured model and judgment contract."""
    if _SHA256.fullmatch(configuration_sha256) is None:
        raise ValueError("issue grouping requires a configuration SHA-256 revision")
    return _digest({"configuration_sha256": configuration_sha256, "judgment_contract": "source-group/v6"})


class IssueGroupCheckpoint[T]:
    """Resume only exact source, candidate, search, and policy bound judgments."""

    def __init__(
        self,
        path: Path,
        *,
        source_revision: str,
        adjudicator_revision: str,
        candidates: tuple[T, ...],
        search: IssueSearchResult,
        candidate_id: Callable[[T], str],
        candidate_location: Callable[[T], tuple[str, int | None]],
        claims_of: Callable[[T], tuple[ClaimRecord, ...]],
        navigator: SourceNavigator,
    ) -> None:
        """Reject changed work rather than replaying stale model answers."""
        if any(_SHA256.fullmatch(value) is None for value in (source_revision, adjudicator_revision)):
            raise ValueError("issue checkpoint requires source and policy SHA-256 revisions")
        self.path = path
        self._by_id = {candidate_id(item): item for item in candidates}
        self._candidate_id = candidate_id
        self._candidate_location = candidate_location
        self._claims_of = claims_of
        self._navigator = navigator
        self._neighborhood_ids = tuple(frozenset(item.candidate_ids) for item in search.neighborhoods)
        self._identity = {
            "schema": _CHECKPOINT_SCHEMA,
            "source_revision": source_revision,
            "adjudicator_revision": adjudicator_revision,
            "candidates_sha256": candidate_sha256(candidates, candidate_id),
            "search_sha256": _digest(search.to_dict()),
        }
        self._groups: dict[tuple[tuple[str, ...], str], GroupAdjudicationResult] = {}
        if not path.exists():
            return
        try:
            saved = read_json_object(path)
            if set(saved) != {*self._identity, "groups", "content_sha256"}:
                raise ValueError("issue checkpoint has an invalid shape")
            if any(saved[name] != expected for name, expected in self._identity.items()):
                raise ValueError("issue checkpoint source, candidate, search, or policy changed")
            if not isinstance(saved["groups"], list):
                raise ValueError("issue checkpoint groups must be a list")
            if saved["content_sha256"] != _digest(
                {key: value for key, value in saved.items() if key != "content_sha256"}
            ):
                raise ValueError("issue checkpoint content hash does not match")
            for item in saved["groups"]:
                if not isinstance(item, dict) or set(item) != {"candidate_ids", "root_id", "judgment"}:
                    raise ValueError("issue checkpoint group has an invalid shape")
                ids = item["candidate_ids"]
                root_id = item["root_id"]
                if not isinstance(ids, list) or not all(isinstance(identity, str) for identity in ids):
                    raise ValueError("issue checkpoint candidate ids are invalid")
                members = tuple(ids)
                result = GroupAdjudicationResult.from_dict(item["judgment"])
                self._validate_group(members, root_id, result)
                key = (members, root_id)
                if key in self._groups:
                    raise ValueError("issue checkpoint repeats a completed group")
                self._groups[key] = result
        except (OSError, ValueError) as exc:
            raise ValueError(f"issue grouping checkpoint is invalid, restart with --fresh: {exc}") from exc

    def _validate_group(
        self,
        candidate_ids: tuple[str, ...],
        root_id: str,
        result: GroupAdjudicationResult,
    ) -> None:
        if (
            not any(set(candidate_ids).issubset(members) for members in self._neighborhood_ids)
            or root_id not in candidate_ids
            or len(candidate_ids) != 2
            or candidate_ids != tuple(sorted(set(candidate_ids)))
        ):
            raise ValueError("issue checkpoint group does not match planned candidates")
        children = set(candidate_ids) - {root_id}
        if (
            len(result.relations) != len(children)
            or {item.candidate_id for item in result.relations} != children
            or any(item.root_id != root_id for item in result.relations)
        ):
            raise ValueError("issue checkpoint did not judge every child")
        by_child = {item.candidate_id: item for item in result.relations}
        if any(
            decision.candidate_id not in children
            or decision.covered_by != (root_id,)
            or by_child[decision.candidate_id].status != "covered"
            for decision in result.decisions
        ):
            raise ValueError("issue checkpoint decisions contradict their group")
        if {item.candidate_id for item in result.decisions} != {
            item.candidate_id for item in result.relations if item.status == "covered"
        }:
            raise ValueError("issue checkpoint loses accepted group coverage")
        single_retained = (
            not result.decisions
            and len(result.votes) == len(children)
            and all(
                relation.status in {"partial", "residual", "independent", "uncertain"} for relation in result.relations
            )
        )
        if len(result.votes) != len(children) * (1 if single_retained else 2) or any(
            vote.candidate_id not in children for vote in result.votes
        ):
            raise ValueError("issue checkpoint vote count or candidate scope is invalid")
        decisions = {item.candidate_id: item for item in result.decisions}
        relations = {item.candidate_id: item for item in result.relations}
        source_by_id = {item.id: item for item in result.source_evidence}
        if len(source_by_id) != len(result.source_evidence):
            raise ValueError("issue checkpoint source evidence ids repeat")
        for child in children:
            votes = [vote for vote in result.votes if vote.candidate_id == child]
            roles = {vote.role for vote in votes}
            if (single_retained and (len(votes) != 1 or roles != {"issue-coverage"} or votes[0].covered)) or (
                not single_retained and (len(votes) != 2 or roles != {"issue-coverage", "issue-coverage-skeptic"})
            ):
                raise ValueError("issue checkpoint child has invalid judgment vote roles or count")
            if any(len(vote.root_assessments) != 1 or vote.root_assessments[0].root_id != root_id for vote in votes):
                raise ValueError("issue checkpoint vote references another root")
            relation = relations[child]
            if single_retained:
                expected = {
                    "partial": "covers_part",
                    "residual": "uncertain",
                    "independent": "unrelated",
                    "uncertain": "uncertain",
                }[relation.status]
                if relation.status != "residual" and votes[0].root_assessments[0].relation != expected:
                    raise ValueError("issue checkpoint retaining vote contradicts its relation")
            if relation.residual_operation is not None:
                if relation.status not in {"partial", "residual"} or not any(
                    vote.residual_operation == relation.residual_operation and not vote.covered for vote in votes
                ):
                    raise ValueError("issue checkpoint residual lacks a retaining judgment vote")
                if not residual_operation_matches(
                    self._by_id[child],
                    relation.residual_operation,
                    navigator=self._navigator,
                    candidate_location=self._candidate_location,
                    child_claims=self._claims_of(self._by_id[child]),
                    source_evidence=result.source_evidence,
                ):
                    raise ValueError("issue checkpoint residual is outside child source evidence")
            elif relation.status == "residual":
                raise ValueError("issue checkpoint residual relation has no exact operation")
            if any(vote.residual_operation is not None for vote in votes) and relation.residual_operation is None:
                raise ValueError("issue checkpoint lost a retaining residual vote")
            link = decisions[child].root_link if child in decisions else relation.partial_link
            if link is not None and not repair_belongs_to_root(
                self._by_id[root_id],
                link,
                candidate_location=self._candidate_location,
            ):
                raise ValueError("issue checkpoint repair operation is outside its proposed root")
            if (
                not single_retained
                and relation.status != "covered"
                and all(vote.covered for vote in votes)
                and agreed_execution_witness(
                    votes[0].root_assessments[0].witness,
                    votes[1].root_assessments[0].witness,
                )
                is not None
            ):
                raise ValueError("issue checkpoint two full votes require a covered relation")
            for vote in votes:
                assessment = vote.root_assessments[0]
                if assessment.relation != "covers_part":
                    if assessment.witness is not None:
                        raise ValueError("issue checkpoint unrelated vote has an execution witness")
                    continue
                if relation.status == "residual" and vote.residual_operation is not None:
                    if any(ref not in source_by_id for ref in assessment.evidence_refs):
                        raise ValueError("issue checkpoint unaccepted root link cites unknown source")
                    continue
                voted_link = CoverageLink(
                    root_id=root_id,
                    operation_file=assessment.operation_file,
                    operation_line=assessment.operation_line,
                    evidence_refs=assessment.evidence_refs,
                    reason=assessment.reason,
                    witness=assessment.witness,
                )
                if not repair_belongs_to_root(
                    self._by_id[root_id],
                    voted_link,
                    candidate_location=self._candidate_location,
                ) or not execution_witness_matches(
                    self._by_id[root_id],
                    self._by_id[child],
                    voted_link,
                    navigator=self._navigator,
                    candidate_location=self._candidate_location,
                    source_evidence=result.source_evidence,
                ):
                    raise ValueError("issue checkpoint execution witness is invalid")
            if child in decisions:
                link = decisions[child].root_link
                agreed = agreed_execution_witness(
                    votes[0].root_assessments[0].witness,
                    votes[1].root_assessments[0].witness,
                )
                if (
                    any(not vote.covered or vote.root_assessments[0].relation != "covers_part" for vote in votes)
                    or agreed != link.witness
                    or not execution_witness_matches(
                        self._by_id[root_id],
                        self._by_id[child],
                        link,
                        navigator=self._navigator,
                        candidate_location=self._candidate_location,
                        source_evidence=result.source_evidence,
                    )
                ):
                    raise ValueError("issue checkpoint coverage lacks two agreeing source votes")
            elif relation.status in {"independent", "uncertain"} and any(vote.covered for vote in votes):
                raise ValueError("issue checkpoint independent relation has a positive vote")
            if relation.status == "residual" and (relation.partial_link is not None or child in decisions):
                raise ValueError("issue checkpoint residual cannot accept a shared root link")
            if relation.status == "partial":
                link = relation.partial_link
                if link is None or link.root_id != root_id:
                    raise ValueError("issue checkpoint partial relation has no source link")
                if single_retained:
                    assessment = votes[0].root_assessments[0]
                    valid_link = CoverageLink(
                        root_id=root_id,
                        operation_file=assessment.operation_file,
                        operation_line=assessment.operation_line,
                        evidence_refs=assessment.evidence_refs,
                        reason=assessment.reason,
                        witness=assessment.witness,
                    )
                    if valid_link != link:
                        raise ValueError("issue checkpoint single partial vote changed its source link")
                    agreed = valid_link.witness
                else:
                    agreed = agreed_execution_witness(
                        votes[0].root_assessments[0].witness,
                        votes[1].root_assessments[0].witness,
                    )
                if any(vote.root_assessments[0].relation != "covers_part" for vote in votes) or agreed != link.witness:
                    raise ValueError("issue checkpoint partial votes disagree on the source operation")
                if not any(
                    (span := source_by_id[ref].source_span) is not None
                    and span.file == link.operation_file
                    and span.start_line <= link.operation_line <= span.end_line
                    for ref in link.evidence_refs
                    if ref in source_by_id
                ):
                    raise ValueError("issue checkpoint partial link lacks exact source evidence")
        project_issues(
            tuple(self._by_id[identity] for identity in candidate_ids),
            result.decisions,
            candidate_id=self._candidate_id,
            candidate_location=self._candidate_location,
            source_evidence=result.source_evidence,
        )

    def load(
        self,
        candidate_ids: tuple[str, ...],
        root_id: str,
        *,
        allow_reverse: bool = False,
    ) -> GroupAdjudicationResult | None:
        """Reuse only a completed judgment for the same planned root."""
        saved = self._groups.get((candidate_ids, root_id))
        if saved is None and not allow_reverse and any(ids == candidate_ids for ids, _root in self._groups):
            raise ValueError("issue checkpoint root changed, restart with --fresh")
        return saved

    def save(
        self,
        candidate_ids: tuple[str, ...],
        root_id: str,
        result: GroupAdjudicationResult,
        *,
        allow_reverse: bool = False,
    ) -> None:
        """Atomically record one clean group before starting the next."""
        self._validate_group(candidate_ids, root_id, result)
        key = (candidate_ids, root_id)
        if key in self._groups:
            raise ValueError("issue checkpoint cannot overwrite a completed group")
        if not allow_reverse and any(ids == candidate_ids for ids, _root in self._groups):
            raise ValueError("issue checkpoint root changed, restart with --fresh")
        self._groups[key] = result
        self._write()

    def _write(self) -> None:
        """Keep group receipts in one hash bound checkpoint."""
        document = {
            **self._identity,
            "groups": [
                {"candidate_ids": list(ids), "root_id": root, "judgment": judgment.to_dict()}
                for (ids, root), judgment in sorted(self._groups.items())
            ],
        }
        write_json_atomic(self.path, {**document, "content_sha256": _digest(document)})


@dataclass(frozen=True, kw_only=True)
class IssueJudgmentFailure:
    """Keep a failed neighborhood visible without deleting its candidates."""

    candidate_ids: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        """Expose failed candidate scope without implying a clean judgment."""
        return {"candidate_ids": list(self.candidate_ids), "reason": self.reason}

    @classmethod
    def from_dict(cls, value: object) -> IssueJudgmentFailure:
        """Reject malformed failure scope, including global upstream failures."""
        if not isinstance(value, dict) or set(value) != {"candidate_ids", "reason"}:
            raise ValueError("issue judgment failure has an invalid shape")
        ids = value["candidate_ids"]
        if (
            not isinstance(ids, list)
            or not all(isinstance(item, str) and item for item in ids)
            or len(set(ids)) != len(ids)
            or not isinstance(value["reason"], str)
            or not value["reason"]
        ):
            raise ValueError("issue judgment failure fields are invalid")
        return cls(candidate_ids=tuple(ids), reason=value["reason"])


@dataclass(frozen=True, kw_only=True)
class IssueConsolidationResult:
    """Return accepted coverage and every unresolved source judgment separately."""

    search: IssueSearchResult
    decisions: tuple[CoverageDecision, ...]
    relations: tuple[GroupRelation, ...]
    votes: tuple[CoverageVote, ...]
    source_evidence: tuple[SourceEvidence, ...]
    unresolved_ids: frozenset[str]
    failures: tuple[IssueJudgmentFailure, ...]

    @classmethod
    def unavailable(cls, candidate_ids: tuple[str, ...], reason: str) -> IssueConsolidationResult:
        """Preserve candidate identities when grouping has no usable source route."""
        ids = tuple(sorted(set(candidate_ids)))
        return cls(
            search=IssueSearchResult(neighborhoods=(), uncovered_pairs=()),
            decisions=(),
            relations=(),
            votes=(),
            source_evidence=(),
            unresolved_ids=frozenset(ids),
            failures=(IssueJudgmentFailure(candidate_ids=ids, reason=reason),) if reason else (),
        )


def consolidate_candidate_issues[T](
    candidates: tuple[T, ...],
    *,
    navigator: SourceNavigator,
    provider: Provider,
    model: str,
    candidate_id: Callable[[T], str],
    candidate_location: Callable[[T], tuple[str, int | None]],
    claims_of: Callable[[T], tuple[ClaimRecord, ...]],
    source_snapshot: SourceSnapshot,
    source_refs_of: Callable[[T], tuple[str, ...]] | None = None,
    category_of: Callable[[T], str] | None = None,
    attack_path_id_of: Callable[[T], str] | None = None,
    candidate_source_evidence: tuple[SourceEvidence, ...] = (),
    checkpoint_path: Path | None = None,
    adjudicator_revision: str = "",
) -> IssueConsolidationResult:
    """Judge bounded source grounded collisions and preserve unresolved reports."""
    ordered = tuple(sorted(candidates, key=candidate_id))
    by_id = {candidate_id(item): item for item in ordered}
    if not model or len(by_id) != len(ordered) or any(not identity for identity in by_id):
        raise ValueError("issue consolidation needs a model and unique candidate ids")
    if not source_snapshot.matches():
        raise ValueError("issue consolidation source snapshot changed")
    signals = tuple(
        CandidateSignal(
            candidate_id=candidate_id(item),
            source_refs=source_refs_of(item) if source_refs_of is not None else (),
            category=category_of(item) if category_of is not None else "",
            attack_path_id=attack_path_id_of(item) if attack_path_id_of is not None else "",
        )
        for item in ordered
    )

    def eligible(ids: tuple[str, ...]) -> bool:
        members = tuple(by_id[identity] for identity in ids)
        locations = tuple(candidate_location(item) for item in members)
        if any(not file or line is None for file, line in locations):
            return False
        try:
            source = navigator.session().read_source_scopes(locations, target_chars=48_000)
        except SourceNavigationError:
            return False
        claims_chars = sum(len(claim.content_json) for item in members for claim in claims_of(item))
        return len(source.text) + claims_chars < 110_000

    search = issue_neighborhoods(
        signals,
        eligible_group=eligible,
        eligible_pair=lambda ids: local_witness_possible(
            by_id[ids[0]],
            by_id[ids[1]],
            navigator=navigator,
            candidate_location=candidate_location,
        ),
    )
    if not source_snapshot.matches():
        raise ValueError("issue consolidation source snapshot changed during search")
    checkpoint = (
        IssueGroupCheckpoint(
            checkpoint_path,
            source_revision=source_snapshot.snapshot_id,
            adjudicator_revision=adjudicator_revision,
            candidates=ordered,
            search=search,
            candidate_id=candidate_id,
            candidate_location=candidate_location,
            claims_of=claims_of,
            navigator=navigator,
        )
        if checkpoint_path is not None
        else None
    )
    evidence_by_id: dict[str, SourceEvidence] = {}
    proposed: list[CoverageDecision] = []
    relations: list[GroupRelation] = []
    votes: list[CoverageVote] = []
    failures: list[IssueJudgmentFailure] = []
    provider_failed = False
    for index, group in enumerate(search.neighborhoods):
        comparison_ids = group.candidate_ids
        root_id = min(
            comparison_ids,
            key=lambda identity: (
                candidate_location(by_id[identity])[0],
                candidate_location(by_id[identity])[1] or 0,
                identity,
            ),
        )
        child_id = next(identity for identity in comparison_ids if identity != root_id)
        result = checkpoint.load(comparison_ids, root_id) if checkpoint is not None else None
        if result is None:
            try:
                result = adjudicate_group_coverage(
                    by_id[root_id],
                    (by_id[child_id],),
                    navigator=navigator,
                    provider=provider,
                    model=model,
                    candidate_id=candidate_id,
                    candidate_location=candidate_location,
                    claims_of=claims_of,
                    source_snapshot=source_snapshot,
                    candidate_source_evidence=candidate_source_evidence,
                )
                if checkpoint is not None:
                    checkpoint.save(comparison_ids, root_id, result)
            except Exception as exc:
                if not source_snapshot.matches():
                    raise ValueError("issue consolidation source snapshot changed during judgment") from exc
                detail = (
                    str(exc)[:300]
                    if isinstance(exc, (ValueError, RoleResponseError, SourceNavigationError))
                    else "request failed"
                )
                failures.append(
                    IssueJudgmentFailure(candidate_ids=comparison_ids, reason=f"{type(exc).__name__}: {detail}")
                )
                if not isinstance(exc, (ValueError, RoleResponseError, SourceNavigationError)):
                    remaining = tuple(
                        sorted(
                            {
                                identity
                                for pending_group in search.neighborhoods[index:]
                                for identity in pending_group.candidate_ids
                            }
                        )
                    )
                    failures.append(
                        IssueJudgmentFailure(
                            candidate_ids=remaining,
                            reason="provider request failed before remaining issue groups",
                        )
                    )
                    provider_failed = True
                    break
                continue
        for evidence in result.source_evidence:
            previous = evidence_by_id.get(evidence.id)
            if previous is not None and previous != evidence:
                raise ValueError("issue consolidation source evidence identity changed")
            evidence_by_id[evidence.id] = evidence
        proposed.extend(result.decisions)
        relations.extend(result.relations)
        votes.extend(result.votes)
    if not provider_failed:
        for relation in tuple(relations):
            if relation.status not in {"uncertain", "disagreed"}:
                continue
            root_id = relation.candidate_id
            child_id = relation.root_id
            comparison_ids = tuple(sorted((root_id, child_id)))
            result = checkpoint.load(comparison_ids, root_id, allow_reverse=True) if checkpoint is not None else None
            if result is None:
                try:
                    result = adjudicate_group_coverage(
                        by_id[root_id],
                        (by_id[child_id],),
                        navigator=navigator,
                        provider=provider,
                        model=model,
                        candidate_id=candidate_id,
                        candidate_location=candidate_location,
                        claims_of=claims_of,
                        source_snapshot=source_snapshot,
                        candidate_source_evidence=candidate_source_evidence,
                    )
                    if checkpoint is not None:
                        checkpoint.save(comparison_ids, root_id, result, allow_reverse=True)
                except Exception as exc:
                    if not source_snapshot.matches():
                        raise ValueError("issue consolidation source snapshot changed during reverse judgment") from exc
                    detail = (
                        str(exc)[:300]
                        if isinstance(exc, (ValueError, RoleResponseError, SourceNavigationError))
                        else "request failed"
                    )
                    failures.append(
                        IssueJudgmentFailure(candidate_ids=comparison_ids, reason=f"{type(exc).__name__}: {detail}")
                    )
                    if not isinstance(exc, (ValueError, RoleResponseError, SourceNavigationError)):
                        provider_failed = True
                        break
                    continue
            for evidence in result.source_evidence:
                previous = evidence_by_id.get(evidence.id)
                if previous is not None and previous != evidence:
                    raise ValueError("reverse issue source evidence identity changed")
                evidence_by_id[evidence.id] = evidence
            proposed.extend(result.decisions)
            relations.extend(result.relations)
            votes.extend(result.votes)
    covered_pairs = {tuple(sorted((decision.candidate_id, decision.root_link.root_id))) for decision in proposed}
    unresolved = {identity for pair in search.uncovered_pairs for identity in pair} | {
        identity for failure in failures for identity in failure.candidate_ids
    }
    unresolved.update(
        relation.candidate_id
        for relation in relations
        if relation.status in {"partial", "residual", "uncertain", "disagreed"}
        and tuple(sorted((relation.root_id, relation.candidate_id))) not in covered_pairs
    )
    by_child: dict[str, list[CoverageDecision]] = {}
    for decision in proposed:
        by_child.setdefault(decision.candidate_id, []).append(decision)
    conflicted = {identity for identity, values in by_child.items() if len(values) > 1}
    accepted = {identity: values[0] for identity, values in by_child.items() if identity not in conflicted}
    conflicted.update(
        identity for identity, decision in accepted.items() if any(root in accepted for root in decision.covered_by)
    )
    hard_unresolved = {identity for failure in failures for identity in failure.candidate_ids}
    hard_unresolved.update(identity for pair in search.uncovered_pairs for identity in pair)
    unresolved.difference_update(set(accepted) - conflicted - hard_unresolved)
    unresolved.update(conflicted)
    blocked_by_unresolved_root = {
        identity for identity, decision in accepted.items() if set(decision.covered_by).intersection(unresolved)
    }
    unresolved.update(blocked_by_unresolved_root)
    decisions = tuple(
        sorted(
            (decision for identity, decision in accepted.items() if identity not in conflicted),
            key=lambda item: item.candidate_id,
        )
    )
    source_evidence = tuple(evidence_by_id[identity] for identity in sorted(evidence_by_id))
    judged_pairs = {tuple(sorted((relation.root_id, relation.candidate_id))) for relation in relations}
    member_roots: dict[str, set[str]] = {identity: {identity} for identity in by_id}
    for decision in decisions:
        if decision.candidate_id not in unresolved:
            member_roots[decision.candidate_id] = set(decision.covered_by)
    planned_pairs = {
        pair for neighborhood in search.neighborhoods for pair in combinations(neighborhood.candidate_ids, 2)
    }
    uncovered_pairs = set(search.uncovered_pairs)
    uncovered_pairs.update(
        pair
        for pair in planned_pairs
        if pair not in judged_pairs and not member_roots[pair[0]].intersection(member_roots[pair[1]])
    )
    unresolved.update(identity for pair in uncovered_pairs for identity in pair)
    search = IssueSearchResult(
        neighborhoods=search.neighborhoods,
        uncovered_pairs=tuple(sorted(uncovered_pairs)),
    )
    project_issues(
        ordered,
        decisions,
        candidate_id=candidate_id,
        candidate_location=candidate_location,
        source_evidence=source_evidence,
        unresolved_ids=frozenset(unresolved),
    )
    return IssueConsolidationResult(
        search=search,
        decisions=decisions,
        relations=tuple(relations),
        votes=tuple(votes),
        source_evidence=source_evidence,
        unresolved_ids=frozenset(unresolved),
        failures=tuple(failures),
    )
