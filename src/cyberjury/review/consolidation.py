"""Project adjudicated coverage without treating source receipts as semantic proof."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, is_dataclass
from itertools import combinations
from typing import Literal

from cyberjury.review.context import SourceEvidence, SourceSpan

_SHA256 = re.compile(r"[0-9a-f]{64}")


def issue_source_to_dict(evidence: SourceEvidence) -> dict[str, object]:
    """Persist one exact repository source fragment."""
    if evidence.source_span is None:
        raise ValueError("issue repository evidence needs an exact source span")
    return {
        "id": evidence.id,
        "identity": evidence.identity,
        "text": evidence.text,
        "source_span": evidence.source_span.to_dict(),
    }


def issue_source_from_dict(value: object) -> SourceEvidence:
    """Reject source entries without an exact repository span."""
    if not isinstance(value, dict):
        raise ValueError("issue source evidence has an invalid shape")
    if set(value) != {"id", "identity", "text", "source_span"}:
        raise ValueError("issue source evidence has an invalid shape")
    return SourceEvidence(
        id=value["id"],
        identity=value["identity"],
        text=value["text"],
        source_span=SourceSpan.from_dict(value["source_span"]),
    )


@dataclass(frozen=True, kw_only=True)
class CandidateSignal:
    """Expose source grounded clues for bounded duplicate search only."""

    candidate_id: str
    source_refs: tuple[str, ...] = ()
    category: str = ""
    attack_path_id: str = ""


@dataclass(frozen=True, kw_only=True)
class IssueNeighborhood:
    """One candidate set to inspect without implying semantic equivalence."""

    candidate_ids: tuple[str, ...]
    signals: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        """Keep every persisted comparison on one canonical source linked pair."""
        if (
            not isinstance(self.candidate_ids, tuple)
            or len(self.candidate_ids) != 2
            or not all(isinstance(identity, str) and identity for identity in self.candidate_ids)
            or self.candidate_ids != tuple(sorted(set(self.candidate_ids)))
            or not isinstance(self.signals, tuple)
            or not self.signals
            or any(
                not isinstance(signal, tuple)
                or len(signal) != 2
                or not all(isinstance(part, str) and part for part in signal)
                for signal in self.signals
            )
            or self.signals != tuple(sorted(set(self.signals)))
        ):
            raise ValueError("issue neighborhood needs one canonical source linked pair")

    def to_dict(self) -> dict[str, object]:
        """Persist a bounded comparison set without implying coverage."""
        return {
            "candidate_ids": list(self.candidate_ids),
            "signals": [list(signal) for signal in self.signals],
        }

    @classmethod
    def from_dict(cls, value: object) -> IssueNeighborhood:
        """Reject malformed search groups before resume."""
        if not isinstance(value, dict) or set(value) != {"candidate_ids", "signals"}:
            raise ValueError("issue neighborhood has an invalid shape")
        ids = value["candidate_ids"]
        signals = value["signals"]
        if (
            not isinstance(ids, list)
            or len(ids) != 2
            or not all(isinstance(identity, str) and identity for identity in ids)
            or tuple(ids) != tuple(sorted(set(ids)))
            or not isinstance(signals, list)
            or not all(
                isinstance(signal, list) and len(signal) == 2 and all(isinstance(part, str) and part for part in signal)
                for signal in signals
            )
        ):
            raise ValueError("issue neighborhood members or signals are invalid")
        return cls(candidate_ids=tuple(ids), signals=tuple((item[0], item[1]) for item in signals))


@dataclass(frozen=True, kw_only=True)
class IssueSearchResult:
    """Expose every budget exclusion instead of treating unsearched pairs as clean."""

    neighborhoods: tuple[IssueNeighborhood, ...]
    uncovered_pairs: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, object]:
        """Expose both searched groups and pairs lost to bounded source reads."""
        return {
            "neighborhoods": [item.to_dict() for item in self.neighborhoods],
            "uncovered_pairs": [list(pair) for pair in self.uncovered_pairs],
        }

    @classmethod
    def from_dict(cls, value: object) -> IssueSearchResult:
        """Read one exact bounded search receipt."""
        fields = {"neighborhoods", "uncovered_pairs"}
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or any(not isinstance(value[field], list) for field in fields)
        ):
            raise ValueError("issue search receipt has an invalid shape")
        pairs = []
        for item in value["uncovered_pairs"]:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not all(isinstance(identity, str) and identity for identity in item)
                or item[0] >= item[1]
            ):
                raise ValueError("issue search uncovered pair is invalid")
            pairs.append((item[0], item[1]))
        neighborhoods = tuple(IssueNeighborhood.from_dict(item) for item in value["neighborhoods"])
        if tuple(pairs) != tuple(sorted(set(pairs))):
            raise ValueError("issue search receipt entries must be canonical")
        return cls(neighborhoods=neighborhoods, uncovered_pairs=tuple(pairs))


def issue_neighborhoods(
    candidates: Iterable[CandidateSignal],
    *,
    eligible_group: Callable[[tuple[str, ...]], bool] | None = None,
    eligible_pair: Callable[[tuple[str, str]], bool] | None = None,
    max_pairs: int = 1_000,
) -> IssueSearchResult:
    """Plan only source-linked pairs that can share one local repair."""
    values = tuple(candidates)
    ids = [item.candidate_id for item in values]
    if len(ids) != len(set(ids)) or any(not identity for identity in ids):
        raise ValueError("issue search needs unique nonempty candidate ids")
    if max_pairs < 1:
        raise ValueError("issue search pair limit must be positive")
    by_signal: dict[tuple[str, str], set[str]] = {}
    for item in values:
        for source_ref in item.source_refs:
            if not source_ref.startswith(("ev-", "src-")):
                continue
            if item.category:
                by_signal.setdefault(("source-category", f"{source_ref}:{item.category}"), set()).add(item.candidate_id)
            if item.attack_path_id:
                by_signal.setdefault(("source-path", f"{source_ref}:{item.attack_path_id}"), set()).add(
                    item.candidate_id
                )
    pairs: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for signal in sorted(by_signal):
        for pair in combinations(sorted(by_signal[signal]), 2):
            if eligible_pair is not None and not eligible_pair(pair):
                continue
            pairs.setdefault(pair, set()).add(signal)
            if len(pairs) > max_pairs:
                raise ValueError("issue search exceeds the bounded pair count")
    neighborhoods = []
    uncovered = []
    for pair, signals in sorted(pairs.items()):
        if eligible_group is not None and not eligible_group(pair):
            uncovered.append(pair)
            continue
        neighborhoods.append(IssueNeighborhood(candidate_ids=pair, signals=tuple(sorted(signals))))
    return IssueSearchResult(
        neighborhoods=tuple(neighborhoods),
        uncovered_pairs=tuple(uncovered),
    )


@dataclass(frozen=True, kw_only=True)
class ExecutionWitness:
    """Locate one shared repair within a bounded executable source region."""

    kind: Literal["same_local_control"]
    callsite_id: str = ""
    definition_id: str = ""
    start_line: int = 0
    end_line: int = 0

    def __post_init__(self) -> None:
        """Reject a relation outside one exact bounded local control."""
        if (
            self.kind != "same_local_control"
            or self.callsite_id
            or self.definition_id
            or isinstance(self.start_line, bool)
            or not isinstance(self.start_line, int)
            or isinstance(self.end_line, bool)
            or not isinstance(self.end_line, int)
            or not 0 < self.start_line <= self.end_line
            or self.end_line - self.start_line > 31
        ):
            raise ValueError("issue execution witness has an invalid relation shape")

    def to_dict(self) -> dict[str, object]:
        """Persist the bounded source range shared by both reports."""
        return {
            "kind": self.kind,
            "callsite_id": self.callsite_id,
            "definition_id": self.definition_id,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExecutionWitness:
        """Require the exact local witness shape on resume."""
        if not isinstance(value, dict) or set(value) != {
            "kind",
            "callsite_id",
            "definition_id",
            "start_line",
            "end_line",
        }:
            raise ValueError("issue execution witness has an invalid shape")
        return cls(**value)


@dataclass(frozen=True, kw_only=True)
class CoverageLink:
    """Bind one proposed root to its own existing repair operation."""

    root_id: str
    operation_file: str
    operation_line: int
    evidence_refs: tuple[str, ...]
    reason: str
    witness: ExecutionWitness | None = None

    def to_dict(self) -> dict[str, object]:
        """Persist one independently cited root relationship."""
        record = {
            "root_id": self.root_id,
            "operation_file": self.operation_file,
            "operation_line": self.operation_line,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
        }
        if self.witness is not None:
            record["witness"] = self.witness.to_dict()
        return record

    @classmethod
    def from_dict(cls, value: object) -> CoverageLink:
        """Reject links without their exact source operation contract."""
        fields = {"root_id", "operation_file", "operation_line", "evidence_refs", "reason"}
        if not isinstance(value, dict) or set(value) not in (fields, fields | {"witness"}):
            raise ValueError("issue coverage link has an invalid shape")
        refs = value["evidence_refs"]
        if (
            not isinstance(value["root_id"], str)
            or not isinstance(value["operation_file"], str)
            or isinstance(value["operation_line"], bool)
            or not isinstance(value["operation_line"], int)
            or not isinstance(refs, list)
            or not all(isinstance(ref, str) for ref in refs)
            or not isinstance(value["reason"], str)
        ):
            raise ValueError("issue coverage link fields are invalid")
        return cls(
            root_id=value["root_id"],
            operation_file=value["operation_file"],
            operation_line=value["operation_line"],
            evidence_refs=tuple(refs),
            reason=value["reason"],
            witness=ExecutionWitness.from_dict(value["witness"]) if "witness" in value else None,
        )


@dataclass(frozen=True, kw_only=True)
class ResidualOperation:
    """Locate a child claim that one proposed root repair cannot cover."""

    file: str
    line: int
    evidence_refs: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        """Keep an unresolved claim attached to a real repository location."""
        SourceSpan(file=self.file, start_line=self.line, end_line=self.line)
        if (
            not isinstance(self.evidence_refs, tuple)
            or not self.evidence_refs
            or any(
                not isinstance(ref, str) or not ref.startswith(("src-", "ev-", "dep-")) for ref in self.evidence_refs
            )
            or len(set(self.evidence_refs)) != len(self.evidence_refs)
            or not isinstance(self.reason, str)
            or not self.reason.strip()
        ):
            raise ValueError("residual operation needs unique source references and a reason")

    def to_dict(self) -> dict[str, object]:
        """Persist the independently cited child residual."""
        return {
            "file": self.file,
            "line": self.line,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: object) -> ResidualOperation:
        """Reject a residual with missing or surplus location fields."""
        if not isinstance(value, dict) or set(value) != {"file", "line", "evidence_refs", "reason"}:
            raise ValueError("residual operation has an invalid shape")
        if not isinstance(value["evidence_refs"], list):
            raise ValueError("residual operation evidence must be a list")
        return cls(
            file=value["file"],
            line=value["line"],
            evidence_refs=tuple(value["evidence_refs"]),
            reason=value["reason"],
        )


@dataclass(frozen=True, kw_only=True)
class CoverageDecision:
    """Claim complete coverage by one source bound repair."""

    candidate_id: str
    root_link: CoverageLink
    reason: str

    @property
    def covered_by(self) -> tuple[str, ...]:
        """Return the representative named by this decision."""
        return (self.root_link.root_id,)

    def to_dict(self) -> dict[str, object]:
        """Persist the complete claim and its source relation."""
        return {
            "candidate_id": self.candidate_id,
            "root_link": self.root_link.to_dict(),
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: object) -> CoverageDecision:
        """Reject a partial or widened persisted coverage decision."""
        if not isinstance(value, dict) or set(value) != {"candidate_id", "root_link", "reason"}:
            raise ValueError("issue coverage decision has an invalid shape")
        if not isinstance(value["candidate_id"], str) or not isinstance(value["reason"], str):
            raise ValueError("issue coverage decision fields are invalid")
        return cls(
            candidate_id=value["candidate_id"],
            root_link=CoverageLink.from_dict(value["root_link"]),
            reason=value["reason"],
        )


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def candidate_sha256[T](candidates: Iterable[T], candidate_id: Callable[[T], str]) -> str:
    """Bind every original candidate field before reusable issue judgments."""
    records: list[dict[str, object]] = []
    for candidate in candidates:
        if not is_dataclass(candidate) or isinstance(candidate, type):
            raise ValueError("issue candidate must be a dataclass")
        records.append({**asdict(candidate), "candidate_id": candidate_id(candidate)})
    ids = [item.get("candidate_id") for item in records]
    if any(not isinstance(identity, str) or not identity for identity in ids) or len(set(ids)) != len(ids):
        raise ValueError("issue candidate records require unique nonempty candidate ids")
    return _digest(sorted(records, key=lambda item: item["candidate_id"]))


def source_evidence_sha256(evidence: Iterable[SourceEvidence]) -> str:
    """Bind every exact source fragment used in issue adjudication."""
    return _digest(
        sorted(
            (
                {
                    "id": item.id,
                    "identity": item.identity,
                    "text": item.text,
                    "span": (
                        (item.source_span.file, item.source_span.start_line, item.source_span.end_line)
                        if item.source_span is not None
                        else None
                    ),
                }
                for item in evidence
            ),
            key=lambda item: item["id"],
        )
    )


@dataclass(frozen=True, kw_only=True)
class ConsolidationReceipt:
    """Bind candidate coverage to exact source, evidence, and judgment policy."""

    source_revision: str
    adjudicator_revision: str
    candidates_sha256: str
    evidence_sha256: str
    decisions: tuple[CoverageDecision, ...]
    content_sha256: str
    schema: str = "review.issue-consolidation/v2"

    def __post_init__(self) -> None:
        """Keep direct construction subject to the same strict receipt contract."""
        if self.schema != "review.issue-consolidation/v2":
            raise ValueError("issue consolidation receipt schema is unsupported")
        for field in (
            self.source_revision,
            self.adjudicator_revision,
            self.candidates_sha256,
            self.evidence_sha256,
            self.content_sha256,
        ):
            if not isinstance(field, str) or _SHA256.fullmatch(field) is None:
                raise ValueError("issue consolidation receipt revisions and hashes must be SHA-256 digests")
        if not isinstance(self.decisions, tuple) or any(
            not isinstance(decision, CoverageDecision) for decision in self.decisions
        ):
            raise ValueError("issue consolidation receipt decisions must be a tuple")
        semantic = self.to_dict()
        semantic.pop("content_sha256")
        if _digest(semantic) != self.content_sha256:
            raise ValueError("issue consolidation receipt hash does not match its content")

    @classmethod
    def create[T](
        cls,
        candidates: Iterable[T],
        decisions: Iterable[CoverageDecision],
        *,
        source_revision: str,
        adjudicator_revision: str,
        candidate_id: Callable[[T], str],
        source_evidence: Iterable[SourceEvidence],
    ) -> ConsolidationReceipt:
        """Freeze all response affecting inputs before a result can be resumed."""
        if any(
            not isinstance(revision, str) or _SHA256.fullmatch(revision) is None
            for revision in (source_revision, adjudicator_revision)
        ):
            raise ValueError("issue consolidation needs source and adjudicator SHA-256 revisions")
        ordered_decisions = tuple(sorted(decisions, key=lambda item: item.candidate_id))
        candidates_sha256 = candidate_sha256(candidates, candidate_id)
        evidence_sha256 = source_evidence_sha256(source_evidence)
        data: dict[str, object] = {
            "schema": "review.issue-consolidation/v2",
            "source_revision": source_revision,
            "adjudicator_revision": adjudicator_revision,
            "candidates_sha256": candidates_sha256,
            "evidence_sha256": evidence_sha256,
            "decisions": [decision.to_dict() for decision in ordered_decisions],
        }
        return cls(
            source_revision=source_revision,
            adjudicator_revision=adjudicator_revision,
            candidates_sha256=candidates_sha256,
            evidence_sha256=evidence_sha256,
            decisions=ordered_decisions,
            content_sha256=_digest(data),
        )

    def to_dict(self) -> dict[str, object]:
        """Write one strict and self validating workspace receipt."""
        return {
            "schema": self.schema,
            "source_revision": self.source_revision,
            "adjudicator_revision": self.adjudicator_revision,
            "candidates_sha256": self.candidates_sha256,
            "evidence_sha256": self.evidence_sha256,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ConsolidationReceipt:
        """Reject malformed or modified persisted coverage before applying it."""
        fields = {
            "schema",
            "source_revision",
            "adjudicator_revision",
            "candidates_sha256",
            "evidence_sha256",
            "decisions",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or value["schema"] != "review.issue-consolidation/v2":
            raise ValueError("issue consolidation receipt has an invalid shape")
        if any(not isinstance(value[name], str) or not value[name] for name in fields - {"schema", "decisions"}):
            raise ValueError("issue consolidation receipt revisions and hashes must be nonempty strings")
        if not isinstance(value["decisions"], list):
            raise ValueError("issue consolidation decisions must be a list")
        semantic = {name: value[name] for name in fields - {"content_sha256"}}
        if _digest(semantic) != value["content_sha256"]:
            raise ValueError("issue consolidation receipt hash does not match its content")
        return cls(
            source_revision=value["source_revision"],
            adjudicator_revision=value["adjudicator_revision"],
            candidates_sha256=value["candidates_sha256"],
            evidence_sha256=value["evidence_sha256"],
            decisions=tuple(CoverageDecision.from_dict(item) for item in value["decisions"]),
            content_sha256=value["content_sha256"],
        )


def project_receipt[T](
    candidates: Iterable[T],
    receipt: ConsolidationReceipt,
    *,
    source_revision: str,
    adjudicator_revision: str,
    candidate_id: Callable[[T], str],
    candidate_location: Callable[[T], tuple[str, int | None]],
    source_evidence: Iterable[SourceEvidence],
    unresolved_ids: frozenset[str] = frozenset(),
    surviving_ids: frozenset[str] | None = None,
) -> tuple[IssueGroup[T], ...]:
    """Reject stale source, candidate, evidence, or policy before issue projection."""
    ordered = tuple(candidates)
    evidence = tuple(source_evidence)
    if (
        receipt.source_revision != source_revision
        or receipt.adjudicator_revision != adjudicator_revision
        or receipt.candidates_sha256 != candidate_sha256(ordered, candidate_id)
        or receipt.evidence_sha256 != source_evidence_sha256(evidence)
    ):
        raise ValueError("issue consolidation receipt does not match the current review")
    return project_issues(
        ordered,
        receipt.decisions,
        candidate_id=candidate_id,
        candidate_location=candidate_location,
        source_evidence=evidence,
        unresolved_ids=unresolved_ids,
        surviving_ids=surviving_ids,
    )


@dataclass(frozen=True, kw_only=True)
class IssueGroup[T]:
    """Retain every original candidate within one final issue projection."""

    representative: T
    members: tuple[T, ...]


def project_issues[T](
    candidates: Iterable[T],
    decisions: Iterable[CoverageDecision],
    *,
    candidate_id: Callable[[T], str],
    candidate_location: Callable[[T], tuple[str, int | None]],
    source_evidence: Iterable[SourceEvidence],
    unresolved_ids: frozenset[str] = frozenset(),
    surviving_ids: frozenset[str] | None = None,
) -> tuple[IssueGroup[T], ...]:
    """Apply adjudicated direct coverage while retaining all member objects."""
    ordered = tuple(sorted(candidates, key=candidate_id))
    by_id = {candidate_id(candidate): candidate for candidate in ordered}
    if len(by_id) != len(ordered) or not all(by_id):
        raise ValueError("issue projection requires unique nonempty candidate ids")
    if not unresolved_ids.issubset(by_id):
        raise ValueError("unresolved issue candidates must belong to this review")
    surviving = frozenset(by_id) if surviving_ids is None else surviving_ids
    if not surviving.issubset(by_id) or not unresolved_ids.issubset(surviving):
        raise ValueError("surviving issue candidates must belong to this review")
    delivered = tuple(source_evidence)
    evidence_by_id = {item.id: item for item in delivered}
    if len(evidence_by_id) != len(delivered):
        raise ValueError("issue source evidence ids must be unique")
    proposed = tuple(decisions)
    coverage: dict[str, tuple[str, ...]] = {}
    for decision in proposed:
        child = decision.candidate_id
        roots = decision.covered_by
        if child not in by_id or child in coverage:
            raise ValueError("issue coverage names an unknown or repeated candidate")
        if roots[0] not in by_id or roots[0] == child:
            raise ValueError("issue coverage must name one distinct, known root candidate")
        if not decision.reason.strip():
            raise ValueError("issue coverage requires an explanation")
        link = decision.root_link
        if not link.reason.strip() or not link.evidence_refs or len(set(link.evidence_refs)) != len(link.evidence_refs):
            raise ValueError("issue coverage link requires a reason and unique source evidence")
        if any(ref not in evidence_by_id for ref in link.evidence_refs):
            raise ValueError("issue coverage requires delivered exact source evidence")
        cited_spans = tuple(evidence_by_id[ref].source_span for ref in link.evidence_refs)
        if (
            not link.operation_file
            or link.operation_line < 1
            or not any(
                span is not None
                and span.file == link.operation_file
                and span.start_line <= link.operation_line <= span.end_line
                for span in cited_spans
            )
        ):
            raise ValueError("issue repair operation must be inside cited source evidence")
        for identity in (child, link.root_id):
            file, line = candidate_location(by_id[identity])
            if line is None or not any(
                item.source_span is not None
                and item.source_span.file == file
                and item.source_span.start_line <= line <= item.source_span.end_line
                for item in delivered
            ):
                raise ValueError("issue judgment must read every linked member location")
        coverage[child] = roots
    if any(root in coverage for roots in coverage.values() for root in roots):
        raise ValueError("issue coverage cannot rely on another covered candidate")

    applied = {
        child: roots
        for child, roots in coverage.items()
        if child in surviving
        and set(roots).issubset(surviving)
        and child not in unresolved_ids
        and not unresolved_ids.intersection(roots)
    }
    members_by_root: dict[str, list[T]] = {identity: [by_id[identity]] for identity in surviving}
    for child, roots in sorted(applied.items()):
        for root in roots:
            members_by_root[root].append(by_id[child])
    return tuple(
        IssueGroup(representative=candidate, members=tuple(members_by_root[identity]))
        for candidate in ordered
        if (identity := candidate_id(candidate)) in surviving and identity not in applied
    )
