"""Typed repository relationship evidence for later model judgment."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from cyberjury.canonical import text_sha256

type DefinitionKind = Literal["function", "type", "file"]
type ObservationKind = Literal["syntax_call", "import_declaration", "namespace_declaration"]
type StructuralRelationKind = Literal["import", "namespace", "inheritance", "reference"]
type RelationshipTargetStatus = Literal["candidate", "unresolved"]


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def _candidate_name(value: str) -> str:
    return value.rsplit(".", 1)[-1]


@dataclass(frozen=True, order=True, kw_only=True)
class SourceReference:
    """The identity of exact normalized source content within one repository snapshot."""

    id: str
    path: str
    start: int
    end: int
    content_sha256: str

    @classmethod
    def create(cls, *, path: str, start: int, end: int, content: str) -> SourceReference:
        """Build a stable reference to the selected source content."""
        digest = text_sha256(content)
        return cls(
            id=_stable_id("src", path, start, end, digest), path=path, start=start, end=end, content_sha256=digest
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the reference without embedding source text."""
        return {
            "id": self.id,
            "path": self.path,
            "range": [self.start, self.end],
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class DefinitionEvidence:
    """One repository definition that can become a relationship endpoint."""

    id: str
    source: SourceReference
    kind: DefinitionKind
    name: str
    signature: str
    owner_id: str = ""

    @property
    def identity(self) -> str:
        """Identify the exact named source range published to a reviewer."""
        return f"{self.source.path}:{self.name}:{self.source.start}:{self.source.end}"

    @classmethod
    def create(
        cls,
        *,
        source: SourceReference,
        kind: DefinitionKind,
        name: str,
        signature: str = "",
        owner_id: str = "",
    ) -> DefinitionEvidence:
        """Build one stable definition identity from its source boundary."""
        return cls(
            id=_stable_id("def", source.id, kind, name, signature, owner_id),
            source=source,
            kind=kind,
            name=name,
            signature=signature,
            owner_id=owner_id,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize one definition and its exact source reference."""
        return {
            "id": self.id,
            "source": self.source.to_dict(),
            "kind": self.kind,
            "name": self.name,
            "signature": self.signature,
            "owner_id": self.owner_id,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class CallsiteEvidence:
    """One concrete call occurrence inside one caller definition."""

    id: str
    caller_definition_id: str
    source: SourceReference
    expression: str
    callee_spelling: str
    receiver_expression: str = ""

    @classmethod
    def create(
        cls,
        *,
        caller_definition_id: str,
        source: SourceReference,
        expression: str,
        callee_spelling: str,
        receiver_expression: str = "",
    ) -> CallsiteEvidence:
        """Build a stable callsite without claiming a target relationship."""
        return cls(
            id=_stable_id("call", caller_definition_id, source.id, expression),
            caller_definition_id=caller_definition_id,
            source=source,
            expression=expression,
            callee_spelling=callee_spelling,
            receiver_expression=receiver_expression,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize one call occurrence and its syntax endpoints."""
        return {
            "id": self.id,
            "caller_definition_id": self.caller_definition_id,
            "source": self.source.to_dict(),
            "expression": self.expression,
            "callee_spelling": self.callee_spelling,
            "receiver_expression": self.receiver_expression,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class AnalysisObservation:
    """One producer clue that is not promoted to a relationship."""

    id: str
    producer: str
    producer_version: str
    kind: ObservationKind
    subject_ids: tuple[str, ...]
    provenance_source_ids: tuple[str, ...] = ()
    label: str = ""

    @classmethod
    def create(
        cls,
        *,
        producer: str,
        producer_version: str,
        kind: ObservationKind,
        subject_ids: tuple[str, ...],
        provenance_source_ids: tuple[str, ...] = (),
        label: str = "",
    ) -> AnalysisObservation:
        """Build one typed and attributable analysis clue."""
        provenance = tuple(dict.fromkeys(provenance_source_ids))
        return cls(
            id=_stable_id("obs", producer, producer_version, kind, subject_ids, provenance, label),
            producer=producer,
            producer_version=producer_version,
            kind=kind,
            subject_ids=subject_ids,
            provenance_source_ids=provenance,
            label=label,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize one producer observation with explicit provenance."""
        return {
            "id": self.id,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "kind": self.kind,
            "subject_ids": list(self.subject_ids),
            "provenance_source_ids": list(self.provenance_source_ids),
            "label": self.label,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class StructuralRelationshipEvidence:
    """One non-call relationship question that claims no target."""

    id: str
    kind: StructuralRelationKind
    source: SourceReference
    reference: str
    target_status: RelationshipTargetStatus
    source_definition_id: str = ""
    candidate_target_definition_ids: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        kind: StructuralRelationKind,
        source: SourceReference,
        reference: str,
        source_definition_id: str = "",
        candidate_target_definition_ids: tuple[str, ...] = (),
    ) -> StructuralRelationshipEvidence:
        """Build one stable structural question from exact source evidence."""
        candidates = tuple(sorted(set(candidate_target_definition_ids)))
        status: RelationshipTargetStatus = "candidate" if candidates else "unresolved"
        return cls(
            id=_stable_id(
                "struct",
                kind,
                source.id,
                reference,
                source_definition_id,
                candidates,
            ),
            kind=kind,
            source=source,
            reference=reference,
            target_status=status,
            source_definition_id=source_definition_id,
            candidate_target_definition_ids=candidates,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize one structural relation question and producer candidates."""
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source.to_dict(),
            "reference": self.reference,
            "target_status": self.target_status,
            "source_definition_id": self.source_definition_id,
            "candidate_target_definition_ids": list(self.candidate_target_definition_ids),
        }


@dataclass(frozen=True, kw_only=True)
class RelationshipEvidenceBundle:
    """The deterministic evidence collected before any model establishes relationships."""

    sources: tuple[SourceReference, ...] = ()
    definitions: tuple[DefinitionEvidence, ...] = ()
    callsites: tuple[CallsiteEvidence, ...] = ()
    observations: tuple[AnalysisObservation, ...] = ()
    structural_relationships: tuple[StructuralRelationshipEvidence, ...] = ()
    call_candidates: Mapping[str, tuple[str, ...]] = field(init=False)

    def __post_init__(self) -> None:
        """Derive each callsite's candidate callee definitions from the definitions sharing its callee name."""
        object.__setattr__(self, "call_candidates", _call_candidates(self.definitions, self.callsites))

    def canonical(self) -> RelationshipEvidenceBundle:
        """Return the same evidence in the stable record order of its receipt."""
        return RelationshipEvidenceBundle(
            sources=tuple(sorted(self.sources, key=lambda item: (item.path, item.start, item.end, item.id))),
            definitions=tuple(
                sorted(
                    self.definitions,
                    key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
                )
            ),
            callsites=tuple(
                sorted(
                    self.callsites,
                    key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
                )
            ),
            observations=tuple(sorted(self.observations, key=lambda item: (item.subject_ids, item.kind, item.id))),
            structural_relationships=tuple(
                sorted(
                    self.structural_relationships,
                    key=lambda item: (item.source.path, item.source.start, item.kind, item.id),
                )
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize deterministic evidence in stable order."""
        canonical = self.canonical()
        return {
            "sources": [source.to_dict() for source in canonical.sources],
            "definitions": [definition.to_dict() for definition in canonical.definitions],
            "callsites": [callsite.to_dict() for callsite in canonical.callsites],
            "observations": [observation.to_dict() for observation in canonical.observations],
            "structural_relationships": [relationship.to_dict() for relationship in canonical.structural_relationships],
        }


def _call_candidates(
    definitions: tuple[DefinitionEvidence, ...],
    callsites: tuple[CallsiteEvidence, ...],
) -> dict[str, tuple[str, ...]]:
    definitions_by_name: dict[str, set[str]] = {}
    for definition in definitions:
        if definition.kind == "file":
            continue
        definitions_by_name.setdefault(_candidate_name(definition.name), set()).add(definition.id)
    return {
        callsite.id: tuple(sorted(definitions_by_name.get(_candidate_name(callsite.callee_spelling), ())))
        for callsite in callsites
    }
