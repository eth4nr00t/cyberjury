"""Typed repository relationship evidence for later model judgment."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal, get_args

from cyberjury.canonical import normalized_repository_path, text_sha256

type DefinitionKind = Literal["function", "method", "type", "file"]
type ObservationKind = Literal["syntax_call", "import_declaration", "namespace_declaration"]
type StructuralRelationKind = Literal["import", "namespace", "inheritance", "reference"]
type RelationshipTargetStatus = Literal["candidate", "unresolved"]

RELATIONSHIP_EVIDENCE_SCHEMA = "cyberjury.relationship-evidence/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def _candidate_name(value: str) -> str:
    return value.rsplit(".", 1)[-1]


@dataclass(frozen=True, order=True, kw_only=True)
class SourceReference:
    """Identify exact normalized source content within one repository snapshot."""

    id: str
    path: str
    start: int
    end: int
    content_sha256: str

    def __post_init__(self) -> None:
        """Reject an unsafe path, an invalid range, or an id that does not bind its content hash."""
        normalized_repository_path(self.path, "source reference path")
        if isinstance(self.start, bool) or not isinstance(self.start, int) or self.start < 0:
            raise ValueError("source reference start must be a nonnegative integer")
        if isinstance(self.end, bool) or not isinstance(self.end, int) or self.end <= self.start:
            raise ValueError("source reference end must be greater than start")
        if not isinstance(self.content_sha256, str) or not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("source reference content_sha256 must be a SHA-256 hex digest")
        if self.id != _stable_id("src", self.path, self.start, self.end, self.content_sha256):
            raise ValueError("source reference id does not match its source identity")

    @classmethod
    def create(cls, *, path: str, start: int, end: int, content: str) -> SourceReference:
        """Build a stable reference after validating the selected source content."""
        digest = text_sha256(content)
        reference = cls(
            id=_stable_id("src", path, start, end, digest),
            path=path,
            start=start,
            end=end,
            content_sha256=digest,
        )
        if len(content) != end - start:
            raise ValueError("source reference content length must match its normalized character range")
        return reference

    def to_data(self) -> dict[str, object]:
        """Serialize the reference without embedding source text."""
        return {
            "id": self.id,
            "path": self.path,
            "range": [self.start, self.end],
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class DefinitionEvidence:
    """Describe one repository definition that can become a relationship endpoint."""

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
        if not name:
            raise ValueError("definition evidence name must not be empty")
        return cls(
            id=_stable_id("def", source.id, kind, name, signature, owner_id),
            source=source,
            kind=kind,
            name=name,
            signature=signature,
            owner_id=owner_id,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one definition and its exact source reference."""
        return {
            "id": self.id,
            "source": self.source.to_data(),
            "kind": self.kind,
            "name": self.name,
            "signature": self.signature,
            "owner_id": self.owner_id,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class CallsiteEvidence:
    """Identify one concrete call occurrence inside one caller definition."""

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
        if not caller_definition_id or not expression or not callee_spelling:
            raise ValueError("callsite evidence needs caller, expression, and callee spelling")
        if text_sha256(expression) != source.content_sha256:
            raise ValueError("callsite expression must equal its exact source content")
        return cls(
            id=_stable_id("call", caller_definition_id, source.id, expression),
            caller_definition_id=caller_definition_id,
            source=source,
            expression=expression,
            callee_spelling=callee_spelling,
            receiver_expression=receiver_expression,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one call occurrence and its syntax endpoints."""
        return {
            "id": self.id,
            "caller_definition_id": self.caller_definition_id,
            "source": self.source.to_data(),
            "expression": self.expression,
            "callee_spelling": self.callee_spelling,
            "receiver_expression": self.receiver_expression,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class CallRelationshipEvidence:
    """Expose one call target question without claiming a callee binding."""

    id: str
    callsite_id: str
    target_status: RelationshipTargetStatus
    candidate_callee_definition_ids: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        callsite_id: str,
        candidate_callee_definition_ids: tuple[str, ...] = (),
    ) -> CallRelationshipEvidence:
        """Build one deterministic candidate or unresolved call relationship."""
        if not callsite_id:
            raise ValueError("call relationship needs a callsite id")
        candidates = tuple(sorted(set(candidate_callee_definition_ids)))
        status: RelationshipTargetStatus = "candidate" if candidates else "unresolved"
        return cls(
            id=_stable_id("callrel", callsite_id, status, candidates),
            callsite_id=callsite_id,
            target_status=status,
            candidate_callee_definition_ids=candidates,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one explicit call target state."""
        return {
            "id": self.id,
            "callsite_id": self.callsite_id,
            "target_status": self.target_status,
            "candidate_callee_definition_ids": list(self.candidate_callee_definition_ids),
        }


@dataclass(frozen=True, order=True, kw_only=True)
class AnalysisObservation:
    """Record one producer clue without promoting it to a relationship."""

    id: str
    producer: str
    producer_version: str
    kind: ObservationKind
    subject_ids: tuple[str, ...]
    candidate_target_ids: tuple[str, ...] = ()
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
        candidate_target_ids: tuple[str, ...] = (),
        provenance_source_ids: tuple[str, ...] = (),
        label: str = "",
    ) -> AnalysisObservation:
        """Build one typed and attributable analysis clue."""
        if not producer or not producer_version or not subject_ids:
            raise ValueError("analysis observation needs producer identity and subjects")
        candidates = tuple(sorted(set(candidate_target_ids)))
        provenance = tuple(dict.fromkeys(provenance_source_ids))
        return cls(
            id=_stable_id("obs", producer, producer_version, kind, subject_ids, candidates, provenance, label),
            producer=producer,
            producer_version=producer_version,
            kind=kind,
            subject_ids=subject_ids,
            candidate_target_ids=candidates,
            provenance_source_ids=provenance,
            label=label,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one producer observation with explicit provenance."""
        return {
            "id": self.id,
            "producer": self.producer,
            "producer_version": self.producer_version,
            "kind": self.kind,
            "subject_ids": list(self.subject_ids),
            "candidate_target_ids": list(self.candidate_target_ids),
            "provenance_source_ids": list(self.provenance_source_ids),
            "label": self.label,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class StructuralRelationshipEvidence:
    """Identify one non-call relationship question without claiming its target."""

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
        if kind not in get_args(StructuralRelationKind.__value__):
            raise ValueError("structural relationship kind is unsupported")
        if not reference:
            raise ValueError("structural relationship needs a reference")
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

    def to_data(self) -> dict[str, object]:
        """Serialize one structural relation question and producer candidates."""
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source.to_data(),
            "reference": self.reference,
            "target_status": self.target_status,
            "source_definition_id": self.source_definition_id,
            "candidate_target_definition_ids": list(self.candidate_target_definition_ids),
        }


def _contains(outer: SourceReference, inner: SourceReference) -> bool:
    return outer.path == inner.path and outer.start <= inner.start and inner.end <= outer.end


@dataclass(frozen=True, kw_only=True)
class RelationshipEvidenceBundle:
    """Collect deterministic evidence before any model establishes relationships."""

    sources: tuple[SourceReference, ...] = ()
    definitions: tuple[DefinitionEvidence, ...] = ()
    callsites: tuple[CallsiteEvidence, ...] = ()
    observations: tuple[AnalysisObservation, ...] = ()
    structural_relationships: tuple[StructuralRelationshipEvidence, ...] = ()
    call_relationships: tuple[CallRelationshipEvidence, ...] = field(init=False)

    def __post_init__(self) -> None:
        """Require stable unique ids and references, then derive one target state per callsite."""
        self._require_unique_ids()
        self._require_consistent_source_content()
        definitions = {definition.id: definition for definition in self.definitions}
        sources = (
            {source.id for source in self.sources}
            | {definition.source.id for definition in self.definitions}
            | {callsite.source.id for callsite in self.callsites}
        )
        self._require_contained_definitions(definitions)
        self._require_contained_callsites(definitions)
        self._require_known_observation_references(definitions, sources)
        self._require_contained_structural_relationships(definitions, sources)
        object.__setattr__(
            self,
            "call_relationships",
            _call_relationships(self.definitions, self.callsites, self.observations),
        )

    def _require_unique_ids(self) -> None:
        for label, values in (
            ("source", self.sources),
            ("definition", self.definitions),
            ("callsite", self.callsites),
            ("observation", self.observations),
            ("structural relationship", self.structural_relationships),
        ):
            ids = [value.id for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"relationship evidence contains duplicate {label} ids")

    def _require_consistent_source_content(self) -> None:
        references = [
            *self.sources,
            *(definition.source for definition in self.definitions),
            *(callsite.source for callsite in self.callsites),
            *(relationship.source for relationship in self.structural_relationships),
        ]
        coordinates: dict[tuple[str, int, int], str] = {}
        for reference in references:
            digest = coordinates.setdefault((reference.path, reference.start, reference.end), reference.content_sha256)
            if digest != reference.content_sha256:
                raise ValueError(f"relationship evidence has conflicting source content at {reference.path}")

    def _require_contained_definitions(self, definitions: dict[str, DefinitionEvidence]) -> None:
        for definition in self.definitions:
            if not definition.owner_id:
                continue
            owner = definitions.get(definition.owner_id)
            if owner is None:
                raise ValueError(f"relationship definition {definition.id} has an unknown owner")
            if not _contains(owner.source, definition.source) or owner.source == definition.source:
                raise ValueError(f"relationship definition {definition.id} is outside its owner source")

    def _require_contained_callsites(self, definitions: dict[str, DefinitionEvidence]) -> None:
        unknown_callers = {
            callsite.caller_definition_id
            for callsite in self.callsites
            if callsite.caller_definition_id not in definitions
        }
        if unknown_callers:
            raise ValueError(f"relationship evidence contains unknown callers: {sorted(unknown_callers)}")
        for callsite in self.callsites:
            if not _contains(definitions[callsite.caller_definition_id].source, callsite.source):
                raise ValueError(f"relationship callsite {callsite.id} is outside its caller source")

    def _require_known_observation_references(
        self, definitions: dict[str, DefinitionEvidence], sources: set[str]
    ) -> None:
        subjects = set(definitions) | {callsite.id for callsite in self.callsites}
        for observation in self.observations:
            if not set(observation.subject_ids) <= subjects:
                raise ValueError(f"relationship observation {observation.id} contains unknown subjects")
            if not set(observation.candidate_target_ids) <= definitions.keys():
                raise ValueError(f"relationship observation {observation.id} contains unknown candidates")
            if not set(observation.provenance_source_ids) <= sources:
                raise ValueError(f"relationship observation {observation.id} contains unknown source provenance")

    def _require_contained_structural_relationships(
        self, definitions: dict[str, DefinitionEvidence], sources: set[str]
    ) -> None:
        for relationship in self.structural_relationships:
            if relationship.source_definition_id:
                source_definition = definitions.get(relationship.source_definition_id)
                if source_definition is None:
                    raise ValueError(f"structural relationship {relationship.id} contains an unknown source definition")
                if not _contains(source_definition.source, relationship.source):
                    raise ValueError(f"structural relationship {relationship.id} is outside its source definition")
            if not set(relationship.candidate_target_definition_ids) <= definitions.keys():
                raise ValueError(f"structural relationship {relationship.id} contains unknown candidates")
            if relationship.source.id not in sources:
                raise ValueError(f"structural relationship {relationship.id} contains unknown source evidence")

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

    def to_data(self) -> dict[str, object]:
        """Serialize deterministic evidence in stable order."""
        canonical = self.canonical()
        return {
            "schema": RELATIONSHIP_EVIDENCE_SCHEMA,
            "sources": [source.to_data() for source in canonical.sources],
            "definitions": [definition.to_data() for definition in canonical.definitions],
            "callsites": [callsite.to_data() for callsite in canonical.callsites],
            "observations": [observation.to_data() for observation in canonical.observations],
            "structural_relationships": [relationship.to_data() for relationship in canonical.structural_relationships],
        }


def _call_relationships(
    definitions: tuple[DefinitionEvidence, ...],
    callsites: tuple[CallsiteEvidence, ...],
    observations: tuple[AnalysisObservation, ...],
) -> tuple[CallRelationshipEvidence, ...]:
    definitions_by_name: dict[str, set[str]] = {}
    for definition in definitions:
        if definition.kind == "file":
            continue
        definitions_by_name.setdefault(_candidate_name(definition.name), set()).add(definition.id)
    observed: dict[str, set[str]] = {}
    for observation in observations:
        for subject_id in observation.subject_ids:
            if subject_id.startswith("call-"):
                observed.setdefault(subject_id, set()).update(observation.candidate_target_ids)
    return tuple(
        CallRelationshipEvidence.create(
            callsite_id=callsite.id,
            candidate_callee_definition_ids=tuple(
                observed.get(callsite.id, set())
                | definitions_by_name.get(_candidate_name(callsite.callee_spelling), set())
            ),
        )
        for callsite in callsites
    )
