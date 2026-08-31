"""Typed evidence and model established repository relationships."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from string import hexdigits
from typing import Literal, TypedDict

from cyberjury.review.failures import BackendUnavailable

type DefinitionKind = Literal["function", "method", "type", "contract", "modifier", "file", "unknown"]
type ObservationKind = Literal[
    "syntax_call",
    "import_declaration",
    "namespace_declaration",
    "static_call_target",
    "dynamic_call",
]
type StructuralRelationKind = Literal["import", "namespace", "inheritance", "reference"]


def _stable_id(prefix: str, *parts: object) -> str:
    payload = "\0".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


@dataclass(frozen=True, order=True, kw_only=True)
class SourceReference:
    """Identify exact normalized source content within one repository snapshot."""

    id: str
    path: str
    start: int
    end: int
    content_sha256: str
    offset_unit: Literal["normalized_character"] = "normalized_character"

    @classmethod
    def create(cls, *, path: str, start: int, end: int, content: str) -> SourceReference:
        """Build a stable reference after validating the selected source content."""
        normalized = PurePosixPath(path)
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or normalized.as_posix() != path
            or ".." in normalized.parts
        ):
            raise ValueError("source reference path must be a nonempty normalized repository path")
        if isinstance(start, bool) or not isinstance(start, int) or start < 0:
            raise ValueError("source reference start must be a nonnegative integer")
        if isinstance(end, bool) or not isinstance(end, int) or end <= start:
            raise ValueError("source reference end must be greater than start")
        if len(content) != end - start:
            raise ValueError("source reference content length must match its normalized character range")
        digest = hashlib.sha256(content.encode()).hexdigest()
        return cls(
            id=_stable_id("src", path, start, end, digest),
            path=path,
            start=start,
            end=end,
            content_sha256=digest,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize the reference without embedding source text."""
        return {
            "id": self.id,
            "path": self.path,
            "range": [self.start, self.end],
            "offset_unit": self.offset_unit,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class ParameterEvidence:
    """Preserve one declared parameter without claiming an argument binding."""

    id: str
    position: int
    name: str
    source: SourceReference
    declaration: str
    type_name: str = ""

    @classmethod
    def create(
        cls,
        *,
        position: int,
        name: str,
        source: SourceReference,
        declaration: str,
        type_name: str = "",
    ) -> ParameterEvidence:
        """Build a stable parameter identity from exact declaration source."""
        if isinstance(position, bool) or not isinstance(position, int) or position < 0:
            raise ValueError("parameter position must be a nonnegative integer")
        if not declaration:
            raise ValueError("parameter evidence needs a declaration")
        return cls(
            id=_stable_id("param", source.id, position, name, declaration, type_name),
            position=position,
            name=name,
            source=source,
            declaration=declaration,
            type_name=type_name,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one exact parameter declaration."""
        return {
            "id": self.id,
            "position": self.position,
            "name": self.name,
            "source": self.source.to_data(),
            "declaration": self.declaration,
            "type_name": self.type_name,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class ReceiverEvidence:
    """Preserve one receiver declaration without claiming a call binding."""

    id: str
    name: str
    source: SourceReference
    declaration: str
    type_name: str = ""

    @classmethod
    def create(
        cls,
        *,
        name: str,
        source: SourceReference,
        declaration: str,
        type_name: str = "",
    ) -> ReceiverEvidence:
        """Build a stable receiver identity from exact declaration source."""
        if not name or not declaration:
            raise ValueError("receiver evidence needs a name and declaration")
        return cls(
            id=_stable_id("receiver", source.id, name, declaration, type_name),
            name=name,
            source=source,
            declaration=declaration,
            type_name=type_name,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one exact receiver declaration."""
        return {
            "id": self.id,
            "name": self.name,
            "source": self.source.to_data(),
            "declaration": self.declaration,
            "type_name": self.type_name,
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
    parameters: tuple[ParameterEvidence, ...] = ()
    receiver: ReceiverEvidence | None = None

    @classmethod
    def create(
        cls,
        *,
        source: SourceReference,
        kind: DefinitionKind,
        name: str,
        signature: str = "",
        owner_id: str = "",
        parameters: tuple[ParameterEvidence, ...] = (),
        receiver: ReceiverEvidence | None = None,
    ) -> DefinitionEvidence:
        """Build one stable definition identity from its source boundary."""
        if not name:
            raise ValueError("definition evidence name must not be empty")
        positions = tuple(parameter.position for parameter in parameters)
        if positions != tuple(range(len(parameters))):
            raise ValueError("definition parameters must use contiguous declaration order positions")
        if any(
            parameter.source.path != source.path
            or parameter.source.start < source.start
            or parameter.source.end > source.end
            for parameter in parameters
        ):
            raise ValueError("definition parameter sources must remain inside the definition source")
        if receiver is not None and (
            kind != "method"
            or receiver.source.path != source.path
            or receiver.source.start < source.start
            or receiver.source.end > source.end
        ):
            raise ValueError("definition receiver source must remain inside a method definition")
        return cls(
            id=_stable_id("def", source.id, kind, name, signature, owner_id, receiver.id if receiver else ""),
            source=source,
            kind=kind,
            name=name,
            signature=signature,
            owner_id=owner_id,
            parameters=parameters,
            receiver=receiver,
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
            "parameters": [parameter.to_data() for parameter in self.parameters],
            "receiver": self.receiver.to_data() if self.receiver is not None else None,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class ArgumentEvidence:
    """Preserve one call argument as a future data relationship endpoint."""

    position: int
    expression: str | None
    source: SourceReference | None = None
    name: str = ""
    type_name: str = ""

    def __post_init__(self) -> None:
        """Reject malformed argument positions and empty expressions."""
        if isinstance(self.position, bool) or not isinstance(self.position, int) or self.position < 0:
            raise ValueError("argument position must be a nonnegative integer")
        if self.expression == "":
            raise ValueError("argument expression must use null when the producer has no expression")
        if self.expression is None and self.source is not None:
            raise ValueError("argument source cannot exist without its expression")

    def to_data(self) -> dict[str, object]:
        """Serialize one ordered call argument."""
        return {
            "position": self.position,
            "name": self.name,
            "type_name": self.type_name,
            "expression": self.expression,
            "source": self.source.to_data() if self.source is not None else None,
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
    arguments: tuple[ArgumentEvidence, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        caller_definition_id: str,
        source: SourceReference,
        expression: str,
        callee_spelling: str,
        receiver_expression: str = "",
        arguments: tuple[ArgumentEvidence, ...] = (),
    ) -> CallsiteEvidence:
        """Build a stable callsite without claiming a target relationship."""
        if not caller_definition_id or not expression or not callee_spelling:
            raise ValueError("callsite evidence needs caller, expression, and callee spelling")
        positions = tuple(argument.position for argument in arguments)
        if positions != tuple(range(len(arguments))):
            raise ValueError("callsite arguments must use contiguous source order positions")
        return cls(
            id=_stable_id("call", caller_definition_id, source.id, expression),
            caller_definition_id=caller_definition_id,
            source=source,
            expression=expression,
            callee_spelling=callee_spelling,
            receiver_expression=receiver_expression,
            arguments=arguments,
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
            "arguments": [argument.to_data() for argument in self.arguments],
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
        candidates = tuple(dict.fromkeys(candidate_target_ids))
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
    source_file: str
    source: SourceReference
    reference: str
    source_definition_id: str = ""
    candidate_target_definition_ids: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        kind: StructuralRelationKind,
        source_file: str,
        source: SourceReference,
        reference: str,
        source_definition_id: str = "",
        candidate_target_definition_ids: tuple[str, ...] = (),
    ) -> StructuralRelationshipEvidence:
        """Build one stable structural question from exact source evidence."""
        if kind not in {"import", "namespace", "inheritance", "reference"}:
            raise ValueError("structural relationship kind is unsupported")
        if not source_file or source.path != source_file or not reference:
            raise ValueError("structural relationship needs matching source file and reference")
        candidates = tuple(dict.fromkeys(candidate_target_definition_ids))
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
            source_file=source_file,
            source=source,
            reference=reference,
            source_definition_id=source_definition_id,
            candidate_target_definition_ids=candidates,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one structural relation question and producer candidates."""
        return {
            "id": self.id,
            "kind": self.kind,
            "source_file": self.source_file,
            "source": self.source.to_data(),
            "reference": self.reference,
            "source_definition_id": self.source_definition_id,
            "candidate_target_definition_ids": list(self.candidate_target_definition_ids),
        }


class RelationshipEvidenceData(TypedDict):
    """JSON shape persisted by every facts backend."""

    sources: list[dict[str, object]]
    definitions: list[dict[str, object]]
    callsites: list[dict[str, object]]
    observations: list[dict[str, object]]
    structural_subjects: list[dict[str, object]]


@dataclass(frozen=True, kw_only=True)
class RelationshipEvidenceBundle:
    """Collect deterministic evidence before any model establishes relationships."""

    sources: tuple[SourceReference, ...] = ()
    definitions: tuple[DefinitionEvidence, ...] = ()
    callsites: tuple[CallsiteEvidence, ...] = ()
    observations: tuple[AnalysisObservation, ...] = ()
    structural_subjects: tuple[StructuralRelationshipEvidence, ...] = ()

    def __post_init__(self) -> None:
        """Require stable unique ids and references within one bundle."""
        source_ids = [source.id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("relationship evidence contains duplicate source ids")
        for label, values in (
            ("definition", self.definitions),
            ("callsite", self.callsites),
            ("observation", self.observations),
            ("structural subject", self.structural_subjects),
        ):
            ids = [value.id for value in values]
            if len(ids) != len(set(ids)):
                raise ValueError(f"relationship evidence contains duplicate {label} ids")
        definitions = {definition.id for definition in self.definitions}
        calls = {callsite.id for callsite in self.callsites}
        sources = (
            {source.id for source in self.sources}
            | {definition.source.id for definition in self.definitions}
            | {definition.receiver.source.id for definition in self.definitions if definition.receiver is not None}
            | {callsite.source.id for callsite in self.callsites}
            | {
                argument.source.id
                for callsite in self.callsites
                for argument in callsite.arguments
                if argument.source is not None
            }
        )
        unknown_callers = {
            callsite.caller_definition_id
            for callsite in self.callsites
            if callsite.caller_definition_id not in definitions
        }
        if unknown_callers:
            raise ValueError(f"relationship evidence contains unknown callers: {sorted(unknown_callers)}")
        subjects = definitions | calls
        for observation in self.observations:
            if not set(observation.subject_ids) <= subjects:
                raise ValueError(f"relationship observation {observation.id} contains unknown subjects")
            if not set(observation.candidate_target_ids) <= definitions:
                raise ValueError(f"relationship observation {observation.id} contains unknown candidates")
            if not set(observation.provenance_source_ids) <= sources:
                raise ValueError(f"relationship observation {observation.id} contains unknown source provenance")
        for subject in self.structural_subjects:
            if subject.source_definition_id and subject.source_definition_id not in definitions:
                raise ValueError(f"structural relationship {subject.id} contains an unknown source definition")
            if not set(subject.candidate_target_definition_ids) <= definitions:
                raise ValueError(f"structural relationship {subject.id} contains unknown candidates")
            if subject.source.id not in sources:
                raise ValueError(f"structural relationship {subject.id} contains unknown source evidence")

    def to_data(self) -> RelationshipEvidenceData:
        """Serialize deterministic evidence in stable order."""
        return {
            "sources": [
                source.to_data()
                for source in sorted(self.sources, key=lambda item: (item.path, item.start, item.end, item.id))
            ],
            "definitions": [
                definition.to_data()
                for definition in sorted(
                    self.definitions,
                    key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
                )
            ],
            "callsites": [
                callsite.to_data()
                for callsite in sorted(
                    self.callsites,
                    key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
                )
            ],
            "observations": [
                observation.to_data()
                for observation in sorted(
                    self.observations,
                    key=lambda item: (item.subject_ids, item.kind, item.id),
                )
            ],
            "structural_subjects": [
                subject.to_data()
                for subject in sorted(
                    self.structural_subjects,
                    key=lambda item: (item.source_file, item.source.start, item.kind, item.id),
                )
            ],
        }


def rebase_relationship_evidence(
    bundle: RelationshipEvidenceBundle,
    prefix: str,
    read_source: Callable[[str], str],
) -> RelationshipEvidenceBundle:
    """Rebuild stable ids when facts were extracted below the review root."""
    if not prefix:
        return bundle
    source_map: dict[str, SourceReference] = {}
    original_sources = {value.id: value for value in bundle.sources}
    for value in bundle.definitions:
        original_sources[value.source.id] = value.source
        for parameter in value.parameters:
            original_sources[parameter.source.id] = parameter.source
        if value.receiver is not None:
            original_sources[value.receiver.source.id] = value.receiver.source
    for value in bundle.callsites:
        original_sources[value.source.id] = value.source
        for argument in value.arguments:
            if argument.source is not None:
                original_sources[argument.source.id] = argument.source
    for value in bundle.structural_subjects:
        original_sources[value.source.id] = value.source

    def source(reference: SourceReference) -> SourceReference:
        existing = source_map.get(reference.id)
        if existing is not None:
            return existing
        path = f"{prefix}/{reference.path}"
        content = read_source(path)[reference.start : reference.end]
        rebased = SourceReference.create(
            path=path,
            start=reference.start,
            end=reference.end,
            content=content,
        )
        if rebased.content_sha256 != reference.content_sha256:
            raise BackendUnavailable(f"rebased relationship source changed at {path}:{reference.start}")
        source_map[reference.id] = rebased
        return rebased

    definitions_by_id = {definition.id: definition for definition in bundle.definitions}
    rebased_definitions: dict[str, DefinitionEvidence] = {}

    def definition(value: DefinitionEvidence) -> DefinitionEvidence:
        existing = rebased_definitions.get(value.id)
        if existing is not None:
            return existing
        owner_id = ""
        if value.owner_id:
            owner = definitions_by_id.get(value.owner_id)
            if owner is None:
                raise BackendUnavailable(f"relationship definition {value.id} has an unknown owner")
            owner_id = definition(owner).id
        rebased = DefinitionEvidence.create(
            source=source(value.source),
            kind=value.kind,
            name=value.name,
            signature=value.signature,
            owner_id=owner_id,
            parameters=tuple(
                ParameterEvidence.create(
                    position=parameter.position,
                    name=parameter.name,
                    source=source(parameter.source),
                    declaration=parameter.declaration,
                    type_name=parameter.type_name,
                )
                for parameter in value.parameters
            ),
            receiver=(
                ReceiverEvidence.create(
                    name=value.receiver.name,
                    source=source(value.receiver.source),
                    declaration=value.receiver.declaration,
                    type_name=value.receiver.type_name,
                )
                if value.receiver is not None
                else None
            ),
        )
        rebased_definitions[value.id] = rebased
        return rebased

    definitions = tuple(definition(value) for value in bundle.definitions)
    callsites: list[CallsiteEvidence] = []
    callsite_ids: dict[str, str] = {}
    for value in bundle.callsites:
        caller = rebased_definitions.get(value.caller_definition_id)
        if caller is None:
            raise BackendUnavailable(f"relationship callsite {value.id} has an unknown caller")
        rebased = CallsiteEvidence.create(
            caller_definition_id=caller.id,
            source=source(value.source),
            expression=value.expression,
            callee_spelling=value.callee_spelling,
            receiver_expression=value.receiver_expression,
            arguments=tuple(
                ArgumentEvidence(
                    position=argument.position,
                    expression=argument.expression,
                    name=argument.name,
                    type_name=argument.type_name,
                    source=source(argument.source) if argument.source is not None else None,
                )
                for argument in value.arguments
            ),
        )
        callsites.append(rebased)
        callsite_ids[value.id] = rebased.id
    id_map = {**{old: value.id for old, value in rebased_definitions.items()}, **callsite_ids}
    observations = tuple(
        AnalysisObservation.create(
            producer=value.producer,
            producer_version=value.producer_version,
            kind=value.kind,
            subject_ids=tuple(id_map[item] for item in value.subject_ids),
            candidate_target_ids=tuple(id_map[item] for item in value.candidate_target_ids),
            provenance_source_ids=tuple(source(original_sources[item]).id for item in value.provenance_source_ids),
            label=value.label,
        )
        for value in bundle.observations
    )
    structural_subjects = tuple(
        StructuralRelationshipEvidence.create(
            kind=value.kind,
            source_file=f"{prefix}/{value.source_file}",
            source=source(value.source),
            reference=value.reference,
            source_definition_id=id_map[value.source_definition_id] if value.source_definition_id else "",
            candidate_target_definition_ids=tuple(id_map[item] for item in value.candidate_target_definition_ids),
        )
        for value in bundle.structural_subjects
    )
    return RelationshipEvidenceBundle(
        sources=tuple(source(value) for value in bundle.sources),
        definitions=definitions,
        callsites=tuple(callsites),
        observations=observations,
        structural_subjects=structural_subjects,
    )


def relationship_evidence_from_data(value: object) -> RelationshipEvidenceBundle:
    """Load persisted relationship evidence or fail on any schema drift."""
    data = _mapping(
        value,
        "relationship evidence",
        {"sources", "definitions", "callsites", "observations", "structural_subjects"},
    )
    sources = tuple(_source_from_data(item, "relationship source") for item in _records(data["sources"], "sources"))
    definitions = tuple(_definition_from_data(item) for item in _records(data["definitions"], "definitions"))
    callsites = tuple(_callsite_from_data(item) for item in _records(data["callsites"], "callsites"))
    observations = tuple(_observation_from_data(item) for item in _records(data["observations"], "observations"))
    structural_subjects = tuple(
        _structural_subject_from_data(item) for item in _records(data["structural_subjects"], "structural_subjects")
    )
    return RelationshipEvidenceBundle(
        sources=sources,
        definitions=definitions,
        callsites=callsites,
        observations=observations,
        structural_subjects=structural_subjects,
    )


def _source_from_data(value: object, location: str) -> SourceReference:
    data = _mapping(value, location, {"id", "path", "range", "offset_unit", "content_sha256"})
    path = _text(data["path"], f"{location}.path")
    span = data["range"]
    if not isinstance(span, list) or len(span) != 2:
        raise BackendUnavailable(f"{location}.range must contain start and end")
    start, end = span
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or start < 0
        or isinstance(end, bool)
        or not isinstance(end, int)
        or end <= start
    ):
        raise BackendUnavailable(f"{location}.range must be a valid normalized character range")
    if data["offset_unit"] != "normalized_character":
        raise BackendUnavailable(f"{location}.offset_unit must be normalized_character")
    digest = _text(data["content_sha256"], f"{location}.content_sha256")
    if len(digest) != 64 or any(character not in hexdigits for character in digest):
        raise BackendUnavailable(f"{location}.content_sha256 must be a SHA-256 hex digest")
    expected = _stable_id("src", path, start, end, digest)
    if data["id"] != expected:
        raise BackendUnavailable(f"{location}.id does not match its source identity")
    return SourceReference(id=expected, path=path, start=start, end=end, content_sha256=digest)


def _definition_from_data(value: object) -> DefinitionEvidence:
    data = _mapping(
        value,
        "definition evidence",
        {"id", "source", "kind", "name", "signature", "owner_id", "parameters", "receiver"},
    )
    source = _source_from_data(data["source"], "definition evidence source")
    kind = data["kind"]
    if kind not in {"function", "method", "type", "contract", "modifier", "file", "unknown"}:
        raise BackendUnavailable("definition evidence kind is unsupported")
    name = _text(data["name"], "definition evidence name")
    signature = _string(data["signature"], "definition evidence signature")
    owner_id = _string(data["owner_id"], "definition evidence owner_id")
    definition = DefinitionEvidence.create(
        source=source,
        kind=kind,
        name=name,
        signature=signature,
        owner_id=owner_id,
        parameters=tuple(
            _parameter_from_data(item) for item in _records(data["parameters"], "definition evidence parameters")
        ),
        receiver=_receiver_from_data(data["receiver"]),
    )
    if data["id"] != definition.id:
        raise BackendUnavailable("definition evidence id does not match its fields")
    return definition


def _parameter_from_data(value: object) -> ParameterEvidence:
    data = _mapping(
        value,
        "parameter evidence",
        {"id", "position", "name", "source", "declaration", "type_name"},
    )
    position = data["position"]
    if isinstance(position, bool) or not isinstance(position, int) or position < 0:
        raise BackendUnavailable("parameter evidence position must be a nonnegative integer")
    try:
        parameter = ParameterEvidence.create(
            position=position,
            name=_string(data["name"], "parameter evidence name"),
            source=_source_from_data(data["source"], "parameter evidence source"),
            declaration=_text(data["declaration"], "parameter evidence declaration"),
            type_name=_string(data["type_name"], "parameter evidence type_name"),
        )
    except ValueError as exc:
        raise BackendUnavailable(str(exc)) from exc
    if data["id"] != parameter.id:
        raise BackendUnavailable("parameter evidence id does not match its fields")
    return parameter


def _receiver_from_data(value: object) -> ReceiverEvidence | None:
    if value is None:
        return None
    data = _mapping(value, "receiver evidence", {"id", "name", "source", "declaration", "type_name"})
    try:
        receiver = ReceiverEvidence.create(
            name=_text(data["name"], "receiver evidence name"),
            source=_source_from_data(data["source"], "receiver evidence source"),
            declaration=_text(data["declaration"], "receiver evidence declaration"),
            type_name=_string(data["type_name"], "receiver evidence type_name"),
        )
    except ValueError as exc:
        raise BackendUnavailable(str(exc)) from exc
    if data["id"] != receiver.id:
        raise BackendUnavailable("receiver evidence id does not match its fields")
    return receiver


def _argument_from_data(value: object) -> ArgumentEvidence:
    data = _mapping(value, "argument evidence", {"position", "name", "type_name", "expression", "source"})
    position = data["position"]
    if isinstance(position, bool) or not isinstance(position, int) or position < 0:
        raise BackendUnavailable("argument evidence position must be a nonnegative integer")
    expression = data["expression"]
    if expression is not None and not isinstance(expression, str):
        raise BackendUnavailable("argument evidence expression must be text or null")
    source = _source_from_data(data["source"], "argument evidence source") if data["source"] is not None else None
    try:
        return ArgumentEvidence(
            position=position,
            expression=expression,
            name=_string(data["name"], "argument evidence name"),
            type_name=_string(data["type_name"], "argument evidence type_name"),
            source=source,
        )
    except ValueError as exc:
        raise BackendUnavailable(str(exc)) from exc


def _callsite_from_data(value: object) -> CallsiteEvidence:
    data = _mapping(
        value,
        "callsite evidence",
        {
            "id",
            "caller_definition_id",
            "source",
            "expression",
            "callee_spelling",
            "receiver_expression",
            "arguments",
        },
    )
    callsite = CallsiteEvidence.create(
        caller_definition_id=_text(data["caller_definition_id"], "callsite caller_definition_id"),
        source=_source_from_data(data["source"], "callsite evidence source"),
        expression=_text(data["expression"], "callsite expression"),
        callee_spelling=_text(data["callee_spelling"], "callsite callee_spelling"),
        receiver_expression=_string(data["receiver_expression"], "callsite receiver_expression"),
        arguments=tuple(_argument_from_data(item) for item in _records(data["arguments"], "callsite arguments")),
    )
    if data["id"] != callsite.id:
        raise BackendUnavailable("callsite evidence id does not match its fields")
    return callsite


def _observation_from_data(value: object) -> AnalysisObservation:
    data = _mapping(
        value,
        "analysis observation",
        {
            "id",
            "producer",
            "producer_version",
            "kind",
            "subject_ids",
            "candidate_target_ids",
            "provenance_source_ids",
            "label",
        },
    )
    kind = data["kind"]
    if kind not in {
        "syntax_call",
        "import_declaration",
        "namespace_declaration",
        "static_call_target",
        "dynamic_call",
    }:
        raise BackendUnavailable("analysis observation kind is unsupported")
    observation = AnalysisObservation.create(
        producer=_text(data["producer"], "analysis observation producer"),
        producer_version=_text(data["producer_version"], "analysis observation producer_version"),
        kind=kind,
        subject_ids=_string_tuple(data["subject_ids"], "analysis observation subject_ids", required=True),
        candidate_target_ids=_string_tuple(data["candidate_target_ids"], "analysis observation candidate_target_ids"),
        provenance_source_ids=_string_tuple(
            data["provenance_source_ids"], "analysis observation provenance_source_ids"
        ),
        label=_string(data["label"], "analysis observation label"),
    )
    if data["id"] != observation.id:
        raise BackendUnavailable("analysis observation id does not match its fields")
    return observation


def _structural_subject_from_data(value: object) -> StructuralRelationshipEvidence:
    data = _mapping(
        value,
        "structural relationship evidence",
        {
            "id",
            "kind",
            "source_file",
            "source",
            "reference",
            "source_definition_id",
            "candidate_target_definition_ids",
        },
    )
    kind = data["kind"]
    if kind not in {"import", "namespace", "inheritance", "reference"}:
        raise BackendUnavailable("structural relationship evidence kind is unsupported")
    try:
        subject = StructuralRelationshipEvidence.create(
            kind=kind,
            source_file=_text(data["source_file"], "structural relationship source_file"),
            source=_source_from_data(data["source"], "structural relationship source"),
            reference=_text(data["reference"], "structural relationship reference"),
            source_definition_id=_string(data["source_definition_id"], "structural relationship source_definition_id"),
            candidate_target_definition_ids=_string_tuple(
                data["candidate_target_definition_ids"],
                "structural relationship candidate_target_definition_ids",
            ),
        )
    except ValueError as exc:
        raise BackendUnavailable(str(exc)) from exc
    if data["id"] != subject.id:
        raise BackendUnavailable("structural relationship evidence id does not match its fields")
    return subject


def _mapping(value: object, location: str, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise BackendUnavailable(f"{location} must contain exactly: {', '.join(sorted(fields))}")
    return value


def _records(value: object, location: str) -> list[object]:
    if not isinstance(value, list):
        raise BackendUnavailable(f"{location} must be a list")
    return value


def _string(value: object, location: str) -> str:
    if not isinstance(value, str):
        raise BackendUnavailable(f"{location} must be text")
    return value


def _text(value: object, location: str) -> str:
    text = _string(value, location)
    if not text:
        raise BackendUnavailable(f"{location} must not be empty")
    return text


def _string_tuple(value: object, location: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise BackendUnavailable(f"{location} must be a list of nonempty strings")
    if required and not value:
        raise BackendUnavailable(f"{location} must not be empty")
    if len(value) != len(set(value)):
        raise BackendUnavailable(f"{location} must not contain duplicates")
    return tuple(value)


__all__ = [
    "AnalysisObservation",
    "ArgumentEvidence",
    "CallsiteEvidence",
    "DefinitionEvidence",
    "ParameterEvidence",
    "ReceiverEvidence",
    "RelationshipEvidenceBundle",
    "SourceReference",
    "StructuralRelationshipEvidence",
    "rebase_relationship_evidence",
    "relationship_evidence_from_data",
]
