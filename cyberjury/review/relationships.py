"""Typed evidence and model established repository relationships."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from string import hexdigits
from typing import Literal, TypedDict

from cyberjury.review.failures import BackendUnavailable

type DefinitionKind = Literal["function", "method", "type", "contract", "modifier", "unknown"]
type ObservationKind = Literal[
    "syntax_call",
    "import_binding",
    "namespace_binding",
    "static_call_target",
    "dynamic_call",
]
type TargetCoverage = Literal["complete", "incomplete"]
type DataCoverage = Literal["complete", "incomplete"]
type NavigationQueryKind = Literal["symbol", "text"]
type NavigationQueryPurpose = Literal["target_candidate", "context_evidence"]
type ContextRelationKind = Literal["data", "control", "type", "registration"]
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
        if not name or not declaration:
            raise ValueError("parameter evidence needs a name and declaration")
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
class DefinitionEvidence:
    """Describe one repository definition that can become a relationship endpoint."""

    id: str
    source: SourceReference
    kind: DefinitionKind
    name: str
    signature: str
    owner_id: str = ""
    parameters: tuple[ParameterEvidence, ...] = ()

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
    ) -> DefinitionEvidence:
        """Build one stable definition identity from its source boundary."""
        if not name:
            raise ValueError("definition evidence name must not be empty")
        positions = tuple(parameter.position for parameter in parameters)
        if positions != tuple(range(len(parameters))):
            raise ValueError("definition parameters must use contiguous declaration order positions")
        return cls(
            id=_stable_id("def", source.id, kind, name, signature, owner_id),
            source=source,
            kind=kind,
            name=name,
            signature=signature,
            owner_id=owner_id,
            parameters=parameters,
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


@dataclass(frozen=True, order=True, kw_only=True)
class SupportedCallRelation:
    """Bind one callsite to one model supported target definition."""

    target_definition_id: str
    evidence_ids: tuple[str, ...]
    argument_relations: tuple[ArgumentToParameterRelation, ...] = ()
    data_coverage: DataCoverage = "complete"
    unmapped_argument_positions: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        """Require every supported edge to cite evidence."""
        if not self.target_definition_id or not self.evidence_ids:
            raise ValueError("supported relation needs a target and evidence ids")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("supported relation evidence ids must be unique")
        positions = tuple(relation.argument_position for relation in self.argument_relations)
        if len(positions) != len(set(positions)):
            raise ValueError("supported relation cannot map one argument more than once")
        if any(
            isinstance(position, bool) or not isinstance(position, int) or position < 0
            for position in self.unmapped_argument_positions
        ):
            raise ValueError("unmapped argument positions must be nonnegative integers")
        if len(self.unmapped_argument_positions) != len(set(self.unmapped_argument_positions)):
            raise ValueError("unmapped argument positions must be unique")
        if set(positions).intersection(self.unmapped_argument_positions):
            raise ValueError("mapped and unmapped argument positions must be disjoint")
        if self.data_coverage == "complete" and self.unmapped_argument_positions:
            raise ValueError("complete data coverage cannot retain unmapped arguments")
        if self.data_coverage == "incomplete" and not self.unmapped_argument_positions:
            raise ValueError("incomplete data coverage must identify unmapped arguments")

    def to_data(self) -> dict[str, object]:
        """Serialize one model supported edge and its provenance."""
        return {
            "target_definition_id": self.target_definition_id,
            "evidence_ids": list(self.evidence_ids),
            "argument_relations": [relation.to_data() for relation in self.argument_relations],
            "data_coverage": self.data_coverage,
            "unmapped_argument_positions": list(self.unmapped_argument_positions),
        }


@dataclass(frozen=True, order=True, kw_only=True)
class RelatedContext:
    """Bind a callsite to non-callee source required for semantic grounding."""

    definition_id: str
    kind: ContextRelationKind
    evidence_ids: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        """Require one categorized and attributable context relationship."""
        if not self.definition_id or self.kind not in {"data", "control", "type", "registration"}:
            raise ValueError("related context needs a definition and supported kind")
        if not self.evidence_ids or len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("related context evidence ids must be nonempty and unique")
        if not self.reason.strip():
            raise ValueError("related context reason must not be empty")

    def to_data(self) -> dict[str, object]:
        """Serialize one model established context relationship."""
        return {
            "definition_id": self.definition_id,
            "kind": self.kind,
            "evidence_ids": list(self.evidence_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class SupportedStructuralRelation:
    """Bind one structural subject to a model supported target definition."""

    target_definition_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require one unique and attributable structural edge."""
        if not self.target_definition_id or not self.evidence_ids:
            raise ValueError("supported structural relation needs a target and evidence ids")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("supported structural relation evidence ids must be unique")

    def to_data(self) -> dict[str, object]:
        """Serialize one model supported structural edge."""
        return {
            "target_definition_id": self.target_definition_id,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, order=True, kw_only=True)
class ArgumentToParameterRelation:
    """Record one model established value transfer across a supported call edge."""

    argument_position: int
    parameter_id: str
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require one attributable call argument to parameter mapping."""
        if isinstance(self.argument_position, bool) or not isinstance(self.argument_position, int):
            raise ValueError("argument relation position must be an integer")
        if self.argument_position < 0 or not self.parameter_id or not self.evidence_ids:
            raise ValueError("argument relation needs a position, parameter, and evidence ids")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("argument relation evidence ids must be unique")

    def to_data(self) -> dict[str, object]:
        """Serialize one cross definition value relationship."""
        return {
            "argument_position": self.argument_position,
            "parameter_id": self.parameter_id,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True, order=True, kw_only=True)
class NavigationReceipt:
    """Record one deterministic repository query issued during model reasoning."""

    id: str
    kind: NavigationQueryKind
    purpose: NavigationQueryPurpose
    query: str
    path_prefix: str
    cursor: int
    returned_definition_ids: tuple[str, ...]
    returned_source_ids: tuple[str, ...]
    next_cursor: int | None

    @classmethod
    def create(
        cls,
        *,
        kind: NavigationQueryKind,
        purpose: NavigationQueryPurpose,
        query: str,
        path_prefix: str,
        cursor: int,
        returned_definition_ids: tuple[str, ...],
        returned_source_ids: tuple[str, ...],
        next_cursor: int | None,
    ) -> NavigationReceipt:
        """Build an attributable query receipt from deterministic results."""
        if kind not in {"symbol", "text"} or not query:
            raise ValueError("navigation receipt needs a supported kind and query")
        if purpose not in {"target_candidate", "context_evidence"}:
            raise ValueError("navigation receipt purpose is unsupported")
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ValueError("navigation receipt cursor must be a nonnegative integer")
        if next_cursor is not None and (
            isinstance(next_cursor, bool) or not isinstance(next_cursor, int) or next_cursor <= cursor
        ):
            raise ValueError("navigation receipt next cursor must advance")
        payload = (
            kind,
            purpose,
            query,
            path_prefix,
            cursor,
            returned_definition_ids,
            returned_source_ids,
            next_cursor,
        )
        return cls(
            id=_stable_id("nav", *payload),
            kind=kind,
            purpose=purpose,
            query=query,
            path_prefix=path_prefix,
            cursor=cursor,
            returned_definition_ids=returned_definition_ids,
            returned_source_ids=returned_source_ids,
            next_cursor=next_cursor,
        )

    def to_data(self) -> dict[str, object]:
        """Serialize one code produced navigation receipt."""
        return {
            "id": self.id,
            "kind": self.kind,
            "purpose": self.purpose,
            "query": self.query,
            "path_prefix": self.path_prefix,
            "cursor": self.cursor,
            "returned_definition_ids": list(self.returned_definition_ids),
            "returned_source_ids": list(self.returned_source_ids),
            "next_cursor": self.next_cursor,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class ExcludedCandidate:
    """Record one candidate rejected by controlling source evidence."""

    target_definition_id: str
    evidence_ids: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        """Require attributable evidence and an explicit exclusion reason."""
        if not self.target_definition_id or not self.evidence_ids or not self.reason.strip():
            raise ValueError("excluded candidate needs a target, evidence ids, and reason")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("excluded candidate evidence ids must be unique")

    def to_data(self) -> dict[str, object]:
        """Serialize one evidence backed candidate exclusion."""
        return {
            "target_definition_id": self.target_definition_id,
            "evidence_ids": list(self.evidence_ids),
            "reason": self.reason,
        }


@dataclass(frozen=True, order=True, kw_only=True)
class CallsiteRelationshipResult:
    """Store model established relations separately from candidates and coverage."""

    callsite_id: str
    supported_relations: tuple[SupportedCallRelation, ...]
    candidate_target_ids: tuple[str, ...]
    target_coverage: TargetCoverage
    coverage_limitation_ids: tuple[str, ...]
    reason: str
    excluded_candidates: tuple[ExcludedCandidate, ...] = ()
    navigation_receipts: tuple[NavigationReceipt, ...] = ()
    related_contexts: tuple[RelatedContext, ...] = ()

    def validate(
        self,
        bundle: RelationshipEvidenceBundle,
        *,
        published_target_ids: frozenset[str] | None = None,
        published_limitation_ids: frozenset[str] = frozenset(),
    ) -> None:
        """Reject invented ids, incomplete receipts, and unsupported completeness."""
        calls = {callsite.id for callsite in bundle.callsites}
        definitions = {definition.id for definition in bundle.definitions}
        observations = {observation.id for observation in bundle.observations}
        sources = (
            {source.id for source in bundle.sources}
            | {definition.source.id for definition in bundle.definitions}
            | {parameter.source.id for definition in bundle.definitions for parameter in definition.parameters}
            | {callsite.source.id for callsite in bundle.callsites}
            | {
                argument.source.id
                for callsite in bundle.callsites
                for argument in callsite.arguments
                if argument.source is not None
            }
            | {subject.source.id for subject in bundle.structural_subjects}
        )
        if self.callsite_id not in calls:
            raise BackendUnavailable(f"relationship result references unknown callsite {self.callsite_id}")
        targets = tuple(relation.target_definition_id for relation in self.supported_relations)
        excluded = tuple(candidate.target_definition_id for candidate in self.excluded_candidates)
        if len(targets) != len(set(targets)):
            raise BackendUnavailable("relationship result contains duplicate supported targets")
        if len(excluded) != len(set(excluded)):
            raise BackendUnavailable("relationship result contains duplicate excluded candidates")
        candidates = tuple(dict.fromkeys(self.candidate_target_ids))
        if candidates != self.candidate_target_ids:
            raise BackendUnavailable("relationship result contains duplicate candidate targets")
        target_sets = (set(targets), set(candidates), set(excluded))
        overlap = any(
            left.intersection(right) for index, left in enumerate(target_sets) for right in target_sets[index + 1 :]
        )
        if overlap:
            raise BackendUnavailable("relationship result overlaps supported, candidate, or excluded targets")
        unknown_targets = set().union(*target_sets).difference(definitions)
        if unknown_targets:
            raise BackendUnavailable(
                f"relationship result references unknown definitions: {', '.join(sorted(unknown_targets))}"
            )
        if published_target_ids is not None:
            accounted = set().union(*target_sets)
            if accounted != published_target_ids:
                raise BackendUnavailable("relationship result must account for every published callsite target")
        definition_map = {definition.id: definition for definition in bundle.definitions}
        parameter_map = {
            parameter.id: (definition.id, parameter)
            for definition in bundle.definitions
            for parameter in definition.parameters
        }
        for relation in self.supported_relations:
            target = definition_map[relation.target_definition_id]
            for argument_relation in relation.argument_relations:
                if argument_relation.argument_position >= len(
                    next(callsite for callsite in bundle.callsites if callsite.id == self.callsite_id).arguments
                ):
                    raise BackendUnavailable("argument relation references an unknown call argument")
                parameter = parameter_map.get(argument_relation.parameter_id)
                if parameter is None or parameter[0] != target.id:
                    raise BackendUnavailable("argument relation parameter does not belong to its call target")
            accounted_arguments = {
                *(item.argument_position for item in relation.argument_relations),
                *relation.unmapped_argument_positions,
            }
            expected_arguments = set(
                range(len(next(callsite for callsite in bundle.callsites if callsite.id == self.callsite_id).arguments))
            )
            if accounted_arguments != expected_arguments:
                raise BackendUnavailable("supported relation must account for every call argument")
        navigation = {receipt.id for receipt in self.navigation_receipts}
        if len(navigation) != len(self.navigation_receipts):
            raise BackendUnavailable("relationship result contains duplicate navigation receipts")
        for receipt in self.navigation_receipts:
            if not set(receipt.returned_definition_ids) <= definitions:
                raise BackendUnavailable("navigation receipt contains unknown definitions")
            if not set(receipt.returned_source_ids) <= sources:
                raise BackendUnavailable("navigation receipt contains unknown sources")
        evidence = observations | sources | navigation
        unknown_evidence = {
            item for relation in self.supported_relations for item in relation.evidence_ids if item not in evidence
        }
        unknown_evidence.update(
            item for candidate in self.excluded_candidates for item in candidate.evidence_ids if item not in evidence
        )
        unknown_evidence.update(
            item for context in self.related_contexts for item in context.evidence_ids if item not in evidence
        )
        unknown_evidence.update(
            item
            for relation in self.supported_relations
            for argument_relation in relation.argument_relations
            for item in argument_relation.evidence_ids
            if item not in evidence
        )
        if unknown_evidence:
            raise BackendUnavailable(
                f"relationship result references unknown evidence: {', '.join(sorted(unknown_evidence))}"
            )
        context_ids = tuple(context.definition_id for context in self.related_contexts)
        if len(context_ids) != len(set(context_ids)):
            raise BackendUnavailable("relationship result contains duplicate related context definitions")
        if not set(context_ids) <= definitions:
            raise BackendUnavailable("relationship result contains unknown related context definitions")
        for context in self.related_contexts:
            callsite = next(item for item in bundle.callsites if item.id == self.callsite_id)
            if context.definition_id == callsite.caller_definition_id:
                raise BackendUnavailable("related context cannot repeat the callsite caller")
            if context.definition_id in targets:
                raise BackendUnavailable("related context cannot repeat a supported call target")
            query_receipts = {
                receipt.id
                for receipt in self.navigation_receipts
                if receipt.purpose == "context_evidence" and context.definition_id in receipt.returned_definition_ids
            }
            owner_context = any(
                definition.owner_id == context.definition_id
                for definition in bundle.definitions
                if definition.id in targets
            )
            if not owner_context and not query_receipts.intersection(context.evidence_ids):
                raise BackendUnavailable(
                    f"related context {context.definition_id} omits its context navigation receipt"
                )
        if self.target_coverage == "complete" and (candidates or self.coverage_limitation_ids):
            raise BackendUnavailable("complete relationship coverage cannot retain candidates or limitations")
        if self.target_coverage == "incomplete" and not (candidates or self.coverage_limitation_ids):
            raise BackendUnavailable("incomplete relationship coverage must explain the remaining obligation")
        unknown_limitations = set(self.coverage_limitation_ids).difference(published_limitation_ids)
        if unknown_limitations:
            raise BackendUnavailable(
                f"relationship result references unknown limitations: {', '.join(sorted(unknown_limitations))}"
            )
        if not self.reason.strip():
            raise BackendUnavailable("relationship result reason must not be empty")

    def to_data(self) -> dict[str, object]:
        """Serialize one validated callsite result."""
        return {
            "callsite_id": self.callsite_id,
            "supported_relations": [relation.to_data() for relation in self.supported_relations],
            "candidate_target_ids": list(self.candidate_target_ids),
            "excluded_candidates": [candidate.to_data() for candidate in self.excluded_candidates],
            "target_coverage": self.target_coverage,
            "coverage_limitation_ids": list(self.coverage_limitation_ids),
            "reason": self.reason,
            "navigation_receipts": [receipt.to_data() for receipt in self.navigation_receipts],
            "related_contexts": [context.to_data() for context in self.related_contexts],
        }


@dataclass(frozen=True, order=True, kw_only=True)
class StructuralRelationshipResult:
    """Store one model established non-call relationship receipt."""

    subject_id: str
    supported_relations: tuple[SupportedStructuralRelation, ...]
    candidate_target_ids: tuple[str, ...]
    target_coverage: TargetCoverage
    coverage_limitation_ids: tuple[str, ...]
    reason: str
    excluded_candidates: tuple[ExcludedCandidate, ...] = ()
    navigation_receipts: tuple[NavigationReceipt, ...] = ()

    def to_data(self) -> dict[str, object]:
        """Serialize one structural result with distinct subject naming."""
        return {
            "subject_id": self.subject_id,
            "supported_relations": [relation.to_data() for relation in self.supported_relations],
            "candidate_target_ids": list(self.candidate_target_ids),
            "excluded_candidates": [candidate.to_data() for candidate in self.excluded_candidates],
            "target_coverage": self.target_coverage,
            "coverage_limitation_ids": list(self.coverage_limitation_ids),
            "reason": self.reason,
            "navigation_receipts": [receipt.to_data() for receipt in self.navigation_receipts],
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


def scope_relationship_evidence(
    bundle: RelationshipEvidenceBundle,
    seed_paths: tuple[str, ...],
) -> RelationshipEvidenceBundle:
    """Keep callsites that can reach or extend the changed definition surface."""
    if not seed_paths:
        return RelationshipEvidenceBundle(definitions=bundle.definitions)
    seeds = set(seed_paths)
    definitions = {definition.id: definition for definition in bundle.definitions}
    calls = {callsite.id: callsite for callsite in bundle.callsites}
    observations_by_call: dict[str, list[AnalysisObservation]] = {}
    for observation in bundle.observations:
        for subject in observation.subject_ids:
            if subject in calls:
                observations_by_call.setdefault(subject, []).append(observation)
    selected = {
        callsite.id
        for callsite in bundle.callsites
        if definitions[callsite.caller_definition_id].source.path in seeds
        or any(
            definitions[target].source.path in seeds
            for observation in observations_by_call.get(callsite.id, ())
            for target in observation.candidate_target_ids
        )
    }
    changed = True
    while changed:
        changed = False
        reached_definitions = {
            target
            for callsite_id in selected
            for target in _candidate_definition_ids(
                calls[callsite_id],
                bundle.definitions,
                tuple(observations_by_call.get(callsite_id, ())),
            )
        }
        for callsite in bundle.callsites:
            if callsite.id not in selected and callsite.caller_definition_id in reached_definitions:
                selected.add(callsite.id)
                changed = True
    callsites = tuple(callsite for callsite in bundle.callsites if callsite.id in selected)
    observations = tuple(
        observation
        for observation in bundle.observations
        if any(subject in selected for subject in observation.subject_ids)
    )
    structural_subjects = tuple(
        subject
        for subject in bundle.structural_subjects
        if subject.source_file in seeds
        or (subject.source_definition_id and definitions[subject.source_definition_id].source.path in seeds)
        or any(definitions[target].source.path in seeds for target in subject.candidate_target_definition_ids)
    )
    used_source_ids = {source_id for observation in observations for source_id in observation.provenance_source_ids}
    used_source_ids.update(subject.source.id for subject in structural_subjects)
    return RelationshipEvidenceBundle(
        sources=tuple(source for source in bundle.sources if source.id in used_source_ids),
        definitions=bundle.definitions,
        callsites=callsites,
        observations=observations,
        structural_subjects=structural_subjects,
    )


def _candidate_definition_ids(
    callsite: CallsiteEvidence,
    definitions: tuple[DefinitionEvidence, ...],
    observations: tuple[AnalysisObservation, ...],
) -> frozenset[str]:
    observed = {target for observation in observations for target in observation.candidate_target_ids}
    spelling = callsite.callee_spelling.split("(", 1)[0].rsplit(".", 1)[-1]
    matching = {
        definition.id for definition in definitions if definition.name.split("(", 1)[0].rsplit(".", 1)[-1] == spelling
    }
    return frozenset(observed | matching)


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
        {"id", "source", "kind", "name", "signature", "owner_id", "parameters"},
    )
    source = _source_from_data(data["source"], "definition evidence source")
    kind = data["kind"]
    if kind not in {"function", "method", "type", "contract", "modifier", "unknown"}:
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
            name=_text(data["name"], "parameter evidence name"),
            source=_source_from_data(data["source"], "parameter evidence source"),
            declaration=_text(data["declaration"], "parameter evidence declaration"),
            type_name=_string(data["type_name"], "parameter evidence type_name"),
        )
    except ValueError as exc:
        raise BackendUnavailable(str(exc)) from exc
    if data["id"] != parameter.id:
        raise BackendUnavailable("parameter evidence id does not match its fields")
    return parameter


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
    if kind not in {"syntax_call", "import_binding", "namespace_binding", "static_call_target", "dynamic_call"}:
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
    "ArgumentToParameterRelation",
    "CallsiteEvidence",
    "CallsiteRelationshipResult",
    "DefinitionEvidence",
    "ExcludedCandidate",
    "NavigationReceipt",
    "ParameterEvidence",
    "RelatedContext",
    "RelationshipEvidenceBundle",
    "SourceReference",
    "StructuralRelationshipEvidence",
    "StructuralRelationshipResult",
    "SupportedCallRelation",
    "SupportedStructuralRelation",
    "rebase_relationship_evidence",
    "relationship_evidence_from_data",
    "scope_relationship_evidence",
]
