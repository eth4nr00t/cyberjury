"""Encode and validate the model relationship conversation protocol."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cyberjury.json_parse import extract_json_object
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import (
    AnalysisObservation,
    ArgumentToParameterRelation,
    CallsiteEvidence,
    CallsiteRelationshipResult,
    DefinitionEvidence,
    ExcludedCandidate,
    NavigationReceipt,
    RelatedContext,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
    StructuralRelationshipResult,
    SupportedCallRelation,
    SupportedStructuralRelation,
)


class RelationshipResolutionError(RuntimeError):
    """One model call cannot produce an attributable relationship result."""


RELATIONSHIP_SYSTEM = """You establish repository code relationships from source evidence.
Tree-sitter and Slither observations are clues, not final relationship truth. For this one relationship subject,
account for every published candidate as supported, retained as a candidate, or excluded by controlling
source evidence. Return complete coverage only when the complete repository target set is proved.
Never invent an id. Never support or exclude a target without reading its exact source and the binding
evidence. Every supported or excluded target must copy all of its published required_evidence_ids into
that result's evidence_ids. The supported, candidate, and excluded target sets must be pairwise disjoint.
An available coverage limitation id is only a label to use when evidence cannot prove the complete target
set. Its presence in the packet does not itself make coverage incomplete.
When source evidence contains previews instead of text, respond only with {"evidence_requests":["src-id"]}
until every source needed by the final result has been delivered. Never cite an unread source id.
When the published candidates are insufficient, request deterministic repository navigation with
{"navigation_requests":[{"kind":"symbol or text","purpose":"target_candidate or context_evidence",
"query":"literal","path_prefix":"","cursor":0}]}.
When producer observations contain no candidate target ids, complete target coverage requires at least
one target_candidate query chain beginning at cursor 0, even when name matching published candidates.
Follow next_cursor until the query coverage needed for your conclusion is complete. A navigation receipt
is evidence that a search ran, not evidence that a returned target is related. Every supported call target
must account for every call argument with an argument_relations entry or an unmapped_argument_positions
entry. Mark data_coverage incomplete whenever an argument cannot be mapped to a declared target parameter.
Use related_contexts for non-callee definitions required to understand data, control, type, or registration
relationships. Never repeat the caller or a supported callee there. Such definitions must come from
context_evidence navigation or be a supported target owner.
Respond with one JSON object and nothing else."""

_RESULT_FIELDS = {
    "callsite_id",
    "supported_relations",
    "candidate_target_ids",
    "excluded_candidates",
    "target_coverage",
    "coverage_limitation_ids",
    "reason",
    "related_contexts",
}
_PERSISTED_RESULT_FIELDS = {*_RESULT_FIELDS, "navigation_receipts"}
_STRUCTURAL_RESULT_FIELDS = {
    "subject_id",
    "supported_relations",
    "candidate_target_ids",
    "excluded_candidates",
    "target_coverage",
    "coverage_limitation_ids",
    "reason",
}
_PERSISTED_STRUCTURAL_RESULT_FIELDS = {*_STRUCTURAL_RESULT_FIELDS, "navigation_receipts"}
MAX_PACKET_CHARS = 60_000


def source_catalog(bundle: RelationshipEvidenceBundle) -> dict[str, SourceReference]:
    """Index every exact source reference available to relationship navigation."""
    sources = {source.id: source for source in bundle.sources}
    for definition in bundle.definitions:
        sources[definition.source.id] = definition.source
        if definition.receiver is not None:
            sources[definition.receiver.source.id] = definition.receiver.source
        for parameter in definition.parameters:
            sources[parameter.source.id] = parameter.source
    for callsite in bundle.callsites:
        sources[callsite.source.id] = callsite.source
        for argument in callsite.arguments:
            if argument.source is not None:
                sources[argument.source.id] = argument.source
    for subject in bundle.structural_subjects:
        sources[subject.source.id] = subject.source
    return sources


def observations_by_callsite(
    observations: tuple[AnalysisObservation, ...],
) -> dict[str, tuple[AnalysisObservation, ...]]:
    """Group producer observations by their callsite subject."""
    grouped: dict[str, list[AnalysisObservation]] = {}
    for observation in observations:
        for subject in observation.subject_ids:
            if subject.startswith("call-"):
                grouped.setdefault(subject, []).append(observation)
    return {key: tuple(values) for key, values in grouped.items()}


def callsite_candidates(
    callsite: CallsiteEvidence,
    bundle: RelationshipEvidenceBundle,
    observations: tuple[AnalysisObservation, ...],
) -> tuple[DefinitionEvidence, ...]:
    """Return only producer-published call targets in deterministic order."""
    observed = {target_id for observation in observations for target_id in observation.candidate_target_ids}
    return tuple(
        definition
        for definition in sorted(
            bundle.definitions,
            key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
        )
        if definition.id in observed
    )


def limitation_id(callsite_id: str) -> str:
    """Build the stable unresolved-target limitation id for one callsite."""
    return f"lim-{hashlib.sha256(f'{callsite_id}:unresolved-target-coverage'.encode()).hexdigest()[:16]}"


def structural_limitation_id(subject_id: str) -> str:
    """Build the stable unresolved-target limitation id for one structural subject."""
    return f"lim-{hashlib.sha256(f'{subject_id}:unresolved-structural-coverage'.encode()).hexdigest()[:16]}"


def call_packet(
    root: Path,
    callsite: CallsiteEvidence,
    candidates: tuple[DefinitionEvidence, ...],
    definitions: dict[str, DefinitionEvidence],
    observations: tuple[AnalysisObservation, ...],
    sources: dict[str, SourceReference],
    limitation_id: str,
) -> dict[str, object]:
    """Build one attributable model packet for a callsite relationship."""
    caller = definitions[callsite.caller_definition_id]
    evidence_ids = {caller.source.id, callsite.source.id}
    evidence_ids.update(argument.source.id for argument in callsite.arguments if argument.source is not None)
    evidence_ids.update(source_id for observation in observations for source_id in observation.provenance_source_ids)
    evidence_ids.update(candidate.source.id for candidate in candidates)
    for candidate in candidates:
        if candidate.receiver is not None:
            evidence_ids.add(candidate.receiver.source.id)
        if candidate.owner_id and candidate.owner_id in definitions:
            evidence_ids.add(definitions[candidate.owner_id].source.id)
        evidence_ids.update(parameter.source.id for parameter in candidate.parameters)
    source_evidence = {
        source_id: {
            "reference": sources[source_id].to_data(),
            "text": read_source(root, sources[source_id]),
        }
        for source_id in sorted(evidence_ids)
    }
    strong = tuple(
        observation
        for observation in observations
        if observation.kind in {"import_declaration", "namespace_declaration", "static_call_target"}
    ) or tuple(observation for observation in observations if observation.kind == "syntax_call")
    binding_evidence = {item for observation in strong for item in (observation.id, *observation.provenance_source_ids)}
    published_candidates = [
        {
            **candidate.to_data(),
            "required_evidence_ids": sorted(
                {caller.source.id, callsite.source.id, candidate.source.id, *binding_evidence}
            ),
        }
        for candidate in candidates
    ]
    return {
        "callsite_id": callsite.id,
        "caller": caller.to_data(),
        "callsite": callsite.to_data(),
        "published_candidates": published_candidates,
        "producer_observations": [observation.to_data() for observation in observations],
        "source_evidence": source_evidence,
        "available_coverage_limitation_ids": [limitation_id],
        "output_contract": {
            "callsite_id": callsite.id,
            "supported_relations": [
                {
                    "target_definition_id": "def-id",
                    "evidence_ids": ["src-id", "obs-id"],
                    "argument_relations": [
                        {
                            "argument_position": 0,
                            "parameter_id": "param-id",
                            "evidence_ids": ["src-argument", "src-parameter"],
                        }
                    ],
                    "data_coverage": "complete or incomplete",
                    "unmapped_argument_positions": [],
                }
            ],
            "candidate_target_ids": ["def-id"],
            "excluded_candidates": [{"target_definition_id": "def-id", "evidence_ids": ["src-id"], "reason": "..."}],
            "target_coverage": "complete or incomplete",
            "coverage_limitation_ids": [limitation_id],
            "related_contexts": [
                {
                    "definition_id": "def-id",
                    "kind": "data or control or type or registration",
                    "evidence_ids": ["nav-id", "src-id"],
                    "reason": "...",
                }
            ],
            "reason": "...",
        },
    }


def structural_packet(
    root: Path,
    subject: StructuralRelationshipEvidence,
    candidates: tuple[DefinitionEvidence, ...],
    sources: dict[str, SourceReference],
) -> dict[str, object]:
    """Build one attributable model packet for a structural relationship."""
    limitation_id = structural_limitation_id(subject.id)
    evidence_ids = {subject.source.id, *(candidate.source.id for candidate in candidates)}
    source_evidence = {
        source_id: {"reference": sources[source_id].to_data(), "text": read_source(root, sources[source_id])}
        for source_id in sorted(evidence_ids)
    }
    return {
        "subject_id": subject.id,
        "structural_subject": subject.to_data(),
        "published_candidates": [
            {
                **candidate.to_data(),
                "required_evidence_ids": [subject.source.id, candidate.source.id],
            }
            for candidate in candidates
        ],
        "source_evidence": source_evidence,
        "available_coverage_limitation_ids": [limitation_id],
        "output_contract": {
            "subject_id": subject.id,
            "supported_relations": [
                {
                    "target_definition_id": "def-id",
                    "evidence_ids": ["src-subject", "src-target"],
                }
            ],
            "candidate_target_ids": ["def-id"],
            "excluded_candidates": [{"target_definition_id": "def-id", "evidence_ids": ["src-id"], "reason": "..."}],
            "target_coverage": "complete or incomplete",
            "coverage_limitation_ids": [limitation_id],
            "reason": "...",
        },
    }


def candidate_groups(
    packet: dict[str, object],
    candidates: tuple[DefinitionEvidence, ...],
    max_packet_chars: int,
) -> tuple[tuple[DefinitionEvidence, ...], ...]:
    """Keep one judgment when metadata fits, otherwise split without dropping candidates."""
    compact = json.dumps(compact_packet(packet), sort_keys=True, indent=2)
    if len(compact) <= max_packet_chars or len(candidates) <= 1:
        return (candidates,)
    return tuple((candidate,) for candidate in candidates)


def compact_packet(packet: dict[str, object]) -> dict[str, object]:
    """Replace exact source bodies with requestable previews while preserving ids."""
    compact = json.loads(json.dumps(packet))
    evidence = compact.get("source_evidence", {})
    if not isinstance(evidence, dict):
        raise RelationshipResolutionError("relationship packet source_evidence must be an object")
    for item in evidence.values():
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            raise RelationshipResolutionError("relationship packet contains malformed source evidence")
        text = item.pop("text")
        item["preview"] = text[:200]
        item["text_available_by_request"] = True
    _strip_compact_integrity_fields(compact)
    compact["compact_source_references"] = "content hashes and offset units remain validated by code"
    compact["request_contract"] = {"evidence_requests": ["src-id"]}
    return compact


def _strip_compact_integrity_fields(value: object) -> None:
    if isinstance(value, dict):
        if {"id", "path", "range", "offset_unit", "content_sha256"} <= set(value):
            value.pop("offset_unit", None)
            value.pop("content_sha256", None)
        for item in value.values():
            _strip_compact_integrity_fields(item)
    elif isinstance(value, list):
        for item in value:
            _strip_compact_integrity_fields(item)


def evidence_requests(text: str) -> tuple[str, ...] | None:
    """Parse one strict exact-source request or return no request."""
    value = extract_json_object(text)
    if not isinstance(value, dict) or set(value) != {"evidence_requests"}:
        return None
    requested = value["evidence_requests"]
    if not isinstance(requested, list) or not all(isinstance(item, str) and item for item in requested):
        raise RelationshipResolutionError("relationship evidence_requests must be a string list")
    if not requested or len(requested) != len(set(requested)):
        raise RelationshipResolutionError("relationship evidence_requests must be nonempty and unique")
    return tuple(requested)


def deliver_relationship_evidence(
    requested: tuple[str, ...],
    sources: dict[str, str],
    delivered: set[str],
    *,
    target_chars: int,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Deliver a bounded set of previously unread exact sources."""
    unknown = set(requested).difference(sources)
    if unknown:
        raise RelationshipResolutionError(
            f"relationship evidence request contains unknown ids: {', '.join(sorted(unknown))}"
        )
    pending = [source_id for source_id in requested if source_id not in delivered]
    if not pending:
        raise RelationshipResolutionError("relationship evidence request repeats only delivered ids")
    blocks: list[str] = []
    delivered_now: list[str] = []
    characters = 0
    for source_id in pending:
        block = f"Source `{source_id}`:\n{sources[source_id]}"
        if blocks and characters + len(block) > target_chars:
            break
        blocks.append(block)
        delivered_now.append(source_id)
        characters += len(block)
    remaining = tuple(source_id for source_id in pending if source_id not in delivered_now)
    return "\n\n".join(blocks), tuple(delivered_now), remaining


def validate_call_read_sources(
    result: CallsiteRelationshipResult,
    delivered: frozenset[str],
    published_sources: frozenset[str],
) -> None:
    """Reject call results that cite exact source the model did not read."""
    cited_sources = {
        evidence_id
        for relation in result.supported_relations
        for evidence_id in relation.evidence_ids
        if evidence_id in published_sources
    }
    cited_sources.update(
        evidence_id
        for candidate in result.excluded_candidates
        for evidence_id in candidate.evidence_ids
        if evidence_id in published_sources
    )
    cited_sources.update(
        evidence_id
        for context in result.related_contexts
        for evidence_id in context.evidence_ids
        if evidence_id in published_sources
    )
    cited_sources.update(
        evidence_id
        for relation in result.supported_relations
        for argument_relation in relation.argument_relations
        for evidence_id in argument_relation.evidence_ids
        if evidence_id in published_sources
    )
    unread = cited_sources.difference(delivered)
    if unread:
        raise RelationshipResolutionError(f"relationship result cites unread source ids: {', '.join(sorted(unread))}")


def merge_partial_results(
    callsite: CallsiteEvidence,
    partial_results: tuple[CallsiteRelationshipResult, ...],
    *,
    limitation_id: str,
) -> CallsiteRelationshipResult:
    """Merge split candidate judgments without dropping candidates or receipts."""
    if not partial_results:
        raise RelationshipResolutionError(f"relationship resolution produced no result for {callsite.id}")
    if len(partial_results) == 1:
        return partial_results[0]
    incomplete = any(result.target_coverage == "incomplete" for result in partial_results)
    limitations = tuple(
        dict.fromkeys(limitation for result in partial_results for limitation in result.coverage_limitation_ids)
    )
    if incomplete and not limitations:
        limitations = (limitation_id,)
    return CallsiteRelationshipResult(
        callsite_id=callsite.id,
        supported_relations=tuple(relation for result in partial_results for relation in result.supported_relations),
        candidate_target_ids=tuple(target for result in partial_results for target in result.candidate_target_ids),
        excluded_candidates=tuple(candidate for result in partial_results for candidate in result.excluded_candidates),
        target_coverage="incomplete" if incomplete else "complete",
        coverage_limitation_ids=limitations,
        reason="; ".join(dict.fromkeys(result.reason for result in partial_results)),
        navigation_receipts=tuple(
            dict.fromkeys(receipt for result in partial_results for receipt in result.navigation_receipts)
        ),
        related_contexts=tuple(
            dict.fromkeys(context for result in partial_results for context in result.related_contexts)
        ),
    )


def read_source(root: Path, reference: SourceReference) -> str:
    """Read and verify one repository-bounded exact source reference."""
    path = (root / reference.path).resolve()
    try:
        path.relative_to(root)
        source = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError, ValueError) as exc:
        raise BackendUnavailable(f"cannot read relationship source {reference.path}: {exc}") from exc
    if reference.end > len(source):
        raise BackendUnavailable(f"relationship source range exceeds {reference.path}")
    selected = source[reference.start : reference.end]
    if hashlib.sha256(selected.encode()).hexdigest() != reference.content_sha256:
        raise BackendUnavailable(f"relationship source content changed at {reference.path}:{reference.start}")
    return selected


def call_result_from_response(text: str, *, persisted: bool = False) -> CallsiteRelationshipResult:
    """Parse one strict call relationship response."""
    value = extract_json_object(text)
    fields = _PERSISTED_RESULT_FIELDS if persisted else _RESULT_FIELDS
    if not isinstance(value, dict) or set(value) != fields:
        raise RelationshipResolutionError(f"relationship reply must contain exactly: {', '.join(sorted(fields))}")
    supported = tuple(
        _supported_call_relation(item, position) for position, item in enumerate(_list(value, "supported_relations"))
    )
    excluded = tuple(
        _excluded_candidate(item, position) for position, item in enumerate(_list(value, "excluded_candidates"))
    )
    coverage = value["target_coverage"]
    if coverage not in {"complete", "incomplete"}:
        raise RelationshipResolutionError("relationship target_coverage must be complete or incomplete")
    try:
        return CallsiteRelationshipResult(
            callsite_id=_nonempty_text(value["callsite_id"], "callsite_id"),
            supported_relations=supported,
            candidate_target_ids=_string_tuple(value["candidate_target_ids"], "candidate_target_ids"),
            excluded_candidates=excluded,
            target_coverage=coverage,
            coverage_limitation_ids=_string_tuple(value["coverage_limitation_ids"], "coverage_limitation_ids"),
            reason=_nonempty_text(value["reason"], "reason"),
            navigation_receipts=(
                tuple(
                    _navigation_receipt(item, position)
                    for position, item in enumerate(_list(value, "navigation_receipts"))
                )
                if persisted
                else ()
            ),
            related_contexts=tuple(
                _related_context(item, position) for position, item in enumerate(_list(value, "related_contexts"))
            ),
        )
    except ValueError as exc:
        raise RelationshipResolutionError(str(exc)) from exc


def structural_result_from_response(
    text: str,
    *,
    persisted: bool = False,
) -> StructuralRelationshipResult:
    """Parse one strict structural relationship response."""
    value = extract_json_object(text)
    fields = _PERSISTED_STRUCTURAL_RESULT_FIELDS if persisted else _STRUCTURAL_RESULT_FIELDS
    if not isinstance(value, dict) or set(value) != fields:
        raise RelationshipResolutionError(
            f"structural relationship reply must contain exactly: {', '.join(sorted(fields))}"
        )
    coverage = value["target_coverage"]
    if coverage not in {"complete", "incomplete"}:
        raise RelationshipResolutionError("structural relationship target_coverage must be complete or incomplete")
    try:
        return StructuralRelationshipResult(
            subject_id=_nonempty_text(value["subject_id"], "subject_id"),
            supported_relations=tuple(
                _supported_structural_relation(item, position)
                for position, item in enumerate(_list(value, "supported_relations"))
            ),
            candidate_target_ids=_string_tuple(value["candidate_target_ids"], "candidate_target_ids"),
            excluded_candidates=tuple(
                _excluded_candidate(item, position) for position, item in enumerate(_list(value, "excluded_candidates"))
            ),
            target_coverage=coverage,
            coverage_limitation_ids=_string_tuple(value["coverage_limitation_ids"], "coverage_limitation_ids"),
            reason=_nonempty_text(value["reason"], "reason"),
            navigation_receipts=(
                tuple(
                    _navigation_receipt(item, position)
                    for position, item in enumerate(_list(value, "navigation_receipts"))
                )
                if persisted
                else ()
            ),
        )
    except ValueError as exc:
        raise RelationshipResolutionError(str(exc)) from exc


def validate_structural_read_sources(
    result: StructuralRelationshipResult,
    delivered: frozenset[str],
    published_sources: frozenset[str],
) -> None:
    """Reject structural results that cite exact source the model did not read."""
    cited = {
        evidence_id
        for relation in result.supported_relations
        for evidence_id in relation.evidence_ids
        if evidence_id in published_sources
    }
    cited.update(
        evidence_id
        for candidate in result.excluded_candidates
        for evidence_id in candidate.evidence_ids
        if evidence_id in published_sources
    )
    unread = cited.difference(delivered)
    if unread:
        raise RelationshipResolutionError(
            f"structural relationship result cites unread source ids: {', '.join(sorted(unread))}"
        )


def _supported_call_relation(value: object, position: int) -> SupportedCallRelation:
    data = _exact_mapping(
        value,
        f"supported_relations[{position}]",
        {
            "target_definition_id",
            "evidence_ids",
            "argument_relations",
            "data_coverage",
            "unmapped_argument_positions",
        },
    )
    coverage = data["data_coverage"]
    if coverage not in {"complete", "incomplete"}:
        raise RelationshipResolutionError("supported relation data_coverage must be complete or incomplete")
    return SupportedCallRelation(
        target_definition_id=_nonempty_text(data["target_definition_id"], "target_definition_id"),
        evidence_ids=_string_tuple(data["evidence_ids"], "evidence_ids", required=True),
        argument_relations=tuple(
            _argument_relation(item, item_position)
            for item_position, item in enumerate(_records(data["argument_relations"], "argument_relations"))
        ),
        data_coverage=coverage,
        unmapped_argument_positions=_integer_tuple(data["unmapped_argument_positions"], "unmapped_argument_positions"),
    )


def _supported_structural_relation(value: object, position: int) -> SupportedStructuralRelation:
    data = _exact_mapping(
        value,
        f"supported_relations[{position}]",
        {"target_definition_id", "evidence_ids"},
    )
    return SupportedStructuralRelation(
        target_definition_id=_nonempty_text(data["target_definition_id"], "target_definition_id"),
        evidence_ids=_string_tuple(data["evidence_ids"], "evidence_ids", required=True),
    )


def _argument_relation(value: object, position: int) -> ArgumentToParameterRelation:
    data = _exact_mapping(
        value,
        f"argument_relations[{position}]",
        {"argument_position", "parameter_id", "evidence_ids"},
    )
    argument_position = data["argument_position"]
    if isinstance(argument_position, bool) or not isinstance(argument_position, int):
        raise RelationshipResolutionError("argument relation position must be an integer")
    return ArgumentToParameterRelation(
        argument_position=argument_position,
        parameter_id=_nonempty_text(data["parameter_id"], "parameter_id"),
        evidence_ids=_string_tuple(data["evidence_ids"], "evidence_ids", required=True),
    )


def _related_context(value: object, position: int) -> RelatedContext:
    data = _exact_mapping(
        value,
        f"related_contexts[{position}]",
        {"definition_id", "kind", "evidence_ids", "reason"},
    )
    kind = data["kind"]
    if kind not in {"data", "control", "type", "registration"}:
        raise RelationshipResolutionError("related context kind is unsupported")
    return RelatedContext(
        definition_id=_nonempty_text(data["definition_id"], "related context definition_id"),
        kind=kind,
        evidence_ids=_string_tuple(data["evidence_ids"], "related context evidence_ids", required=True),
        reason=_nonempty_text(data["reason"], "related context reason"),
    )


def _navigation_receipt(value: object, position: int) -> NavigationReceipt:
    data = _exact_mapping(
        value,
        f"navigation_receipts[{position}]",
        {
            "id",
            "kind",
            "purpose",
            "query",
            "path_prefix",
            "cursor",
            "returned_definition_ids",
            "returned_source_ids",
            "next_cursor",
        },
    )
    kind = data["kind"]
    if kind not in {"symbol", "text"}:
        raise RelationshipResolutionError("navigation receipt kind must be symbol or text")
    purpose = data["purpose"]
    if purpose not in {"target_candidate", "context_evidence"}:
        raise RelationshipResolutionError("navigation receipt purpose is unsupported")
    cursor = data["cursor"]
    if isinstance(cursor, bool) or not isinstance(cursor, int):
        raise RelationshipResolutionError("navigation receipt cursor must be an integer")
    next_cursor = data["next_cursor"]
    if next_cursor is not None and (isinstance(next_cursor, bool) or not isinstance(next_cursor, int)):
        raise RelationshipResolutionError("navigation receipt next_cursor must be an integer or null")
    receipt = NavigationReceipt.create(
        kind=kind,
        purpose=purpose,
        query=_nonempty_text(data["query"], "navigation receipt query"),
        path_prefix=_text_value(data["path_prefix"], "navigation receipt path_prefix"),
        cursor=cursor,
        returned_definition_ids=_string_tuple(data["returned_definition_ids"], "returned_definition_ids"),
        returned_source_ids=_string_tuple(data["returned_source_ids"], "returned_source_ids"),
        next_cursor=next_cursor,
    )
    if data["id"] != receipt.id:
        raise RelationshipResolutionError("navigation receipt id does not match its fields")
    return receipt


def _excluded_candidate(value: object, position: int) -> ExcludedCandidate:
    data = _exact_mapping(
        value,
        f"excluded_candidates[{position}]",
        {"target_definition_id", "evidence_ids", "reason"},
    )
    return ExcludedCandidate(
        target_definition_id=_nonempty_text(data["target_definition_id"], "target_definition_id"),
        evidence_ids=_string_tuple(data["evidence_ids"], "evidence_ids", required=True),
        reason=_nonempty_text(data["reason"], "reason"),
    )


def validate_controlling_evidence(
    result: CallsiteRelationshipResult,
    *,
    callsite: CallsiteEvidence,
    definitions: dict[str, DefinitionEvidence],
    observations: tuple[AnalysisObservation, ...],
) -> None:
    """Require exact endpoints and navigation provenance for every model claim."""
    caller = definitions[callsite.caller_definition_id]
    strong = tuple(
        observation
        for observation in observations
        if observation.kind in {"import_declaration", "namespace_declaration", "static_call_target"}
    ) or tuple(observation for observation in observations if observation.kind == "syntax_call")
    required_binding = {item for observation in strong for item in (observation.id, *observation.provenance_source_ids)}
    for label, target_id, evidence_ids in (
        *(
            ("supported relation", relation.target_definition_id, relation.evidence_ids)
            for relation in result.supported_relations
        ),
        *(
            ("excluded candidate", candidate.target_definition_id, candidate.evidence_ids)
            for candidate in result.excluded_candidates
        ),
    ):
        required = {
            caller.source.id,
            callsite.source.id,
            definitions[target_id].source.id,
            *required_binding,
        }
        initial_targets = {target for observation in observations for target in observation.candidate_target_ids}
        if target_id not in initial_targets:
            query_receipts = {
                receipt.id for receipt in result.navigation_receipts if target_id in receipt.returned_definition_ids
            }
            if not query_receipts.intersection(evidence_ids):
                raise RelationshipResolutionError(f"{label} {target_id} omits its navigation receipt")
        missing = required.difference(evidence_ids)
        if missing:
            raise RelationshipResolutionError(
                f"{label} {target_id} omits controlling evidence: {', '.join(sorted(missing))}"
            )
    parameters = {parameter.id: parameter for definition in definitions.values() for parameter in definition.parameters}
    for relation in result.supported_relations:
        for data_relation in relation.argument_relations:
            argument = callsite.arguments[data_relation.argument_position]
            if argument.source is None:
                raise RelationshipResolutionError(
                    f"argument relation {data_relation.argument_position} has no exact argument source"
                )
            parameter = parameters[data_relation.parameter_id]
            required = {argument.source.id, parameter.source.id}
            missing = required.difference(data_relation.evidence_ids)
            if missing:
                raise RelationshipResolutionError(
                    "argument relation "
                    f"{data_relation.argument_position} omits exact endpoint evidence: {', '.join(sorted(missing))}"
                )
    for context in result.related_contexts:
        required = {
            caller.source.id,
            callsite.source.id,
            definitions[context.definition_id].source.id,
        }
        missing = required.difference(context.evidence_ids)
        if missing:
            raise RelationshipResolutionError(
                f"related context {context.definition_id} omits controlling evidence: {', '.join(sorted(missing))}"
            )


def _list(data: dict[str, object], field: str) -> list[object]:
    value = data[field]
    if not isinstance(value, list):
        raise RelationshipResolutionError(f"relationship {field} must be a list")
    return value


def _records(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise RelationshipResolutionError(f"relationship {field} must be a list")
    return value


def _exact_mapping(value: object, location: str, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RelationshipResolutionError(f"{location} must contain exactly: {', '.join(sorted(fields))}")
    return value


def _nonempty_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationshipResolutionError(f"relationship {field} must be nonempty text")
    return value


def _text_value(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RelationshipResolutionError(f"relationship {field} must be text")
    return value


def _string_tuple(value: object, field: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise RelationshipResolutionError(f"relationship {field} must be a string list")
    if required and not value:
        raise RelationshipResolutionError(f"relationship {field} must not be empty")
    if len(value) != len(set(value)):
        raise RelationshipResolutionError(f"relationship {field} must not contain duplicates")
    return tuple(value)


def _integer_tuple(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value
    ):
        raise RelationshipResolutionError(f"relationship {field} must be a nonnegative integer list")
    if len(value) != len(set(value)):
        raise RelationshipResolutionError(f"relationship {field} must not contain duplicates")
    return tuple(value)


__all__ = [
    "MAX_PACKET_CHARS",
    "RELATIONSHIP_SYSTEM",
    "RelationshipResolutionError",
    "call_packet",
    "call_result_from_response",
    "callsite_candidates",
    "candidate_groups",
    "compact_packet",
    "deliver_relationship_evidence",
    "evidence_requests",
    "limitation_id",
    "merge_partial_results",
    "observations_by_callsite",
    "read_source",
    "source_catalog",
    "structural_limitation_id",
    "structural_packet",
    "structural_result_from_response",
    "validate_call_read_sources",
    "validate_controlling_evidence",
    "validate_structural_read_sources",
]
