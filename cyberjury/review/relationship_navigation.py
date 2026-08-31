"""Provide bounded deterministic navigation for model relationship analysis."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cyberjury.json_parse import extract_json_object
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    DefinitionEvidence,
    NavigationReceipt,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)


class NavigationError(RuntimeError):
    """A model navigation request cannot be executed or attributed."""


@dataclass(frozen=True, kw_only=True)
class NavigationRequest:
    """One validated deterministic repository query page."""

    kind: Literal["symbol", "text"]
    purpose: Literal["target_candidate", "context_evidence"]
    query: str
    path_prefix: str
    cursor: int


def parse_navigation_requests(text: str) -> tuple[NavigationRequest, ...] | None:
    """Parse a strict navigation request without treating final output as a query."""
    value = extract_json_object(text)
    if not isinstance(value, dict) or set(value) != {"navigation_requests"}:
        return None
    requests = value["navigation_requests"]
    if not isinstance(requests, list) or not requests or len(requests) > 4:
        raise NavigationError("relationship navigation_requests must contain one to four queries")
    normalized: list[NavigationRequest] = []
    for position, item in enumerate(requests):
        data = _exact_mapping(
            item,
            f"navigation_requests[{position}]",
            {"kind", "purpose", "query", "path_prefix", "cursor"},
        )
        kind = data["kind"]
        if kind not in {"symbol", "text"}:
            raise NavigationError("relationship navigation kind must be symbol or text")
        purpose = data["purpose"]
        if purpose not in {"target_candidate", "context_evidence"}:
            raise NavigationError("relationship navigation purpose must be target_candidate or context_evidence")
        query = _nonempty_text(data["query"], "navigation query")
        path_prefix = data["path_prefix"]
        if not isinstance(path_prefix, str) or path_prefix.startswith("/") or ".." in Path(path_prefix).parts:
            raise NavigationError("relationship navigation path_prefix must stay within the repository")
        cursor = data["cursor"]
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise NavigationError("relationship navigation cursor must be a nonnegative integer")
        normalized.append(
            NavigationRequest(
                kind=kind,
                purpose=purpose,
                query=query,
                path_prefix=path_prefix,
                cursor=cursor,
            )
        )
    return tuple(normalized)


def execute_navigation(
    bundle: RelationshipEvidenceBundle,
    source_catalog: dict[str, SourceReference],
    request: NavigationRequest,
    *,
    page_size: int,
    read_source: Callable[[SourceReference], str],
) -> NavigationReceipt:
    """Execute one stable query page without assigning relationship meaning."""
    definitions = sorted(
        (definition for definition in bundle.definitions if definition.kind != "file"),
        key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
    )
    if request.kind == "symbol":
        needle = request.query.casefold()
        matching_definitions = [
            definition
            for definition in definitions
            if _path_matches(definition.source.path, request.path_prefix)
            and needle
            in "\n".join(
                (
                    definition.name,
                    definition.signature,
                    definition.source.path,
                    _owner_name(definition, bundle.definitions),
                )
            ).casefold()
        ]
        matching_sources = [definition.source.id for definition in matching_definitions]
    else:
        matching_source_ids = [
            source_id
            for source_id, reference in sorted(
                source_catalog.items(),
                key=lambda item: (item[1].path, item[1].start, item[1].end, item[0]),
            )
            if _path_matches(reference.path, request.path_prefix) and request.query in read_source(reference)
        ]
        matching_sources = matching_source_ids
        matching_definitions = _definitions_covering_sources(
            definitions,
            matching_source_ids,
            source_catalog,
        )
    result_keys = [("definition", definition.id) for definition in matching_definitions]
    result_keys.extend(("source", source_id) for source_id in matching_sources)
    unique_keys = list(dict.fromkeys(result_keys))
    page = unique_keys[request.cursor : request.cursor + page_size]
    next_cursor = request.cursor + len(page) if request.cursor + len(page) < len(unique_keys) else None
    return NavigationReceipt.create(
        kind=request.kind,
        purpose=request.purpose,
        query=request.query,
        path_prefix=request.path_prefix,
        cursor=request.cursor,
        returned_definition_ids=tuple(value for item_kind, value in page if item_kind == "definition"),
        returned_source_ids=tuple(value for item_kind, value in page if item_kind == "source"),
        next_cursor=next_cursor,
    )


def call_navigation_delivery(
    receipt: NavigationReceipt,
    *,
    callsite: CallsiteEvidence,
    definitions: dict[str, DefinitionEvidence],
    observations: tuple[AnalysisObservation, ...],
    source_text: dict[str, str],
) -> dict[str, object]:
    """Render query results while preserving target and context purpose boundaries."""
    caller = definitions[callsite.caller_definition_id]
    binding_evidence = {
        item for observation in observations for item in (observation.id, *observation.provenance_source_ids)
    }
    definitions_data = [
        {
            **definitions[definition_id].to_data(),
            "required_evidence_ids": sorted(
                {
                    receipt.id,
                    caller.source.id,
                    callsite.source.id,
                    definitions[definition_id].source.id,
                    *binding_evidence,
                }
            ),
        }
        for definition_id in receipt.returned_definition_ids
    ]
    return _delivery(receipt, definitions_data, source_text)


def structural_navigation_delivery(
    receipt: NavigationReceipt,
    *,
    subject: StructuralRelationshipEvidence,
    definitions: dict[str, DefinitionEvidence],
    source_text: dict[str, str],
) -> dict[str, object]:
    """Render structural query results under the same purpose contract."""
    definitions_data = [
        {
            **definitions[target_id].to_data(),
            "required_evidence_ids": [
                receipt.id,
                subject.source.id,
                definitions[target_id].source.id,
            ],
        }
        for target_id in receipt.returned_definition_ids
    ]
    return _delivery(receipt, definitions_data, source_text)


def _delivery(
    receipt: NavigationReceipt,
    definitions_data: list[dict[str, object]],
    source_text: dict[str, str],
) -> dict[str, object]:
    return {
        "receipt": receipt.to_data(),
        "published_candidates": definitions_data if receipt.purpose == "target_candidate" else [],
        "published_context_definitions": definitions_data if receipt.purpose == "context_evidence" else [],
        "published_sources": [
            {
                "id": source_id,
                "preview": source_text[source_id][:400],
                "text_available_by_request": True,
            }
            for source_id in receipt.returned_source_ids
        ],
    }


def _definitions_covering_sources(
    definitions: list[DefinitionEvidence],
    source_ids: list[str],
    source_catalog: dict[str, SourceReference],
) -> list[DefinitionEvidence]:
    matching = set(source_ids)
    return [
        definition
        for definition in definitions
        if definition.source.id in matching
        or any(
            source_catalog[source_id].path == definition.source.path
            and source_catalog[source_id].start <= definition.source.start
            and definition.source.end <= source_catalog[source_id].end
            for source_id in source_ids
        )
    ]


def _path_matches(path: str, prefix: str) -> bool:
    return not prefix or path == prefix or path.startswith(f"{prefix.rstrip('/')}/")


def _owner_name(
    definition: DefinitionEvidence,
    definitions: tuple[DefinitionEvidence, ...],
) -> str:
    if not definition.owner_id:
        return ""
    owner = next((item for item in definitions if item.id == definition.owner_id), None)
    return owner.name if owner is not None else ""


def _exact_mapping(value: object, location: str, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise NavigationError(f"{location} must contain exactly: {', '.join(sorted(fields))}")
    return value


def _nonempty_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise NavigationError(f"relationship {field} must be nonempty text")
    return value


__all__ = [
    "NavigationError",
    "NavigationRequest",
    "call_navigation_delivery",
    "execute_navigation",
    "parse_navigation_requests",
    "structural_navigation_delivery",
]
