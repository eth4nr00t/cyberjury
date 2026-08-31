"""Establish repository content relationships from deterministic producer evidence."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from time import perf_counter
from typing import TypeVar

from cyberjury.providers.base import Message, Provider
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationship_navigation import (
    NavigationError,
    call_navigation_delivery,
    execute_navigation,
    parse_navigation_requests,
    structural_navigation_delivery,
)
from cyberjury.review.relationship_projection import (
    callsite_result_incomplete,
    graph_with_model_relationships,
    relationship_evidence_fingerprint,
    relationship_obligation_ids,
    relationship_result_from_data,
    structural_result_from_data,
    validate_relationship_results,
    validate_structural_result,
    validate_structural_results,
    validate_target_navigation_coverage,
)
from cyberjury.review.relationship_protocol import (
    MAX_PACKET_CHARS,
    RELATIONSHIP_SYSTEM,
    RelationshipResolutionError,
    call_packet,
    call_result_from_response,
    callsite_candidates,
    candidate_groups,
    deliver_relationship_evidence,
    evidence_requests,
    merge_partial_results,
    observations_by_callsite,
    read_source,
    structural_limitation_id,
    structural_packet,
    structural_result_from_response,
    validate_call_read_sources,
    validate_controlling_evidence,
    validate_structural_read_sources,
)
from cyberjury.review.relationship_protocol import (
    compact_packet as compact_relationship_packet,
)
from cyberjury.review.relationship_protocol import (
    limitation_id as call_limitation_id,
)
from cyberjury.review.relationship_protocol import (
    source_catalog as build_source_catalog,
)
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    CallsiteRelationshipResult,
    DefinitionEvidence,
    NavigationReceipt,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
    StructuralRelationshipResult,
)

_ResultT = TypeVar("_ResultT", CallsiteRelationshipResult, StructuralRelationshipResult)


class RelationshipResolver(ABC):
    """Establish call and structural relationships from deterministic evidence."""

    def cache_identity(self) -> str:
        """Identify relationship behavior persisted across resume."""
        resolver = type(self)
        return f"{resolver.__module__}.{resolver.__qualname__}"

    @abstractmethod
    def resolve(self, root: str | Path, bundle: RelationshipEvidenceBundle) -> RelationshipResolution:
        """Return one result for every relationship subject or fail loud."""


@dataclass(frozen=True, kw_only=True)
class RelationshipResolution:
    """Complete ordered call and structural receipts for one evidence bundle."""

    call_results: tuple[CallsiteRelationshipResult, ...]
    structural_results: tuple[StructuralRelationshipResult, ...] = ()
    calls: int
    initial_packet_characters: int
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_seconds: float = 0.0
    restored: bool = False


@dataclass(frozen=True, kw_only=True)
class ModelRelationshipResolver(RelationshipResolver):
    """Ask one model to establish every call and structural relationship from exact source."""

    provider: Provider
    model: str
    max_tokens: int = 1200
    max_packet_chars: int = MAX_PACKET_CHARS
    correction_attempts: int = 1
    concurrency: int = 4
    evidence_followups: int = 8
    navigation_followups: int = 8
    navigation_page_size: int = 25

    def __post_init__(self) -> None:
        """Reject invalid relationship execution limits before model work."""
        if (
            isinstance(self.correction_attempts, bool)
            or not isinstance(self.correction_attempts, int)
            or self.correction_attempts < 0
        ):
            raise ValueError("relationship correction_attempts must be a nonnegative integer")
        if isinstance(self.concurrency, bool) or not isinstance(self.concurrency, int) or self.concurrency < 1:
            raise ValueError("relationship concurrency must be a positive integer")
        if (
            isinstance(self.evidence_followups, bool)
            or not isinstance(self.evidence_followups, int)
            or self.evidence_followups < 0
        ):
            raise ValueError("relationship evidence_followups must be a nonnegative integer")
        if (
            isinstance(self.navigation_followups, bool)
            or not isinstance(self.navigation_followups, int)
            or self.navigation_followups < 0
        ):
            raise ValueError("relationship navigation_followups must be a nonnegative integer")
        if (
            isinstance(self.navigation_page_size, bool)
            or not isinstance(self.navigation_page_size, int)
            or self.navigation_page_size < 1
        ):
            raise ValueError("relationship navigation_page_size must be a positive integer")

    def cache_identity(self) -> str:
        """Bind persisted results to provider class, model, prompt, and limits."""
        provider = type(self.provider)
        payload = {
            "resolver": super().cache_identity(),
            "provider": f"{provider.__module__}.{provider.__qualname__}",
            "model": self.model,
            "max_tokens": self.max_tokens,
            "max_packet_chars": self.max_packet_chars,
            "correction_attempts": self.correction_attempts,
            "concurrency": self.concurrency,
            "evidence_followups": self.evidence_followups,
            "navigation_followups": self.navigation_followups,
            "navigation_page_size": self.navigation_page_size,
            "system_sha256": hashlib.sha256(RELATIONSHIP_SYSTEM.encode()).hexdigest(),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def resolve(self, root: str | Path, bundle: RelationshipEvidenceBundle) -> RelationshipResolution:
        """Return one validated receipt per relationship subject or fail the review."""
        base = Path(root).resolve()
        started = perf_counter()
        source_catalog = build_source_catalog(bundle)
        definitions = {definition.id: definition for definition in bundle.definitions}
        observations = observations_by_callsite(bundle.observations)
        tasks = []
        initial_packet_characters = 0
        for callsite in sorted(
            bundle.callsites,
            key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
        ):
            candidates = callsite_candidates(callsite, bundle, observations.get(callsite.id, ()))
            limitation_id = call_limitation_id(callsite.id)
            packet = call_packet(
                base,
                callsite,
                candidates,
                definitions,
                observations.get(callsite.id, ()),
                source_catalog,
                limitation_id,
            )
            groups = candidate_groups(packet, candidates, self.max_packet_chars)
            for group in groups:
                grouped_packet = (
                    packet
                    if group == candidates
                    else call_packet(
                        base,
                        callsite,
                        group,
                        definitions,
                        observations.get(callsite.id, ()),
                        source_catalog,
                        limitation_id,
                    )
                )
                source_text = {source_id: item["text"] for source_id, item in grouped_packet["source_evidence"].items()}
                full_request = json.dumps(grouped_packet, sort_keys=True, indent=2)
                compact_payload = compact_relationship_packet(grouped_packet)
                compact_request = json.dumps(compact_payload, sort_keys=True, indent=2)
                if len(compact_request) > self.max_packet_chars:
                    raise RelationshipResolutionError(
                        f"relationship candidate catalog for {callsite.id} needs {len(compact_request)} "
                        f"characters, over the {self.max_packet_chars} character limit"
                    )
                request = full_request if len(full_request) <= self.max_packet_chars else compact_request
                delivered = frozenset(source_text) if request == full_request else frozenset()
                initial_packet_characters += len(request)
                tasks.append(
                    (
                        request,
                        callsite,
                        group,
                        observations.get(callsite.id, ()),
                        limitation_id,
                        source_text,
                        delivered,
                    )
                )
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(tasks) or 1)) as pool:
            pending = [
                pool.submit(
                    self._resolve_callsite,
                    request,
                    callsite=callsite,
                    candidates=candidates,
                    definitions=definitions,
                    observations=callsite_observations,
                    bundle=bundle,
                    limitation_id=limitation_id,
                    source_text=source_text,
                    delivered_source_ids=delivered,
                    root=base,
                    source_catalog=source_catalog,
                )
                for (
                    request,
                    callsite,
                    candidates,
                    callsite_observations,
                    limitation_id,
                    source_text,
                    delivered,
                ) in tasks
            ]
            completed = [future.result() for future in pending]
        partials: dict[str, list[CallsiteRelationshipResult]] = {}
        for result, _calls, _input, _output in completed:
            partials.setdefault(result.callsite_id, []).append(result)
        call_results = [
            merge_partial_results(
                callsite,
                tuple(partials[callsite.id]),
                limitation_id=call_limitation_id(callsite.id),
            )
            for callsite in sorted(
                bundle.callsites,
                key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
            )
        ]
        structural_completed, structural_initial_packet_characters = self._resolve_structural_subjects(
            base,
            bundle,
            definitions,
            source_catalog,
        )
        structural_results = tuple(item[0] for item in structural_completed)
        initial_packet_characters += structural_initial_packet_characters
        model_calls = sum(calls for _result, calls, _input, _output in (*completed, *structural_completed))
        input_tokens = sum(input_count for _result, _calls, input_count, _output in (*completed, *structural_completed))
        output_tokens = sum(
            output_count for _result, _calls, _input, output_count in (*completed, *structural_completed)
        )
        if {result.callsite_id for result in call_results} != {callsite.id for callsite in bundle.callsites}:
            raise RelationshipResolutionError("relationship resolution did not receipt every callsite")
        validate_relationship_results(bundle, tuple(call_results))
        validate_structural_results(bundle, structural_results)
        return RelationshipResolution(
            call_results=tuple(call_results),
            structural_results=structural_results,
            calls=model_calls,
            initial_packet_characters=initial_packet_characters,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            elapsed_seconds=round(perf_counter() - started, 3),
        )

    def _resolve_structural_subjects(
        self,
        root: Path,
        bundle: RelationshipEvidenceBundle,
        definitions: dict[str, DefinitionEvidence],
        source_catalog: dict[str, SourceReference],
    ) -> tuple[list[tuple[StructuralRelationshipResult, int, int, int]], int]:
        tasks = []
        for subject in sorted(
            bundle.structural_subjects,
            key=lambda item: (item.source_file, item.source.start, item.kind, item.id),
        ):
            candidates = tuple(definitions[target_id] for target_id in subject.candidate_target_definition_ids)
            packet = structural_packet(root, subject, candidates, source_catalog)
            source_text = {source_id: item["text"] for source_id, item in packet["source_evidence"].items()}
            full_request = json.dumps(packet, sort_keys=True, indent=2)
            compact_payload = compact_relationship_packet(packet)
            compact_request = json.dumps(compact_payload, sort_keys=True, indent=2)
            if len(compact_request) > self.max_packet_chars:
                raise RelationshipResolutionError(
                    f"structural relationship packet for {subject.id} exceeds the character limit"
                )
            request = full_request if len(full_request) <= self.max_packet_chars else compact_request
            delivered = frozenset(source_text) if request == full_request else frozenset()
            tasks.append((request, subject, candidates, source_text, delivered))
        with ThreadPoolExecutor(max_workers=min(self.concurrency, len(tasks) or 1)) as pool:
            pending = [
                pool.submit(
                    self._resolve_structural_subject,
                    request,
                    subject=subject,
                    candidates=candidates,
                    bundle=bundle,
                    source_text=source_text,
                    delivered_source_ids=delivered,
                    root=root,
                    definitions=definitions,
                    source_catalog=source_catalog,
                )
                for request, subject, candidates, source_text, delivered in tasks
            ]
            return [future.result() for future in pending], sum(len(item[0]) for item in tasks)

    def _resolve_subject(
        self,
        request: str,
        *,
        subject_id: str,
        candidates: tuple[DefinitionEvidence, ...],
        bundle: RelationshipEvidenceBundle,
        source_text: dict[str, str],
        delivered_source_ids: frozenset[str],
        root: Path,
        definitions: dict[str, DefinitionEvidence],
        source_catalog: dict[str, SourceReference],
        parse_result: Callable[[str], _ResultT],
        validate_result: Callable[[_ResultT, frozenset[str]], None],
        validate_read_sources: Callable[[_ResultT, frozenset[str], frozenset[str]], None],
        navigation_delivery: Callable[[NavigationReceipt, dict[str, str]], dict[str, object]],
    ) -> tuple[_ResultT, int, int, int]:
        """Run one bounded relationship conversation under caller supplied schema controls."""
        messages = [Message(role="user", content=request)]
        delivered = set(delivered_source_ids)
        calls = input_tokens = output_tokens = evidence_exchanges = corrections = 0
        navigation_exchanges = 0
        navigation_receipts: list[NavigationReceipt] = []
        published_candidates = {candidate.id: candidate for candidate in candidates}
        while True:
            try:
                completion = self.provider.complete(
                    system=RELATIONSHIP_SYSTEM,
                    messages=messages,
                    model=self.model,
                    max_tokens=self.max_tokens,
                    cache=False,
                )
                calls += 1
                input_tokens += completion.usage.input_tokens
                output_tokens += completion.usage.output_tokens
            except Exception as exc:
                raise RelationshipResolutionError(
                    f"relationship provider failed for {subject_id}: {type(exc).__name__}: {exc}"
                ) from exc
            try:
                navigation_requests = parse_navigation_requests(completion.text)
                if navigation_requests is not None:
                    if navigation_exchanges >= self.navigation_followups:
                        raise RelationshipResolutionError("relationship navigation request limit reached")
                    delivery_items = []
                    for navigation_request in navigation_requests:
                        receipt = execute_navigation(
                            bundle,
                            source_catalog,
                            navigation_request,
                            page_size=self.navigation_page_size,
                            read_source=lambda reference: read_source(root, reference),
                        )
                        if receipt in navigation_receipts:
                            raise RelationshipResolutionError("relationship navigation request repeats a query page")
                        navigation_receipts.append(receipt)
                        if receipt.purpose == "target_candidate":
                            for target_id in receipt.returned_definition_ids:
                                published_candidates[target_id] = definitions[target_id]
                        for target_id in receipt.returned_definition_ids:
                            definition = definitions[target_id]
                            reference = definition.source
                            source_text[reference.id] = read_source(root, reference)
                            if definition.receiver is not None:
                                source_text[definition.receiver.source.id] = read_source(
                                    root,
                                    definition.receiver.source,
                                )
                            for parameter in definition.parameters:
                                source_text[parameter.source.id] = read_source(root, parameter.source)
                        for source_id in receipt.returned_source_ids:
                            source_text[source_id] = read_source(root, source_catalog[source_id])
                        delivery_items.append(navigation_delivery(receipt, source_text))
                    navigation_exchanges += 1
                    messages.extend(
                        (
                            Message(role="assistant", content=completion.text),
                            Message(
                                role="user",
                                content=(
                                    "Deterministic navigation results:\n"
                                    f"{json.dumps(delivery_items, sort_keys=True, indent=2)}\n\n"
                                    "Request more pages or exact source evidence, or return the final result."
                                ),
                            ),
                        )
                    )
                    continue
                requested = evidence_requests(completion.text)
                if requested is not None:
                    if evidence_exchanges >= self.evidence_followups:
                        raise RelationshipResolutionError("relationship evidence request limit reached")
                    delivery, delivered_now, remaining = deliver_relationship_evidence(
                        requested,
                        source_text,
                        delivered,
                        target_chars=self.max_packet_chars,
                    )
                    delivered.update(delivered_now)
                    evidence_exchanges += 1
                    messages.extend(
                        (
                            Message(role="assistant", content=completion.text),
                            Message(
                                role="user",
                                content=(
                                    f"Requested exact source evidence:\n{delivery}\n\n"
                                    f"Undelivered requested ids: {json.dumps(remaining)}. Request remaining ids "
                                    "in another evidence_requests object or return the final relationship result."
                                ),
                            ),
                        )
                    )
                    continue
                result = replace(
                    parse_result(completion.text),
                    navigation_receipts=tuple(navigation_receipts),
                )
                validate_result(result, frozenset(published_candidates))
                validate_read_sources(
                    result,
                    frozenset(delivered),
                    frozenset(source_text),
                )
                return result, calls, input_tokens, output_tokens
            except (BackendUnavailable, NavigationError, RelationshipResolutionError, ValueError) as exc:
                if corrections == self.correction_attempts:
                    raise RelationshipResolutionError(
                        f"relationship resolution failed for {subject_id}: {exc}"
                    ) from exc
                corrections += 1
                messages.extend(
                    (
                        Message(role="assistant", content=completion.text),
                        Message(
                            role="user",
                            content=(
                                f"The response was rejected: {exc}. Return one corrected JSON object that "
                                "follows the original contract. Do not add commentary."
                            ),
                        ),
                    )
                )

    def _resolve_structural_subject(
        self,
        request: str,
        *,
        subject: StructuralRelationshipEvidence,
        candidates: tuple[DefinitionEvidence, ...],
        bundle: RelationshipEvidenceBundle,
        source_text: dict[str, str],
        delivered_source_ids: frozenset[str],
        root: Path,
        definitions: dict[str, DefinitionEvidence],
        source_catalog: dict[str, SourceReference],
    ) -> tuple[StructuralRelationshipResult, int, int, int]:
        limitation_id = structural_limitation_id(subject.id)

        def validate_result(
            result: StructuralRelationshipResult,
            published_target_ids: frozenset[str],
        ) -> None:
            validate_structural_result(
                bundle,
                result,
                subject=subject,
                published_target_ids=published_target_ids,
                published_limitation_ids=frozenset({limitation_id}),
            )
            validate_target_navigation_coverage(
                target_coverage=result.target_coverage,
                target_navigation_required=not candidates,
                receipts=result.navigation_receipts,
            )

        return self._resolve_subject(
            request,
            subject_id=subject.id,
            candidates=candidates,
            bundle=bundle,
            source_text=source_text,
            delivered_source_ids=delivered_source_ids,
            root=root,
            definitions=definitions,
            source_catalog=source_catalog,
            parse_result=structural_result_from_response,
            validate_result=validate_result,
            validate_read_sources=validate_structural_read_sources,
            navigation_delivery=lambda receipt, text: structural_navigation_delivery(
                receipt,
                subject=subject,
                definitions=definitions,
                source_text=text,
            ),
        )

    def _resolve_callsite(
        self,
        request: str,
        *,
        callsite: CallsiteEvidence,
        candidates: tuple[DefinitionEvidence, ...],
        definitions: dict[str, DefinitionEvidence],
        observations: tuple[AnalysisObservation, ...],
        bundle: RelationshipEvidenceBundle,
        limitation_id: str,
        source_text: dict[str, str],
        delivered_source_ids: frozenset[str],
        root: Path,
        source_catalog: dict[str, SourceReference],
    ) -> tuple[CallsiteRelationshipResult, int, int, int]:
        def validate_result(
            result: CallsiteRelationshipResult,
            published_target_ids: frozenset[str],
        ) -> None:
            result.validate(
                bundle,
                published_target_ids=published_target_ids,
                published_limitation_ids=frozenset({limitation_id}),
            )
            validate_target_navigation_coverage(
                target_coverage=result.target_coverage,
                target_navigation_required=not any(observation.candidate_target_ids for observation in observations),
                receipts=result.navigation_receipts,
            )
            validate_controlling_evidence(
                result,
                callsite=callsite,
                definitions=definitions,
                observations=observations,
            )

        return self._resolve_subject(
            request,
            subject_id=callsite.id,
            candidates=candidates,
            bundle=bundle,
            source_text=source_text,
            delivered_source_ids=delivered_source_ids,
            root=root,
            definitions=definitions,
            source_catalog=source_catalog,
            parse_result=call_result_from_response,
            validate_result=validate_result,
            validate_read_sources=validate_call_read_sources,
            navigation_delivery=lambda receipt, text: call_navigation_delivery(
                receipt,
                callsite=callsite,
                definitions=definitions,
                observations=observations,
                source_text=text,
            ),
        )


__all__ = [
    "ModelRelationshipResolver",
    "RelationshipResolution",
    "RelationshipResolutionError",
    "RelationshipResolver",
    "callsite_result_incomplete",
    "graph_with_model_relationships",
    "relationship_evidence_fingerprint",
    "relationship_obligation_ids",
    "relationship_result_from_data",
    "structural_result_from_data",
    "validate_relationship_results",
    "validate_structural_results",
]
