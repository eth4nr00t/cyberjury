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

from cyberjury.json_parse import extract_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    UnresolvedDependency,
    dependencies_data,
    unresolved_dependencies_data,
)
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationship_navigation import (
    NavigationError,
    call_navigation_delivery,
    execute_navigation,
    parse_navigation_requests,
    structural_navigation_delivery,
)
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

_ResultT = TypeVar("_ResultT", CallsiteRelationshipResult, StructuralRelationshipResult)

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
_MAX_PACKET_CHARS = 60_000


class RelationshipResolutionError(RuntimeError):
    """One model call cannot produce an attributable relationship result."""


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
    max_packet_chars: int = _MAX_PACKET_CHARS
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
        source_catalog = _source_catalog(bundle)
        definitions = {definition.id: definition for definition in bundle.definitions}
        observations = _observations_by_callsite(bundle.observations)
        tasks = []
        initial_packet_characters = 0
        for callsite in sorted(
            bundle.callsites,
            key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
        ):
            candidates = _callsite_candidates(callsite, bundle, observations.get(callsite.id, ()))
            limitation_id = _limitation_id(callsite.id)
            packet = _packet(
                base,
                callsite,
                candidates,
                definitions,
                observations.get(callsite.id, ()),
                source_catalog,
                limitation_id,
            )
            groups = _candidate_groups(packet, candidates, self.max_packet_chars)
            for group in groups:
                grouped_packet = (
                    packet
                    if group == candidates
                    else _packet(
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
                compact_packet = _compact_packet(grouped_packet)
                compact_request = json.dumps(compact_packet, sort_keys=True, indent=2)
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
            _merge_partial_results(
                callsite,
                tuple(partials[callsite.id]),
                limitation_id=_limitation_id(callsite.id),
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
            packet = _structural_packet(root, subject, candidates, source_catalog)
            source_text = {source_id: item["text"] for source_id, item in packet["source_evidence"].items()}
            full_request = json.dumps(packet, sort_keys=True, indent=2)
            compact_packet = _compact_packet(packet)
            compact_request = json.dumps(compact_packet, sort_keys=True, indent=2)
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
                            read_source=lambda reference: _read_source(root, reference),
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
                            source_text[reference.id] = _read_source(root, reference)
                            for parameter in definition.parameters:
                                source_text[parameter.source.id] = _read_source(root, parameter.source)
                        for source_id in receipt.returned_source_ids:
                            source_text[source_id] = _read_source(root, source_catalog[source_id])
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
                requested = _evidence_requests(completion.text)
                if requested is not None:
                    if evidence_exchanges >= self.evidence_followups:
                        raise RelationshipResolutionError("relationship evidence request limit reached")
                    delivery, delivered_now, remaining = _deliver_relationship_evidence(
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
        limitation_id = _structural_limitation_id(subject.id)

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
            parse_result=_structural_result_from_response,
            validate_result=validate_result,
            validate_read_sources=_validate_structural_read_sources,
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
            _validate_controlling_evidence(
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
            parse_result=_result_from_response,
            validate_result=validate_result,
            validate_read_sources=_validate_read_source_ids,
            navigation_delivery=lambda receipt, text: call_navigation_delivery(
                receipt,
                callsite=callsite,
                definitions=definitions,
                observations=observations,
                source_text=text,
            ),
        )


def relationship_evidence_fingerprint(bundle: RelationshipEvidenceBundle) -> str:
    """Hash the canonical producer evidence persisted beside model results."""
    encoded = json.dumps(bundle.to_data(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def callsite_result_incomplete(result: CallsiteRelationshipResult) -> bool:
    """Include unresolved target coverage and unresolved cross-call data mapping."""
    return result.target_coverage == "incomplete" or any(
        relation.data_coverage == "incomplete" for relation in result.supported_relations
    )


def relationship_obligation_ids(resolution: RelationshipResolution) -> tuple[str, ...]:
    """Project every unresolved relationship dimension into pending work identities."""
    obligations = [
        limitation
        for result in resolution.call_results
        if result.target_coverage == "incomplete"
        for limitation in result.coverage_limitation_ids
    ]
    obligations.extend(
        f"data:{result.callsite_id}:{relation.target_definition_id}"
        for result in resolution.call_results
        for relation in result.supported_relations
        if relation.data_coverage == "incomplete"
    )
    obligations.extend(
        limitation
        for result in resolution.structural_results
        if result.target_coverage == "incomplete"
        for limitation in result.coverage_limitation_ids
    )
    return tuple(dict.fromkeys(obligations))


def validate_relationship_results(
    bundle: RelationshipEvidenceBundle,
    call_results: tuple[CallsiteRelationshipResult, ...],
) -> None:
    """Revalidate a complete persisted result set against current evidence."""
    callsites = {callsite.id: callsite for callsite in bundle.callsites}
    if len(call_results) != len(callsites) or {result.callsite_id for result in call_results} != set(callsites):
        raise BackendUnavailable("model relationships must receipt every producer callsite exactly once")
    definitions = {definition.id: definition for definition in bundle.definitions}
    observations = _observations_by_callsite(bundle.observations)
    for result in call_results:
        callsite = callsites[result.callsite_id]
        candidates = _callsite_candidates(callsite, bundle, observations.get(callsite.id, ()))
        published = {
            *(candidate.id for candidate in candidates),
            *(
                definition_id
                for receipt in result.navigation_receipts
                if receipt.purpose == "target_candidate"
                for definition_id in receipt.returned_definition_ids
            ),
        }
        result.validate(
            bundle,
            published_target_ids=frozenset(published),
            published_limitation_ids=frozenset({_limitation_id(callsite.id)}),
        )
        _validate_controlling_evidence(
            result,
            callsite=callsite,
            definitions=definitions,
            observations=observations.get(callsite.id, ()),
        )


def validate_structural_results(
    bundle: RelationshipEvidenceBundle,
    results: tuple[StructuralRelationshipResult, ...],
) -> None:
    """Revalidate every persisted non-call relationship against current evidence."""
    subjects = {subject.id: subject for subject in bundle.structural_subjects}
    if len(results) != len(subjects) or {result.subject_id for result in results} != set(subjects):
        raise BackendUnavailable("model relationships must receipt every structural subject exactly once")
    for result in results:
        subject = subjects[result.subject_id]
        validate_structural_result(
            bundle,
            result,
            subject=subject,
            published_target_ids=frozenset(
                {
                    *subject.candidate_target_definition_ids,
                    *(
                        target
                        for receipt in result.navigation_receipts
                        if receipt.purpose == "target_candidate"
                        for target in receipt.returned_definition_ids
                    ),
                }
            ),
            published_limitation_ids=frozenset({_structural_limitation_id(subject.id)}),
        )


def validate_structural_result(
    bundle: RelationshipEvidenceBundle,
    result: StructuralRelationshipResult,
    *,
    subject: StructuralRelationshipEvidence,
    published_target_ids: frozenset[str],
    published_limitation_ids: frozenset[str],
) -> None:
    definitions = {definition.id: definition for definition in bundle.definitions}
    sources = set(_source_catalog(bundle))
    if result.subject_id != subject.id:
        raise BackendUnavailable("structural relationship result references the wrong subject")
    supported = tuple(relation.target_definition_id for relation in result.supported_relations)
    candidates = result.candidate_target_ids
    excluded = tuple(item.target_definition_id for item in result.excluded_candidates)
    if any(len(values) != len(set(values)) for values in (supported, candidates, excluded)):
        raise BackendUnavailable("structural relationship result contains duplicate targets")
    target_sets = (set(supported), set(candidates), set(excluded))
    if any(
        left.intersection(right) for position, left in enumerate(target_sets) for right in target_sets[position + 1 :]
    ):
        raise BackendUnavailable("structural relationship result overlaps target categories")
    accounted = set().union(*target_sets)
    if accounted != published_target_ids:
        raise BackendUnavailable("structural relationship result must account for every published target")
    if not accounted <= set(definitions):
        raise BackendUnavailable("structural relationship result references unknown definitions")
    receipt_ids = {receipt.id for receipt in result.navigation_receipts}
    evidence = sources | receipt_ids
    for label, target_id, evidence_ids in (
        *(("supported relation", item.target_definition_id, item.evidence_ids) for item in result.supported_relations),
        *(("excluded candidate", item.target_definition_id, item.evidence_ids) for item in result.excluded_candidates),
    ):
        unknown = set(evidence_ids).difference(evidence)
        if unknown:
            raise BackendUnavailable("structural relationship result references unknown evidence")
        required = {subject.source.id, definitions[target_id].source.id}
        if target_id not in subject.candidate_target_definition_ids:
            query_receipts = {
                receipt.id
                for receipt in result.navigation_receipts
                if receipt.purpose == "target_candidate" and target_id in receipt.returned_definition_ids
            }
            if not query_receipts.intersection(evidence_ids):
                raise BackendUnavailable(f"{label} {target_id} omits its navigation receipt")
        missing = required.difference(evidence_ids)
        if missing:
            raise BackendUnavailable(f"{label} {target_id} omits controlling evidence: {', '.join(sorted(missing))}")
    if result.target_coverage == "complete" and (candidates or result.coverage_limitation_ids):
        raise BackendUnavailable("complete structural coverage cannot retain candidates or limitations")
    if result.target_coverage == "incomplete" and not (candidates or result.coverage_limitation_ids):
        raise BackendUnavailable("incomplete structural coverage must explain the remaining obligation")
    if not set(result.coverage_limitation_ids) <= published_limitation_ids:
        raise BackendUnavailable("structural relationship result references unknown limitations")
    if not result.reason.strip():
        raise BackendUnavailable("structural relationship result reason must not be empty")


def relationship_result_from_data(value: object) -> CallsiteRelationshipResult:
    """Load one persisted strict result without model output repair."""
    try:
        text = json.dumps(value, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise BackendUnavailable(f"relationship result is not JSON serializable: {exc}") from exc
    try:
        return _result_from_response(text, persisted=True)
    except RelationshipResolutionError as exc:
        raise BackendUnavailable(str(exc)) from exc


def structural_result_from_data(value: object) -> StructuralRelationshipResult:
    """Load one persisted structural result without repairing its output."""
    try:
        text = json.dumps(value, separators=(",", ":"))
        return _structural_result_from_response(text, persisted=True)
    except (TypeError, ValueError, RelationshipResolutionError) as exc:
        raise BackendUnavailable(str(exc)) from exc


def graph_with_model_relationships(
    graph: dict[str, object],
    bundle: RelationshipEvidenceBundle,
    call_results: tuple[CallsiteRelationshipResult, ...],
    structural_results: tuple[StructuralRelationshipResult, ...] = (),
) -> dict[str, object]:
    """Replace coded edges with validated model established relationships."""
    callsites = {callsite.id: callsite for callsite in bundle.callsites}
    definitions = {definition.id: definition for definition in bundle.definitions}
    validate_relationship_results(bundle, call_results)
    validate_structural_results(bundle, structural_results)
    model_dependencies: list[DefinitionDependency] = []
    model_unresolved: list[UnresolvedDependency] = []
    for result in call_results:
        callsite = callsites[result.callsite_id]
        caller = definitions[callsite.caller_definition_id]
        source = _fragment(caller)
        for relation in result.supported_relations:
            target_definition = definitions[relation.target_definition_id]
            target = _fragment(target_definition)
            if target != source:
                model_dependencies.append(
                    DefinitionDependency(
                        source_file=source.file,
                        source=source,
                        target=target,
                        kind="call",
                        resolution="supported",
                        reference=callsite.callee_spelling,
                    )
                )
                parameters = {parameter.id: parameter for parameter in target_definition.parameters}
                for data_relation in relation.argument_relations:
                    parameter = parameters[data_relation.parameter_id]
                    model_dependencies.append(
                        DefinitionDependency(
                            source_file=source.file,
                            source=source,
                            target=target,
                            kind="data",
                            resolution="supported",
                            reference=(
                                f"{callsite.callee_spelling} argument[{data_relation.argument_position}] "
                                f"to parameter[{parameter.position}] {parameter.name}"
                            ),
                        )
                    )
                if relation.data_coverage == "incomplete":
                    model_unresolved.append(
                        UnresolvedDependency(
                            source_file=source.file,
                            source=source,
                            kind="data",
                            reference=f"{callsite.callee_spelling} argument mapping",
                        )
                    )
        for context in result.related_contexts:
            target = _fragment(definitions[context.definition_id])
            if target != source:
                model_dependencies.append(
                    DefinitionDependency(
                        source_file=source.file,
                        source=source,
                        target=target,
                        kind=context.kind,
                        resolution="supported",
                        reference=context.reason,
                    )
                )
        if result.target_coverage == "incomplete":
            model_unresolved.append(
                UnresolvedDependency(
                    source_file=source.file,
                    source=source,
                    kind="call",
                    reference=callsite.callee_spelling,
                )
            )
    structural_subjects = {subject.id: subject for subject in bundle.structural_subjects}
    for result in structural_results:
        subject = structural_subjects[result.subject_id]
        source_definition = definitions[subject.source_definition_id] if subject.source_definition_id else None
        source = _fragment(source_definition) if source_definition is not None else None
        kind = "import" if subject.kind == "namespace" else subject.kind
        for relation in result.supported_relations:
            target = _fragment(definitions[relation.target_definition_id])
            if target != source:
                model_dependencies.append(
                    DefinitionDependency(
                        source_file=subject.source_file,
                        source=source,
                        target=target,
                        kind=kind,
                        resolution="supported",
                        reference=subject.reference,
                    )
                )
        if result.target_coverage == "incomplete":
            model_unresolved.append(
                UnresolvedDependency(
                    source_file=subject.source_file,
                    source=source,
                    kind=kind,
                    reference=subject.reference,
                )
            )
    updated = json.loads(json.dumps(graph))
    updated["dependencies"] = dependencies_data(tuple(dict.fromkeys(model_dependencies)))
    updated["unresolved_dependencies"] = unresolved_dependencies_data(tuple(dict.fromkeys(model_unresolved)))
    return updated


def _fragment(definition: DefinitionEvidence) -> DefinitionFragment:
    return DefinitionFragment(
        definition.source.path,
        definition.name,
        definition.source.start,
        definition.source.end,
    )


def _source_catalog(bundle: RelationshipEvidenceBundle) -> dict[str, SourceReference]:
    sources = {source.id: source for source in bundle.sources}
    for definition in bundle.definitions:
        sources[definition.source.id] = definition.source
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


def _observations_by_callsite(
    observations: tuple[AnalysisObservation, ...],
) -> dict[str, tuple[AnalysisObservation, ...]]:
    grouped: dict[str, list[AnalysisObservation]] = {}
    for observation in observations:
        for subject in observation.subject_ids:
            if subject.startswith("call-"):
                grouped.setdefault(subject, []).append(observation)
    return {key: tuple(values) for key, values in grouped.items()}


def _callsite_candidates(
    callsite: CallsiteEvidence,
    bundle: RelationshipEvidenceBundle,
    observations: tuple[AnalysisObservation, ...],
) -> tuple[DefinitionEvidence, ...]:
    observed = {target_id for observation in observations for target_id in observation.candidate_target_ids}
    spelling = _base_name(callsite.callee_spelling)
    matching = {definition.id for definition in bundle.definitions if _base_name(definition.name) == spelling}
    selected = observed | matching
    return tuple(
        definition
        for definition in sorted(
            bundle.definitions,
            key=lambda item: (item.source.path, item.source.start, item.source.end, item.id),
        )
        if definition.id in selected
    )


def _base_name(value: str) -> str:
    return value.split("(", 1)[0].rsplit(".", 1)[-1]


def _limitation_id(callsite_id: str) -> str:
    return f"lim-{hashlib.sha256(f'{callsite_id}:unresolved-target-coverage'.encode()).hexdigest()[:16]}"


def _structural_limitation_id(subject_id: str) -> str:
    return f"lim-{hashlib.sha256(f'{subject_id}:unresolved-structural-coverage'.encode()).hexdigest()[:16]}"


def _packet(
    root: Path,
    callsite: CallsiteEvidence,
    candidates: tuple[DefinitionEvidence, ...],
    definitions: dict[str, DefinitionEvidence],
    observations: tuple[AnalysisObservation, ...],
    sources: dict[str, SourceReference],
    limitation_id: str,
) -> dict[str, object]:
    caller = definitions[callsite.caller_definition_id]
    evidence_ids = {caller.source.id, callsite.source.id}
    evidence_ids.update(argument.source.id for argument in callsite.arguments if argument.source is not None)
    evidence_ids.update(source_id for observation in observations for source_id in observation.provenance_source_ids)
    evidence_ids.update(candidate.source.id for candidate in candidates)
    for candidate in candidates:
        if candidate.owner_id and candidate.owner_id in definitions:
            evidence_ids.add(definitions[candidate.owner_id].source.id)
        evidence_ids.update(parameter.source.id for parameter in candidate.parameters)
    source_evidence = {
        source_id: {
            "reference": sources[source_id].to_data(),
            "text": _read_source(root, sources[source_id]),
        }
        for source_id in sorted(evidence_ids)
    }
    strong = tuple(
        observation
        for observation in observations
        if observation.kind in {"import_binding", "namespace_binding", "static_call_target"}
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


def _structural_packet(
    root: Path,
    subject: StructuralRelationshipEvidence,
    candidates: tuple[DefinitionEvidence, ...],
    sources: dict[str, SourceReference],
) -> dict[str, object]:
    limitation_id = _structural_limitation_id(subject.id)
    evidence_ids = {subject.source.id, *(candidate.source.id for candidate in candidates)}
    source_evidence = {
        source_id: {"reference": sources[source_id].to_data(), "text": _read_source(root, sources[source_id])}
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


def _candidate_groups(
    packet: dict[str, object],
    candidates: tuple[DefinitionEvidence, ...],
    max_packet_chars: int,
) -> tuple[tuple[DefinitionEvidence, ...], ...]:
    """Keep one judgment when metadata fits, otherwise split without dropping candidates."""
    compact = json.dumps(_compact_packet(packet), sort_keys=True, indent=2)
    if len(compact) <= max_packet_chars or len(candidates) <= 1:
        return (candidates,)
    return tuple((candidate,) for candidate in candidates)


def _compact_packet(packet: dict[str, object]) -> dict[str, object]:
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


def _evidence_requests(text: str) -> tuple[str, ...] | None:
    value = extract_json_object(text)
    if not isinstance(value, dict) or set(value) != {"evidence_requests"}:
        return None
    requested = value["evidence_requests"]
    if not isinstance(requested, list) or not all(isinstance(item, str) and item for item in requested):
        raise RelationshipResolutionError("relationship evidence_requests must be a string list")
    if not requested or len(requested) != len(set(requested)):
        raise RelationshipResolutionError("relationship evidence_requests must be nonempty and unique")
    return tuple(requested)


def _deliver_relationship_evidence(
    requested: tuple[str, ...],
    sources: dict[str, str],
    delivered: set[str],
    *,
    target_chars: int,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
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


def _validate_read_source_ids(
    result: CallsiteRelationshipResult,
    delivered: frozenset[str],
    published_sources: frozenset[str],
) -> None:
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


def _merge_partial_results(
    callsite: CallsiteEvidence,
    partial_results: tuple[CallsiteRelationshipResult, ...],
    *,
    limitation_id: str,
) -> CallsiteRelationshipResult:
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


def _read_source(root: Path, reference: SourceReference) -> str:
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


def _result_from_response(text: str, *, persisted: bool = False) -> CallsiteRelationshipResult:
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


def _structural_result_from_response(
    text: str,
    *,
    persisted: bool = False,
) -> StructuralRelationshipResult:
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


def _validate_structural_read_sources(
    result: StructuralRelationshipResult,
    delivered: frozenset[str],
    published_sources: frozenset[str],
) -> None:
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


def _validate_controlling_evidence(
    result: CallsiteRelationshipResult,
    *,
    callsite: CallsiteEvidence,
    definitions: dict[str, DefinitionEvidence],
    observations: tuple[AnalysisObservation, ...],
) -> None:
    caller = definitions[callsite.caller_definition_id]
    strong = tuple(
        observation
        for observation in observations
        if observation.kind in {"import_binding", "namespace_binding", "static_call_target"}
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
        if target_id not in initial_targets and _base_name(definitions[target_id].name) != _base_name(
            callsite.callee_spelling
        ):
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
            parameter = parameters[data_relation.parameter_id]
            required = {argument.source.id, parameter.source.id}
            missing = required.difference(data_relation.evidence_ids)
            if missing:
                raise RelationshipResolutionError(
                    "argument relation "
                    f"{data_relation.argument_position} omits exact endpoint evidence: {', '.join(sorted(missing))}"
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
