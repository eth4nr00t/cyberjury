"""Validate relationship results and project supported edges into facts graphs."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    UnresolvedDependency,
    dependencies_data,
    unresolved_dependencies_data,
)
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationship_protocol import (
    RelationshipResolutionError,
    call_result_from_response,
    callsite_candidates,
    limitation_id,
    observations_by_callsite,
    source_catalog,
    structural_limitation_id,
    structural_result_from_response,
    validate_controlling_evidence,
)
from cyberjury.review.relationships import (
    CallsiteRelationshipResult,
    DefinitionEvidence,
    NavigationReceipt,
    RelationshipEvidenceBundle,
    StructuralRelationshipEvidence,
    StructuralRelationshipResult,
)

if TYPE_CHECKING:
    from cyberjury.review.relations import RelationshipResolution


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
    observations = observations_by_callsite(bundle.observations)
    for result in call_results:
        callsite = callsites[result.callsite_id]
        candidates = callsite_candidates(callsite, bundle, observations.get(callsite.id, ()))
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
            published_limitation_ids=frozenset({limitation_id(callsite.id)}),
        )
        validate_target_navigation_coverage(
            target_coverage=result.target_coverage,
            target_navigation_required=not any(
                observation.candidate_target_ids for observation in observations.get(callsite.id, ())
            ),
            receipts=result.navigation_receipts,
        )
        validate_controlling_evidence(
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
            published_limitation_ids=frozenset({structural_limitation_id(subject.id)}),
        )
        validate_target_navigation_coverage(
            target_coverage=result.target_coverage,
            target_navigation_required=not subject.candidate_target_definition_ids,
            receipts=result.navigation_receipts,
        )


def validate_target_navigation_coverage(
    *,
    target_coverage: str,
    target_navigation_required: bool,
    receipts: tuple[NavigationReceipt, ...],
) -> None:
    """Require attributable and fully paged target search before complete coverage."""
    if target_coverage != "complete":
        return
    target_receipts = tuple(receipt for receipt in receipts if receipt.purpose == "target_candidate")
    if target_navigation_required and not target_receipts:
        raise BackendUnavailable("complete target coverage without producer targets requires target navigation")
    query_keys = {(receipt.kind, receipt.query, receipt.path_prefix) for receipt in target_receipts}
    if any(
        not any(
            receipt.kind == kind
            and receipt.query == query
            and receipt.path_prefix == path_prefix
            and receipt.cursor == 0
            for receipt in target_receipts
        )
        for kind, query, path_prefix in query_keys
    ):
        raise BackendUnavailable("complete target coverage requires every target navigation query to begin at cursor 0")
    pages = {(receipt.kind, receipt.query, receipt.path_prefix, receipt.cursor) for receipt in target_receipts}
    incomplete = [
        receipt
        for receipt in target_receipts
        if receipt.next_cursor is not None
        and (receipt.kind, receipt.query, receipt.path_prefix, receipt.next_cursor) not in pages
    ]
    if incomplete:
        raise BackendUnavailable("complete target coverage requires every target navigation page")


def validate_structural_result(
    bundle: RelationshipEvidenceBundle,
    result: StructuralRelationshipResult,
    *,
    subject: StructuralRelationshipEvidence,
    published_target_ids: frozenset[str],
    published_limitation_ids: frozenset[str],
) -> None:
    """Validate one structural result against published targets and evidence."""
    definitions = {definition.id: definition for definition in bundle.definitions}
    sources = set(source_catalog(bundle))
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
        return call_result_from_response(text, persisted=True)
    except RelationshipResolutionError as exc:
        raise BackendUnavailable(str(exc)) from exc


def structural_result_from_data(value: object) -> StructuralRelationshipResult:
    """Load one persisted structural result without repairing its output."""
    try:
        text = json.dumps(value, separators=(",", ":"))
        return structural_result_from_response(text, persisted=True)
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


__all__ = [
    "callsite_result_incomplete",
    "graph_with_model_relationships",
    "relationship_evidence_fingerprint",
    "relationship_obligation_ids",
    "relationship_result_from_data",
    "structural_result_from_data",
    "validate_relationship_results",
    "validate_structural_result",
    "validate_structural_results",
    "validate_target_navigation_coverage",
]
