"""Build and render language neutral syntax evidence."""

from __future__ import annotations

from cyberjury.review.facts import Facts
from cyberjury.review.relationships import (
    AnalysisObservation,
    CallsiteEvidence,
    DefinitionEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)
from cyberjury.review.syntax.analyzer import (
    AnalyzedDefinition,
    AnalyzedNamespace,
    AnalyzedOwner,
    AnalyzedRepository,
)


def facts_from_repository(repository: AnalyzedRepository) -> Facts:
    """Publish syntax evidence without claiming resolved relationships."""
    return Facts(by_file=render_by_file(repository), relationships=relationship_evidence(repository).canonical())


def relationship_evidence(repository: AnalyzedRepository) -> RelationshipEvidenceBundle:
    """Publish exact syntax as clues without assigning relationship targets."""
    definitions = _definition_evidences(repository.definitions, repository.sources)
    analyzed_by_id = {
        evidence.id: analyzed for analyzed, evidence in zip(repository.definitions, definitions, strict=True)
    }
    calls: list[CallsiteEvidence] = []
    observations: list[AnalysisObservation] = []
    extra_sources: dict[str, SourceReference] = {}
    for definition in definitions:
        analyzed = analyzed_by_id[definition.id]
        source = repository.sources[analyzed.file]
        for analyzed_call in analyzed.callsites:
            call_source = _source_reference(analyzed.file, source, analyzed_call.start, analyzed_call.end)
            callsite = CallsiteEvidence.create(
                caller_definition_id=definition.id,
                source=call_source,
                expression=analyzed_call.expression,
                callee_spelling=analyzed_call.callee,
                receiver_expression=analyzed_call.receiver,
            )
            calls.append(callsite)
            observations.append(
                AnalysisObservation.create(
                    producer="tree-sitter",
                    producer_version=repository.producer_version,
                    kind="syntax_call",
                    subject_ids=(callsite.id,),
                    provenance_source_ids=(definition.source.id, call_source.id),
                    label=(
                        f"{analyzed_call.receiver}.{analyzed_call.callee}"
                        if analyzed_call.receiver
                        else analyzed_call.callee
                    ),
                )
            )
            observations.extend(
                _declaration_observations(
                    repository,
                    analyzed,
                    definition,
                    callsite,
                    call_source,
                    source,
                    extra_sources,
                )
            )
    structural_relationships = _structural_relationships(repository, definitions)
    for relationship in structural_relationships:
        extra_sources[relationship.source.id] = relationship.source
    return RelationshipEvidenceBundle(
        sources=tuple(extra_sources.values()),
        definitions=definitions,
        callsites=tuple(calls),
        observations=tuple(observations),
        structural_relationships=structural_relationships,
    )


def _declaration_observations(
    repository: AnalyzedRepository,
    analyzed: AnalyzedDefinition,
    definition: DefinitionEvidence,
    callsite: CallsiteEvidence,
    call_source: SourceReference,
    source: str,
    extra_sources: dict[str, SourceReference],
) -> tuple[AnalysisObservation, ...]:
    output: list[AnalysisObservation] = []
    for item in repository.imports.get(analyzed.file, ()):
        if not _owner_matches(item.owner, analyzed) or item.local not in {
            callsite.callee_spelling,
            callsite.receiver_expression,
        }:
            continue
        declaration = _source_reference(analyzed.file, source, item.start, item.end)
        extra_sources[declaration.id] = declaration
        output.append(
            AnalysisObservation.create(
                producer="tree-sitter",
                producer_version=repository.producer_version,
                kind="import_declaration",
                subject_ids=(callsite.id,),
                provenance_source_ids=(definition.source.id, call_source.id, declaration.id),
                label=f"{item.local} from {_module_name(item.module)}",
            )
        )
    for item in repository.namespaces.get(analyzed.file, ()):
        if not _owner_matches(item.owner, analyzed) or not callsite.receiver_expression:
            continue
        if item.local and item.local != callsite.receiver_expression:
            continue
        declaration = _source_reference(analyzed.file, source, item.start, item.end)
        extra_sources[declaration.id] = declaration
        output.append(
            AnalysisObservation.create(
                producer="tree-sitter",
                producer_version=repository.producer_version,
                kind="namespace_declaration",
                subject_ids=(callsite.id,),
                provenance_source_ids=(definition.source.id, call_source.id, declaration.id),
                label=_namespace_label(item),
            )
        )
    return tuple(output)


def _structural_relationships(
    repository: AnalyzedRepository,
    definitions: tuple[DefinitionEvidence, ...],
) -> tuple[StructuralRelationshipEvidence, ...]:
    by_owner = {
        (analyzed.file, analyzed.name, analyzed.start, analyzed.end): evidence.id
        for analyzed, evidence in zip(repository.definitions, definitions, strict=True)
    }
    relationships: dict[str, StructuralRelationshipEvidence] = {}
    for file, imports in repository.imports.items():
        source = repository.sources[file]
        for item in imports:
            relationship = StructuralRelationshipEvidence.create(
                kind="import",
                source=_source_reference(file, source, item.start, item.end),
                reference=item.imported,
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            relationships.setdefault(relationship.id, relationship)
    for file, namespaces in repository.namespaces.items():
        source = repository.sources[file]
        for item in namespaces:
            relationship = StructuralRelationshipEvidence.create(
                kind="namespace",
                source=_source_reference(file, source, item.start, item.end),
                reference=_namespace_label(item),
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            relationships.setdefault(relationship.id, relationship)
    for file, uses in repository.qualified_uses.items():
        source = repository.sources[file]
        for item in uses:
            relationship = StructuralRelationshipEvidence.create(
                kind="reference",
                source=_source_reference(file, source, item.start, item.end),
                reference=f"{item.qualifier}.{item.name}",
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            relationships.setdefault(relationship.id, relationship)
    definitions_by_name: dict[str, tuple[str, ...]] = {}
    for definition in definitions:
        if definition.kind != "type":
            continue
        definitions_by_name[definition.name] = tuple(
            sorted((*definitions_by_name.get(definition.name, ()), definition.id))
        )
    for file, values in repository.structural_relationships.items():
        source = repository.sources[file]
        for item in values:
            relationship = StructuralRelationshipEvidence.create(
                kind=item.kind,
                source=_source_reference(file, source, item.start, item.end),
                reference=item.reference,
                source_definition_id=_owner_id(file, item.owner, by_owner),
                candidate_target_definition_ids=definitions_by_name.get(item.target_name, ()),
            )
            relationships.setdefault(relationship.id, relationship)
    return tuple(sorted(relationships.values(), key=lambda item: (item.source.path, item.source.start, item.id)))


def _definition_evidences(
    analyzed: tuple[AnalyzedDefinition, ...],
    sources: dict[str, str],
) -> tuple[DefinitionEvidence, ...]:
    by_location = {
        (definition.file, definition.name, definition.start, definition.end): definition for definition in analyzed
    }
    built: dict[tuple[str, str, int, int], DefinitionEvidence] = {}

    def build(definition: AnalyzedDefinition) -> DefinitionEvidence:
        key = (definition.file, definition.name, definition.start, definition.end)
        existing = built.get(key)
        if existing is not None:
            return existing
        source_text = sources[definition.file]
        source = _source_reference(definition.file, source_text, definition.start, definition.end)
        owner_id = ""
        if definition.owner is not None:
            owner = by_location.get(
                (definition.file, definition.owner.name, definition.owner.start, definition.owner.end)
            )
            if owner is not None:
                owner_id = build(owner).id
        if definition.is_file_scope:
            kind = "file"
        elif definition.is_type:
            kind = "type"
        else:
            kind = "function"
        evidence = DefinitionEvidence.create(
            source=source,
            kind=kind,
            name=definition.name,
            signature=definition.signature,
            owner_id=owner_id,
        )
        built[key] = evidence
        return evidence

    return tuple(build(definition) for definition in analyzed)


def _source_reference(path: str, source: str, start: int, end: int) -> SourceReference:
    return SourceReference.create(path=path, start=start, end=end, content=source[start:end])


def _owner_matches(owner: AnalyzedOwner | None, definition: AnalyzedDefinition) -> bool:
    if owner is None:
        return True
    return owner.start <= definition.start and definition.end <= owner.end


def _owner_id(
    file: str,
    owner: AnalyzedOwner | None,
    definitions: dict[tuple[str, str, int, int], str],
) -> str:
    if owner is None:
        return ""
    return definitions.get((file, owner.name, owner.start, owner.end), "")


def render_by_file(repository: AnalyzedRepository) -> dict[str, str]:
    """Render one syntax observation block per analyzed source file."""
    output: dict[str, list[str]] = {}
    for definition in repository.definitions:
        line = f"  {definition.name}()"
        if definition.calls:
            line += "  observes calls " + ", ".join(definition.calls)
        output.setdefault(definition.file, []).append(line)
    for file, imports in repository.imports.items():
        values = tuple(dict.fromkeys(f"{item.local} from {_module_name(item.module)}" for item in imports))
        if values:
            output.setdefault(file, []).insert(0, "  observes imports " + ", ".join(values))
    for file, namespaces in repository.namespaces.items():
        values = tuple(dict.fromkeys(_namespace_label(item) for item in namespaces))
        if values:
            output.setdefault(file, []).insert(0, "  observes namespaces " + ", ".join(values))
    return {file: f"{file}\n" + "\n".join(lines) for file, lines in output.items()}


def _module_name(value: str) -> str:
    return value.strip("\"'")


def _namespace_label(value: AnalyzedNamespace) -> str:
    return f"{value.local} from {value.specifier}" if value.local else value.specifier
