"""Build and render the Web profile's language neutral syntax evidence."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.profiles.web.facts.analyzer import (
    AnalyzedDefinition,
    AnalyzedImport,
    AnalyzedNamespace,
    AnalyzedOwner,
    AnalyzedQualifiedUse,
    AnalyzedRepository,
)
from cyberjury.profiles.web.facts.resolver import RepositoryNavigationEvidence
from cyberjury.review.facts import Facts
from cyberjury.review.relationships import (
    AnalysisObservation,
    ArgumentEvidence,
    CallsiteEvidence,
    DefinitionEvidence,
    ParameterEvidence,
    ReceiverEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)


@dataclass(frozen=True, kw_only=True)
class Graph:
    """Store exact syntax facts and requestable repository evidence."""

    definitions: tuple[AnalyzedDefinition, ...]
    syntax_imports: dict[str, list[AnalyzedImport]]
    syntax_namespaces: dict[str, list[AnalyzedNamespace]]
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]]
    sources: dict[str, str]
    producer_version: str

    def to_data(self) -> dict[str, dict[str, list[dict[str, object]]]]:
        """Preserve repeated definition names in deterministic source order."""
        output: dict[str, dict[str, list[dict[str, object]]]] = {}
        for definition in self.definitions:
            entry = {"range": [definition.start, definition.end], "calls": list(definition.calls)}
            output.setdefault(definition.file, {}).setdefault(definition.name, []).append(entry)
        return output


def build_graph(analyzed: AnalyzedRepository, navigation: RepositoryNavigationEvidence) -> Graph:
    """Combine parsed syntax with unparsed repository declaration evidence."""
    return Graph(
        definitions=analyzed.definitions,
        syntax_imports=analyzed.imports,
        syntax_namespaces=analyzed.namespaces,
        qualified_uses=analyzed.qualified_uses,
        sources={**analyzed.sources, **navigation.navigation_sources},
        producer_version=analyzed.producer_version,
    )


def facts_from_graph(graph: Graph) -> Facts:
    """Serialize syntax evidence without claiming resolved relationships."""
    if not graph.definitions and not any(
        (
            any(graph.syntax_imports.values()),
            any(graph.syntax_namespaces.values()),
            any(graph.qualified_uses.values()),
        )
    ):
        return Facts()
    data = {
        "relationship_evidence": relationship_evidence(graph).to_data(),
        "graph": {
            "callgraph": graph.to_data(),
            "syntax_imports": syntax_imports_data(graph.syntax_imports),
            "syntax_namespaces": syntax_namespaces_data(graph.syntax_namespaces),
            "qualified_uses": qualified_uses_data(graph.qualified_uses),
            "dependencies": [],
            "unresolved_dependencies": [],
        },
        "by_file": render_by_file(graph),
    }
    return Facts(summary=render_summary(graph), data=data)


def relationship_evidence(graph: Graph) -> RelationshipEvidenceBundle:
    """Publish exact syntax as clues without assigning relationship targets."""
    missing = {definition.file for definition in graph.definitions}.difference(graph.sources)
    if missing:
        raise ValueError(f"missing analyzed source for: {', '.join(sorted(missing))}")
    definitions = _definition_evidences(graph.definitions, graph.sources)
    analyzed_by_id = {evidence.id: analyzed for analyzed, evidence in zip(graph.definitions, definitions, strict=True)}
    calls: list[CallsiteEvidence] = []
    observations: list[AnalysisObservation] = []
    extra_sources = _file_references(graph.sources)
    for definition in definitions:
        analyzed = analyzed_by_id[definition.id]
        source = graph.sources[analyzed.file]
        for analyzed_call in analyzed.callsites:
            call_source = _source_reference(analyzed.file, source, analyzed_call.start, analyzed_call.end)
            arguments = tuple(
                ArgumentEvidence(
                    position=argument.position,
                    name=argument.name,
                    expression=argument.expression,
                    source=_source_reference(analyzed.file, source, argument.start, argument.end),
                )
                for argument in analyzed_call.arguments
            )
            callsite = CallsiteEvidence.create(
                caller_definition_id=definition.id,
                source=call_source,
                expression=analyzed_call.expression,
                callee_spelling=analyzed_call.callee,
                receiver_expression=analyzed_call.receiver,
                arguments=arguments,
            )
            calls.append(callsite)
            observations.append(
                AnalysisObservation.create(
                    producer="tree-sitter",
                    producer_version=graph.producer_version,
                    kind="syntax_call",
                    subject_ids=(callsite.id,),
                    candidate_target_ids=(),
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
                    graph,
                    analyzed,
                    definition,
                    callsite,
                    call_source,
                    source,
                    extra_sources,
                )
            )
    structural_subjects = _structural_subjects(graph, definitions)
    for subject in structural_subjects:
        extra_sources[subject.source.id] = subject.source
    return RelationshipEvidenceBundle(
        sources=tuple(extra_sources.values()),
        definitions=definitions,
        callsites=tuple(calls),
        observations=tuple(observations),
        structural_subjects=structural_subjects,
    )


def _declaration_observations(
    graph: Graph,
    analyzed: AnalyzedDefinition,
    definition: DefinitionEvidence,
    callsite: CallsiteEvidence,
    call_source: SourceReference,
    source: str,
    extra_sources: dict[str, SourceReference],
) -> tuple[AnalysisObservation, ...]:
    output: list[AnalysisObservation] = []
    for item in graph.syntax_imports.get(analyzed.file, ()):
        if not _owner_matches(item.owner, analyzed) or (item.local or item.imported) != callsite.callee_spelling:
            continue
        declaration = _source_reference(analyzed.file, source, item.start, item.end)
        extra_sources[declaration.id] = declaration
        output.append(
            AnalysisObservation.create(
                producer="tree-sitter",
                producer_version=graph.producer_version,
                kind="import_declaration",
                subject_ids=(callsite.id,),
                candidate_target_ids=(),
                provenance_source_ids=(definition.source.id, call_source.id, declaration.id),
                label=f"{item.local or item.imported} from {_module_name(item.module)}",
            )
        )
    for item in graph.syntax_namespaces.get(analyzed.file, ()):
        if not _owner_matches(item.owner, analyzed) or not callsite.receiver_expression:
            continue
        if item.local and item.local != callsite.receiver_expression:
            continue
        declaration = _source_reference(analyzed.file, source, item.start, item.end)
        extra_sources[declaration.id] = declaration
        output.append(
            AnalysisObservation.create(
                producer="tree-sitter",
                producer_version=graph.producer_version,
                kind="namespace_declaration",
                subject_ids=(callsite.id,),
                candidate_target_ids=(),
                provenance_source_ids=(definition.source.id, call_source.id, declaration.id),
                label=_namespace_label(item),
            )
        )
    return tuple(output)


def _structural_subjects(
    graph: Graph,
    definitions: tuple[DefinitionEvidence, ...],
) -> tuple[StructuralRelationshipEvidence, ...]:
    by_owner = {
        (analyzed.file, analyzed.name, analyzed.start, analyzed.end): evidence.id
        for analyzed, evidence in zip(graph.definitions, definitions, strict=True)
    }
    subjects: dict[str, StructuralRelationshipEvidence] = {}
    for file, imports in graph.syntax_imports.items():
        source = graph.sources[file]
        for item in imports:
            subject = StructuralRelationshipEvidence.create(
                kind="import",
                source_file=file,
                source=_source_reference(file, source, item.start, item.end),
                reference=item.imported or item.local or _module_name(item.module),
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            subjects.setdefault(subject.id, subject)
    for file, namespaces in graph.syntax_namespaces.items():
        source = graph.sources[file]
        for item in namespaces:
            subject = StructuralRelationshipEvidence.create(
                kind="namespace",
                source_file=file,
                source=_source_reference(file, source, item.start, item.end),
                reference=_namespace_label(item),
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            subjects.setdefault(subject.id, subject)
    for file, uses in graph.qualified_uses.items():
        source = graph.sources[file]
        for item in uses:
            subject = StructuralRelationshipEvidence.create(
                kind="reference",
                source_file=file,
                source=_source_reference(file, source, item.start, item.end),
                reference=f"{item.qualifier}.{item.name}",
                source_definition_id=_owner_id(file, item.owner, by_owner),
            )
            subjects.setdefault(subject.id, subject)
    return tuple(sorted(subjects.values(), key=lambda item: (item.source_file, item.source.start, item.id)))


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
        elif definition.type_owner is not None or definition.receiver is not None:
            kind = "method"
        else:
            kind = "function"
        evidence = DefinitionEvidence.create(
            source=source,
            kind=kind,
            name=definition.name,
            signature=definition.signature,
            owner_id=owner_id,
            parameters=tuple(
                ParameterEvidence.create(
                    position=parameter.position,
                    name=parameter.name,
                    source=_source_reference(definition.file, source_text, parameter.start, parameter.end),
                    declaration=parameter.declaration,
                    type_name=parameter.type_name,
                )
                for parameter in definition.parameters
            ),
            receiver=(
                ReceiverEvidence.create(
                    name=definition.receiver.name,
                    source=_source_reference(
                        definition.file,
                        source_text,
                        definition.receiver.start,
                        definition.receiver.end,
                    ),
                    declaration=definition.receiver.declaration,
                    type_name=definition.receiver.type_name,
                )
                if definition.receiver is not None
                else None
            ),
        )
        built[key] = evidence
        return evidence

    return tuple(build(definition) for definition in analyzed)


def _file_references(sources: dict[str, str]) -> dict[str, SourceReference]:
    references: dict[str, SourceReference] = {}
    for path, content in sources.items():
        if not content:
            continue
        reference = SourceReference.create(path=path, start=0, end=len(content), content=content)
        references[reference.id] = reference
    return references


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


def render_by_file(graph: Graph) -> dict[str, str]:
    """Render one syntax observation block per analyzed source file."""
    output: dict[str, list[str]] = {}
    for definition in graph.definitions:
        line = f"  {definition.name}()"
        if definition.calls:
            line += "  observes calls " + ", ".join(definition.calls)
        output.setdefault(definition.file, []).append(line)
    for file, imports in graph.syntax_imports.items():
        values = tuple(
            dict.fromkeys(f"{item.local or item.imported} from {_module_name(item.module)}" for item in imports)
        )
        if values:
            output.setdefault(file, []).insert(0, "  observes imports " + ", ".join(values))
    for file, namespaces in graph.syntax_namespaces.items():
        values = tuple(dict.fromkeys(_namespace_label(item) for item in namespaces))
        if values:
            output.setdefault(file, []).insert(0, "  observes namespaces " + ", ".join(values))
    return {file: f"{file}\n" + "\n".join(lines) for file, lines in output.items()}


def syntax_imports_data(values: dict[str, list[AnalyzedImport]]) -> dict[str, list[dict[str, object]]]:
    """Serialize exact import declarations without interpreting module targets."""
    return {
        file: [
            {
                "module": _module_name(item.module),
                "imported": item.imported,
                "local": item.local,
                "range": [item.start, item.end],
            }
            for item in imports
        ]
        for file, imports in values.items()
        if imports
    }


def syntax_namespaces_data(values: dict[str, list[AnalyzedNamespace]]) -> dict[str, list[dict[str, object]]]:
    """Serialize exact namespace declarations without interpreting their targets."""
    return {
        file: [
            {
                "local": item.local,
                "specifier": item.specifier,
                "range": [item.start, item.end],
            }
            for item in namespaces
        ]
        for file, namespaces in values.items()
        if namespaces
    }


def qualified_uses_data(values: dict[str, list[AnalyzedQualifiedUse]]) -> dict[str, list[dict[str, object]]]:
    """Serialize qualified syntax uses as unresolved relationship clues."""
    return {
        file: [
            {
                "qualifier": item.qualifier,
                "name": item.name,
                "range": [item.start, item.end],
            }
            for item in uses
        ]
        for file, uses in values.items()
        if uses
    }


def _module_name(value: str) -> str:
    return value.strip("\"'")


def _namespace_label(value: AnalyzedNamespace) -> str:
    return f"{value.local} from {value.specifier}" if value.local else value.specifier


def render_summary(graph: Graph) -> str:
    """Summarize deterministic syntax evidence without claiming relationship edges."""
    files = len({definition.file for definition in graph.definitions})
    calls = sum(len(definition.callsites) for definition in graph.definitions)
    structural = sum(map(len, graph.syntax_imports.values()))
    structural += sum(map(len, graph.syntax_namespaces.values()))
    structural += sum(map(len, graph.qualified_uses.values()))
    return (
        f"Syntax evidence: {len(graph.definitions)} definitions across {files} files, "
        f"{calls} call observations, and {structural} structural observations. "
        "Relationship targets remain unresolved until model analysis."
    )
