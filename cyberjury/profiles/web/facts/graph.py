"""Build and render the web profile's resolved syntax graph."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.profiles.web.facts.analyzer import (
    AnalyzedDefinition,
    AnalyzedImport,
    AnalyzedNamespace,
    AnalyzedRepository,
)
from cyberjury.profiles.web.facts.resolver import ResolvedRepository
from cyberjury.review.definitions import (
    CallCandidate,
    DefinitionFragment,
    StructuralCandidate,
    StructuralGap,
    call_candidates_data,
    structural_candidates_data,
    structural_gaps_data,
)
from cyberjury.review.facts import Facts
from cyberjury.review.relationships import (
    AnalysisObservation,
    ArgumentEvidence,
    CallsiteEvidence,
    DefinitionEvidence,
    ParameterEvidence,
    RelationshipEvidenceBundle,
    SourceReference,
    StructuralRelationshipEvidence,
)


@dataclass(frozen=True, kw_only=True)
class Graph:
    """Store analyzed definitions and repository resolved relationships."""

    defs: tuple[AnalyzedDefinition, ...]
    syntax_imports: dict[str, list[AnalyzedImport]]
    syntax_namespaces: dict[str, list[AnalyzedNamespace]]
    imports: dict[str, list[str]]
    references: dict[str, list[str]]
    import_targets: dict[str, list[str]]
    call_candidates: tuple[CallCandidate, ...]
    structural_candidates: tuple[StructuralCandidate, ...]
    structural_gaps: tuple[StructuralGap, ...]
    sources: dict[str, str]
    producer_version: str

    def to_data(self) -> dict[str, dict[str, list[dict[str, object]]]]:
        """Preserve repeated names as lists in the payload consumed by the engine."""
        output: dict[str, dict[str, list[dict[str, object]]]] = {}
        for definition in self.defs:
            entry = {"range": [definition.start, definition.end], "calls": list(definition.calls)}
            output.setdefault(definition.file, {}).setdefault(definition.name, []).append(entry)
        return output


def build_graph(analyzed: AnalyzedRepository, resolved: ResolvedRepository) -> Graph:
    """Combine analyzed definitions with repository resolved relationships."""
    return Graph(
        defs=analyzed.definitions,
        syntax_imports=analyzed.imports,
        syntax_namespaces=analyzed.namespaces,
        imports=resolved.imports,
        references=resolved.references,
        import_targets=resolved.import_targets,
        call_candidates=resolved.call_candidates,
        structural_candidates=resolved.structural_candidates,
        structural_gaps=resolved.structural_gaps,
        sources=analyzed.sources,
        producer_version=analyzed.producer_version,
    )


def facts_from_graph(graph: Graph) -> Facts:
    """Serialize one resolved graph into the shared Facts contract."""
    if not graph.defs and not any(
        (
            any(graph.syntax_imports.values()),
            any(graph.syntax_namespaces.values()),
            any(graph.imports.values()),
            any(graph.references.values()),
            any(graph.import_targets.values()),
            graph.call_candidates,
            graph.structural_candidates,
            graph.structural_gaps,
        )
    ):
        return Facts()
    data = {
        "relationship_evidence": relationship_evidence(graph).to_data(),
        "graph": {
            "callgraph": graph.to_data(),
            "syntax_imports": syntax_imports_data(graph.syntax_imports),
            "imports": {file: list(dict.fromkeys(names)) for file, names in graph.imports.items()},
            "references": {file: list(dict.fromkeys(names)) for file, names in graph.references.items()},
            "import_targets": {file: list(dict.fromkeys(targets)) for file, targets in graph.import_targets.items()},
            "call_candidates": call_candidates_data(graph.call_candidates),
            "structural_candidates": structural_candidates_data(graph.structural_candidates),
            "structural_gaps": structural_gaps_data(graph.structural_gaps),
            "dependencies": [],
            "unresolved_dependencies": [],
        },
        "by_file": render_by_file(graph),
    }
    return Facts(summary=render_summary(graph), data=data)


def relationship_evidence(graph: Graph) -> RelationshipEvidenceBundle:
    """Render syntax and resolver output as clues without establishing relations."""
    missing = {definition.file for definition in graph.defs}.difference(graph.sources)
    if missing:
        raise ValueError(f"missing analyzed source for: {', '.join(sorted(missing))}")
    definitions = _definition_evidences(graph.defs, graph.sources)
    by_fragment = {
        (definition.source.path, definition.name, definition.source.start, definition.source.end): definition
        for definition in definitions
    }
    definitions_by_id = {definition.id: definition for definition in definitions}
    analyzed_by_id = {evidence.id: analyzed for analyzed, evidence in zip(graph.defs, definitions, strict=True)}
    calls: list[CallsiteEvidence] = []
    observations: list[AnalysisObservation] = []
    extra_sources = {
        reference.id: reference
        for path, content in graph.sources.items()
        if content
        for reference in (SourceReference.create(path=path, start=0, end=len(content), content=content),)
    }
    producer_version = graph.producer_version
    for definition in definitions:
        analyzed = analyzed_by_id[definition.id]
        source = graph.sources[analyzed.file]
        source_fragment = DefinitionFragment(analyzed.file, analyzed.name, analyzed.start, analyzed.end)
        for analyzed_call in analyzed.callsites:
            call_source = SourceReference.create(
                path=analyzed.file,
                start=analyzed_call.start,
                end=analyzed_call.end,
                content=source[analyzed_call.start : analyzed_call.end],
            )
            arguments = tuple(
                ArgumentEvidence(
                    position=argument.position,
                    name=argument.name,
                    expression=argument.expression,
                    source=SourceReference.create(
                        path=analyzed.file,
                        start=argument.start,
                        end=argument.end,
                        content=source[argument.start : argument.end],
                    ),
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
            candidates = _candidate_ids(graph, source_fragment, analyzed_call.callee, by_fragment)
            observations.append(
                AnalysisObservation.create(
                    producer="tree-sitter",
                    producer_version=producer_version,
                    kind="syntax_call",
                    subject_ids=(callsite.id,),
                    candidate_target_ids=candidates,
                    provenance_source_ids=(definition.source.id, call_source.id),
                    label=(
                        f"{analyzed_call.receiver}.{analyzed_call.callee}"
                        if analyzed_call.receiver
                        else analyzed_call.callee
                    ),
                )
            )
            binding = next(
                (
                    item
                    for item in graph.syntax_imports.get(analyzed.file, ())
                    if (item.local or item.imported) == analyzed_call.callee
                ),
                None,
            )
            imported_target_files = set(graph.import_targets.get(analyzed.file, ()))
            binding_targets = {
                definitions_by_id[candidate].source.path for candidate in candidates if candidate in definitions_by_id
            }
            if binding is not None and binding_targets.intersection(imported_target_files):
                binding_source = SourceReference.create(
                    path=analyzed.file,
                    start=binding.start,
                    end=binding.end,
                    content=source[binding.start : binding.end],
                )
                extra_sources[binding_source.id] = binding_source
                observations.append(
                    AnalysisObservation.create(
                        producer="tree-sitter",
                        producer_version=producer_version,
                        kind="import_binding",
                        subject_ids=(callsite.id,),
                        candidate_target_ids=candidates,
                        provenance_source_ids=(definition.source.id, call_source.id, binding_source.id),
                        label=f"{binding.local or binding.imported} from {binding.module.strip(chr(34) + chr(39))}",
                    )
                )
            namespace = next(
                (
                    item
                    for item in graph.syntax_namespaces.get(analyzed.file, ())
                    if item.local == analyzed_call.receiver
                ),
                None,
            )
            if namespace is not None:
                namespace_source = SourceReference.create(
                    path=analyzed.file,
                    start=namespace.start,
                    end=namespace.end,
                    content=source[namespace.start : namespace.end],
                )
                extra_sources[namespace_source.id] = namespace_source
                observations.append(
                    AnalysisObservation.create(
                        producer="tree-sitter",
                        producer_version=producer_version,
                        kind="namespace_binding",
                        subject_ids=(callsite.id,),
                        candidate_target_ids=candidates,
                        provenance_source_ids=(definition.source.id, call_source.id, namespace_source.id),
                        label=f"{namespace.local} from {namespace.specifier}",
                    )
                )
    return RelationshipEvidenceBundle(
        sources=tuple(extra_sources.values()),
        definitions=definitions,
        callsites=tuple(calls),
        observations=tuple(observations),
        structural_subjects=_structural_subjects(graph, definitions),
    )


def _structural_subjects(
    graph: Graph,
    definitions: tuple[DefinitionEvidence, ...],
) -> tuple[StructuralRelationshipEvidence, ...]:
    by_fragment = {
        DefinitionFragment(
            definition.source.path,
            definition.name,
            definition.source.start,
            definition.source.end,
        ): definition
        for definition in definitions
    }
    grouped: dict[
        tuple[str, str, str, str],
        tuple[SourceReference, str, list[str]],
    ] = {}
    for candidate in graph.structural_candidates:
        source_definition = by_fragment.get(candidate.source) if candidate.source is not None else None
        source = (
            source_definition.source
            if source_definition is not None
            else _file_source(candidate.source_file, graph.sources)
        )
        target = by_fragment.get(candidate.target)
        if target is None:
            continue
        kind = _web_structural_kind(graph, candidate.source_file, candidate.kind, candidate.reference)
        key = (candidate.source_file, kind, candidate.reference, source_definition.id if source_definition else "")
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = (source, source_definition.id if source_definition else "", [target.id])
        else:
            existing[2].append(target.id)
    return tuple(
        StructuralRelationshipEvidence.create(
            kind=kind,
            source_file=source_file,
            source=source,
            reference=reference,
            source_definition_id=source_definition_id,
            candidate_target_definition_ids=tuple(dict.fromkeys(candidate_ids)),
        )
        for (source_file, kind, reference, source_definition_id), (
            source,
            _,
            candidate_ids,
        ) in sorted(grouped.items())
    )


def _file_source(path: str, sources: dict[str, str]) -> SourceReference:
    content = sources.get(path, "")
    if not content:
        raise ValueError(f"missing nonempty source for structural relationship at {path}")
    return SourceReference.create(path=path, start=0, end=len(content), content=content)


def _web_structural_kind(graph: Graph, source_file: str, kind: str, reference: str) -> str:
    if any(
        reference == item.local or reference.startswith(f"{item.local}.") or item.specifier == reference
        for item in graph.syntax_namespaces.get(source_file, ())
    ):
        return "namespace"
    return kind


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
        source = SourceReference.create(
            path=definition.file,
            start=definition.start,
            end=definition.end,
            content=source_text[definition.start : definition.end],
        )
        owner_id = ""
        if definition.owner is not None:
            owner = by_location.get(
                (definition.file, definition.owner.name, definition.owner.start, definition.owner.end)
            )
            if owner is not None:
                owner_id = build(owner).id
        if definition.is_type:
            kind = "type"
        elif definition.type_owner is not None:
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
                    source=SourceReference.create(
                        path=definition.file,
                        start=parameter.start,
                        end=parameter.end,
                        content=source_text[parameter.start : parameter.end],
                    ),
                    declaration=parameter.declaration,
                    type_name=parameter.type_name,
                )
                for parameter in definition.parameters
            ),
        )
        built[key] = evidence
        return evidence

    return tuple(build(definition) for definition in analyzed)


def _candidate_ids(
    graph: Graph,
    source: DefinitionFragment,
    spelling: str,
    definitions: dict[tuple[str, str, int, int], DefinitionEvidence],
) -> tuple[str, ...]:
    candidates = []
    for candidate in graph.call_candidates:
        if candidate.source != source:
            continue
        if candidate.reference != spelling:
            continue
        target = candidate.target
        definition = definitions.get((target.file, target.name, target.start, target.end))
        if definition is not None:
            candidates.append(definition.id)
    return tuple(dict.fromkeys(candidates))


def render_by_file(graph: Graph) -> dict[str, str]:
    """Render one graph block per file so split units retain the complete file graph."""
    output: dict[str, list[str]] = {}
    for definition in graph.defs:
        line = f"  {definition.name}()"
        if definition.calls:
            line += "  observes calls " + ", ".join(definition.calls)
        output.setdefault(definition.file, []).append(line)
    for file, imports in graph.syntax_imports.items():
        observations = tuple(
            dict.fromkeys(f"{item.local or item.imported} from {_module_name(item.module)}" for item in imports)
        )
        if observations:
            output.setdefault(file, []).insert(0, "  observes imports " + ", ".join(observations))
    for file, names in graph.imports.items():
        output.setdefault(file, []).insert(0, "  imports " + ", ".join(dict.fromkeys(names)))
    for file, names in graph.references.items():
        output.setdefault(file, []).insert(0, "  references " + ", ".join(dict.fromkeys(names)))
    return {file: f"{file}\n" + "\n".join(lines) for file, lines in output.items()}


def syntax_imports_data(values: dict[str, list[AnalyzedImport]]) -> dict[str, list[dict[str, object]]]:
    """Preserve syntax observations even when no exact module target is known."""
    return {
        file: [
            {
                "module": item.module.strip("\"'"),
                "imported": item.imported,
                "local": item.local,
                "reexport": item.reexport,
            }
            for item in imports
        ]
        for file, imports in values.items()
        if imports
    }


def _module_name(value: str) -> str:
    """Remove syntax quotes without interpreting the module reference."""
    return value.strip("\"'")


def render_summary(graph: Graph) -> str:
    """Summarize graph scale without repeating structured graph detail."""
    if not graph.defs:
        return ""
    files = len({definition.file for definition in graph.defs})
    edges = sum(len(definition.calls) for definition in graph.defs)
    return (
        f"Syntax evidence: {len(graph.defs)} definitions across {files} files, {edges} call observations. "
        "Resolver targets are candidate clues for model relationship analysis, never final edges."
    )
