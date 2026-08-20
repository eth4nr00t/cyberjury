"""Build and render the web profile's resolved syntax graph."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.profiles.web.facts.analyzer import AnalyzedDefinition, AnalyzedRepository
from cyberjury.profiles.web.facts.resolver import ResolvedRepository
from cyberjury.review.definitions import (
    DefinitionDependency,
    UnresolvedDependency,
    dependencies_data,
    unresolved_dependencies_data,
)
from cyberjury.review.facts import Facts


@dataclass(frozen=True, kw_only=True)
class Graph:
    """Store analyzed definitions and repository resolved relationships."""

    defs: tuple[AnalyzedDefinition, ...]
    imports: dict[str, list[str]]
    references: dict[str, list[str]]
    import_targets: dict[str, list[str]]
    dependencies: tuple[DefinitionDependency, ...]
    unresolved: tuple[UnresolvedDependency, ...]

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
        imports=resolved.imports,
        references=resolved.references,
        import_targets=resolved.import_targets,
        dependencies=resolved.dependencies,
        unresolved=resolved.unresolved,
    )


def facts_from_graph(graph: Graph) -> Facts:
    """Serialize one resolved graph into the shared Facts contract."""
    if not graph.defs:
        return Facts()
    data = {
        "graph": {
            "callgraph": graph.to_data(),
            "imports": {file: list(dict.fromkeys(names)) for file, names in graph.imports.items()},
            "references": {file: list(dict.fromkeys(names)) for file, names in graph.references.items()},
            "import_targets": {file: list(dict.fromkeys(targets)) for file, targets in graph.import_targets.items()},
            "dependencies": dependencies_data(graph.dependencies),
            "unresolved_dependencies": unresolved_dependencies_data(graph.unresolved),
        },
        "by_file": render_by_file(graph),
    }
    return Facts(summary=render_summary(graph), data=data)


def render_by_file(graph: Graph) -> dict[str, str]:
    """Render one graph block per file so split units retain the complete file graph."""
    output: dict[str, list[str]] = {}
    for definition in graph.defs:
        line = f"  {definition.name}()"
        if definition.calls:
            line += "  calls " + ", ".join(definition.calls)
        output.setdefault(definition.file, []).append(line)
    for file, names in graph.imports.items():
        output.setdefault(file, []).insert(0, "  imports " + ", ".join(dict.fromkeys(names)))
    for file, names in graph.references.items():
        output.setdefault(file, []).insert(0, "  references " + ", ".join(dict.fromkeys(names)))
    return {file: f"{file}\n" + "\n".join(lines) for file, lines in output.items()}


def render_summary(graph: Graph) -> str:
    """Summarize graph scale without repeating structured graph detail."""
    if not graph.defs:
        return ""
    files = len({definition.file for definition in graph.defs})
    edges = sum(len(definition.calls) for definition in graph.defs)
    return (
        f"Call graph: {len(graph.defs)} definitions across {files} files, {edges} call edges, "
        "extracted from syntax. Ambiguous syntax edges retain every definition in the resolved "
        "import scope."
    )
