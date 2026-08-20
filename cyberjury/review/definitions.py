"""Validate definition graphs and plan bounded review evidence."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from cyberjury.review.failures import BackendUnavailable

type FactsGraph = dict[str, object]


@dataclass(frozen=True, order=True)
class DefinitionFragment:
    """One complete source definition exposed through the shared facts graph."""

    file: str
    name: str
    start: int
    end: int

    @property
    def identity(self) -> str:
        """Identify the exact source range required by a grounded judgment."""
        return f"{self.file}:{self.name}:{self.start}:{self.end}"


@dataclass(frozen=True, order=True)
class DefinitionDependency:
    """Connect one source file or definition to a complete target definition."""

    source_file: str
    target: DefinitionFragment
    source: DefinitionFragment | None = None
    kind: Literal["call", "import", "reference"] = "call"
    resolution: Literal["exact", "ambiguous"] = "exact"
    reference: str = ""

    @property
    def identity(self) -> str:
        """Identify one directed relationship with its resolution state."""
        source = self.source.identity if self.source is not None else self.source_file
        return f"{source}:{self.kind}:{self.reference or self.target.name}:{self.resolution}:{self.target.identity}"


@dataclass(frozen=True, order=True)
class UnresolvedDependency:
    """Record one repository dependency that facts could not resolve."""

    source_file: str
    reference: str
    kind: Literal["call", "import", "reference"] = "import"
    source: DefinitionFragment | None = None

    @property
    def identity(self) -> str:
        """Identify an unresolved edge without inventing a target."""
        owner = self.source.identity if self.source is not None else self.source_file
        return f"{owner}:{self.kind}:{self.reference}"


@dataclass(frozen=True, kw_only=True)
class DefinitionUnitPlan:
    """One review surface with a preserved dependency subgraph and source evidence."""

    seeds: tuple[DefinitionFragment, ...] = ()
    seed_files: tuple[str, ...] = ()
    dependencies: tuple[DefinitionDependency, ...] = ()
    evidence: tuple[DefinitionFragment, ...] = ()
    unresolved: tuple[UnresolvedDependency, ...] = ()

    @property
    def fragments(self) -> tuple[DefinitionFragment, ...]:
        """Return the bounded source evidence selected beside the complete subgraph."""
        return self.evidence


def dependencies_data(dependencies: tuple[DefinitionDependency, ...]) -> list[dict[str, object]]:
    """Serialize resolved definition edges into the shared facts payload."""

    def record(fragment: DefinitionFragment) -> dict[str, object]:
        return {
            "file": fragment.file,
            "name": fragment.name,
            "range": [fragment.start, fragment.end],
        }

    return [
        {
            "source_file": dependency.source_file,
            "source": record(dependency.source) if dependency.source is not None else None,
            "target": record(dependency.target),
            "kind": dependency.kind,
            "resolution": dependency.resolution,
            "reference": dependency.reference,
        }
        for dependency in dependencies
    ]


def unresolved_dependencies_data(values: tuple[UnresolvedDependency, ...]) -> list[dict[str, object]]:
    """Serialize unresolved internal edges without inventing a target definition."""
    return [
        {
            "source_file": value.source_file,
            "source": (
                {
                    "file": value.source.file,
                    "name": value.source.name,
                    "range": [value.source.start, value.source.end],
                }
                if value.source is not None
                else None
            ),
            "kind": value.kind,
            "reference": value.reference,
        }
        for value in values
    ]


def definition_fragments(graph: FactsGraph) -> dict[str, tuple[DefinitionFragment, ...]]:
    """Index every definition range or reject an incomplete nonempty graph."""
    callgraph = graph.get("callgraph")
    if callgraph is None:
        return {}
    if not isinstance(callgraph, dict):
        raise BackendUnavailable("the facts graph callgraph must be an object")
    index: dict[str, list[DefinitionFragment]] = {}
    for raw_file, raw_definitions in callgraph.items():
        if not isinstance(raw_file, str) or not raw_file:
            raise BackendUnavailable("the facts graph contains a definition with an invalid file")
        for fragment in _validated_definition_entries(raw_file, raw_definitions):
            index.setdefault(fragment.name, []).append(fragment)
    return {name: tuple(dict.fromkeys(fragments)) for name, fragments in index.items()}


def _validated_definition_entries(file: str, raw_definitions: object) -> tuple[DefinitionFragment, ...]:
    if not isinstance(raw_definitions, dict):
        raise BackendUnavailable(f"the facts graph definitions for {file} must be an object")
    fragments: list[DefinitionFragment] = []
    for raw_name, raw_entries in raw_definitions.items():
        if not isinstance(raw_name, str) or not raw_name:
            raise BackendUnavailable(f"the facts graph contains a definition with an invalid name in {file}")
        location = f"{file}:{raw_name}"
        if not isinstance(raw_entries, list | tuple) or not raw_entries:
            raise BackendUnavailable(f"the facts graph definition entries for {location} must be a nonempty list")
        fragments.extend(
            _validated_definition_fragment(file, raw_name, raw_entry, f"{location} entry {position + 1}")
            for position, raw_entry in enumerate(raw_entries)
        )
    return tuple(fragments)


def _validated_definition_fragment(file: str, name: str, raw_entry: object, location: str) -> DefinitionFragment:
    if not isinstance(raw_entry, dict):
        raise BackendUnavailable(f"the facts graph definition {location} must be an object")
    span = raw_entry.get("range")
    if not isinstance(span, list | tuple) or len(span) != 2:
        raise BackendUnavailable(f"the facts graph definition {location} has an invalid range")
    start, end = span
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise BackendUnavailable(f"the facts graph definition {location} has an invalid range")
    return DefinitionFragment(file, name, start, end)


def _dependency_fragment(raw: object) -> DefinitionFragment | None:
    if not isinstance(raw, dict):
        return None
    file = raw.get("file")
    name = raw.get("name")
    span = raw.get("range")
    if not isinstance(file, str) or not file or not isinstance(name, str) or not name:
        return None
    if not isinstance(span, list | tuple) or len(span) != 2:
        return None
    start, end = span
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        return None
    return DefinitionFragment(file, name, start, end)


def definition_dependencies(graph: FactsGraph) -> tuple[DefinitionDependency, ...]:
    """Read exact dependency edges resolved by the selected facts backend."""
    definition_fragments(graph)
    raw_dependencies = graph.get("dependencies")
    if not isinstance(raw_dependencies, list | tuple):
        callgraph = graph.get("callgraph")
        if isinstance(callgraph, dict) and callgraph:
            raise BackendUnavailable("the facts graph has definitions but no resolved dependency edges")
        return ()
    dependencies: list[DefinitionDependency] = []
    for raw in raw_dependencies:
        if not isinstance(raw, dict):
            raise BackendUnavailable("the facts graph contains a malformed dependency edge")
        source_file = raw.get("source_file")
        raw_source = raw.get("source")
        source = _dependency_fragment(raw_source)
        target = _dependency_fragment(raw.get("target"))
        if raw_source is not None and source is None:
            raise BackendUnavailable("the facts graph contains a malformed dependency endpoint")
        if not isinstance(source_file, str) or not source_file or target is None:
            raise BackendUnavailable("the facts graph contains a malformed dependency endpoint")
        if source == target:
            continue
        kind = raw.get("kind", "call")
        resolution = raw.get("resolution", "exact")
        reference = raw.get("reference", "")
        if kind not in {"call", "import", "reference"} or resolution not in {"exact", "ambiguous"}:
            raise BackendUnavailable("the facts graph contains an unsupported dependency edge")
        if not isinstance(reference, str):
            raise BackendUnavailable("the facts graph contains a malformed dependency reference")
        dependencies.append(DefinitionDependency(source_file, target, source, kind, resolution, reference))
    return tuple(dict.fromkeys(dependencies))


def unresolved_dependencies(graph: FactsGraph) -> tuple[UnresolvedDependency, ...]:
    """Read unresolved repository edges without treating them as external code."""
    raw_values = graph.get("unresolved_dependencies", ())
    if not isinstance(raw_values, list | tuple):
        raise BackendUnavailable("the facts graph contains malformed unresolved dependencies")
    values: list[UnresolvedDependency] = []
    for raw in raw_values:
        if not isinstance(raw, dict):
            raise BackendUnavailable("the facts graph contains a malformed unresolved dependency")
        source_file = raw.get("source_file")
        reference = raw.get("reference")
        kind = raw.get("kind", "import")
        raw_source = raw.get("source")
        source = _dependency_fragment(raw_source)
        if raw_source is not None and source is None:
            raise BackendUnavailable("the facts graph contains a malformed unresolved dependency endpoint")
        if not isinstance(source_file, str) or not source_file or not isinstance(reference, str) or not reference:
            raise BackendUnavailable("the facts graph contains a malformed unresolved dependency")
        if kind not in {"call", "import", "reference"}:
            raise BackendUnavailable("the facts graph contains an unsupported unresolved dependency")
        values.append(UnresolvedDependency(source_file, reference, kind, source))
    return tuple(dict.fromkeys(values))


def definition_references(
    seeds: tuple[DefinitionFragment, ...],
    source_for_file: Callable[[str], str],
) -> dict[DefinitionFragment, frozenset[str]]:
    """Extract generic symbol references from each exact seed definition."""
    sources: dict[str, str] = {}
    references: dict[DefinitionFragment, frozenset[str]] = {}
    for seed in seeds:
        source = sources.setdefault(seed.file, source_for_file(seed.file))
        references[seed] = frozenset(re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", source[seed.start : seed.end]))
    return references


def dependency_paths(
    seeds: tuple[DefinitionFragment, ...],
    graph: FactsGraph,
    *,
    depth: int,
    seed_files: tuple[str, ...] = (),
) -> tuple[tuple[DefinitionDependency, ...], ...]:
    """Trace indivisible definition paths from exact seed definitions."""
    edges = definition_dependencies(graph)
    by_source: dict[DefinitionFragment, list[DefinitionDependency]] = {}
    file_edges: dict[str, list[DefinitionDependency]] = {}
    for edge in edges:
        if edge.source is None:
            file_edges.setdefault(edge.source_file, []).append(edge)
        else:
            by_source.setdefault(edge.source, []).append(edge)

    starts = [(edge,) for file in seed_files for edge in file_edges.get(file, ())]
    starts.extend((edge,) for seed in seeds for edge in by_source.get(seed, ()))
    paths: list[tuple[DefinitionDependency, ...]] = []

    def walk(path: tuple[DefinitionDependency, ...], remaining: int) -> None:
        target = path[-1].target
        if remaining == 0:
            paths.append(path)
            return
        visited = {*seeds, *(item.target for item in path)}
        next_edges = [edge for edge in by_source.get(target, ()) if edge.target not in visited]
        if not next_edges:
            paths.append(path)
            return
        for edge in next_edges:
            walk((*path, edge), remaining - 1)

    for start in starts:
        walk(start, max(0, depth - 1))
    return tuple(dict.fromkeys(paths))


def dependency_closure(
    seeds: tuple[DefinitionFragment, ...],
    graph: FactsGraph,
    *,
    depth: int,
    seed_files: tuple[str, ...] = (),
) -> tuple[DefinitionDependency, ...]:
    """Flatten every exact dependency path reachable from the supplied definitions."""
    return tuple(
        dict.fromkeys(
            edge for path in dependency_paths(seeds, graph, depth=depth, seed_files=seed_files) for edge in path
        )
    )


def plan_definition_units(
    seeds: tuple[DefinitionFragment, ...],
    graph: FactsGraph,
    *,
    depth: int,
    max_chars: int,
    seed_files: tuple[str, ...] = (),
    include_seed_chars: bool = True,
    references_by_seed: dict[DefinitionFragment, frozenset[str]] | None = None,
    pack_surfaces: bool = True,
) -> tuple[DefinitionUnitPlan, ...]:
    """Build one bounded evidence plan per review surface from a complete subgraph."""
    if max_chars < 1:
        raise ValueError("definition unit size must be positive")
    edges = definition_dependencies(graph)
    unresolved = unresolved_dependencies(graph)
    by_source: dict[DefinitionFragment, list[DefinitionDependency]] = {}
    by_file: dict[str, list[DefinitionDependency]] = {}
    for edge in edges:
        if edge.source is None:
            by_file.setdefault(edge.source_file, []).append(edge)
        else:
            by_source.setdefault(edge.source, []).append(edge)

    anchors = dict.fromkeys((*(seed.file for seed in seeds), *seed_files))
    grouped = tuple(
        plan
        for anchor in anchors
        if (
            plan := _plan_definition_anchor(
                anchor,
                seeds=seeds,
                seed_files=seed_files,
                unresolved=unresolved,
                by_source=by_source,
                by_file=by_file,
                depth=depth,
                max_chars=max_chars,
                include_seed_chars=include_seed_chars,
                references_by_seed=references_by_seed,
            )
        )
        is not None
    )

    if not pack_surfaces:
        return grouped

    return _pack_definition_plans(grouped, max_chars=max_chars, include_seed_chars=include_seed_chars)


def _plan_definition_anchor(
    anchor: str,
    *,
    seeds: tuple[DefinitionFragment, ...],
    seed_files: tuple[str, ...],
    unresolved: tuple[UnresolvedDependency, ...],
    by_source: dict[DefinitionFragment, list[DefinitionDependency]],
    by_file: dict[str, list[DefinitionDependency]],
    depth: int,
    max_chars: int,
    include_seed_chars: bool,
    references_by_seed: dict[DefinitionFragment, frozenset[str]] | None,
) -> DefinitionUnitPlan | None:
    anchor_seeds = tuple(seed for seed in seeds if seed.file == anchor)
    starts = [edge for seed in anchor_seeds for edge in by_source.get(seed, ())]
    starts.extend(
        edge for edge in by_file.get(anchor, ()) if _edge_matches_anchor(edge, anchor_seeds, references_by_seed)
    )
    reached, hop_by_edge = _reachable_dependency_subgraph(tuple(dict.fromkeys(starts)), by_source, depth)
    anchor_unresolved = tuple(
        item
        for item in unresolved
        if item.source in anchor_seeds or (item.source is None and item.source_file == anchor)
    )
    if not anchor_seeds and not reached and not anchor_unresolved:
        return None
    evidence = _bounded_definition_evidence(
        anchor_seeds,
        reached,
        hop_by_edge,
        max_chars=max_chars,
        include_seed_chars=include_seed_chars,
    )
    return DefinitionUnitPlan(
        seeds=anchor_seeds,
        seed_files=(anchor,) if anchor in seed_files else (),
        dependencies=reached,
        evidence=evidence,
        unresolved=anchor_unresolved,
    )


def _edge_matches_anchor(
    edge: DefinitionDependency,
    anchor_seeds: tuple[DefinitionFragment, ...],
    references_by_seed: dict[DefinitionFragment, frozenset[str]] | None,
) -> bool:
    return (
        not anchor_seeds
        or references_by_seed is None
        or any(edge.target.name in references_by_seed.get(seed, ()) for seed in anchor_seeds)
    )


def _bounded_definition_evidence(
    anchor_seeds: tuple[DefinitionFragment, ...],
    reached: tuple[DefinitionDependency, ...],
    hop_by_edge: dict[DefinitionDependency, int],
    *,
    max_chars: int,
    include_seed_chars: bool,
) -> tuple[DefinitionFragment, ...]:
    evidence = list(anchor_seeds)
    ordered = sorted(reached, key=lambda edge: (hop_by_edge[edge], edge.resolution == "ambiguous"))
    for target in dict.fromkeys(edge.target for edge in ordered):
        candidate = tuple(dict.fromkeys((*evidence, target)))
        budget = candidate if include_seed_chars else tuple(item for item in candidate if item not in anchor_seeds)
        if definition_union_size(budget) <= max_chars:
            evidence.append(target)
    return tuple(dict.fromkeys(evidence))


def _pack_definition_plans(
    grouped: tuple[DefinitionUnitPlan, ...],
    *,
    max_chars: int,
    include_seed_chars: bool,
) -> tuple[DefinitionUnitPlan, ...]:

    packed: list[DefinitionUnitPlan] = []
    current: DefinitionUnitPlan | None = None
    for plan in grouped:
        if current is None:
            current = plan
            continue
        candidate = merge_definition_unit_plans(current, plan)
        budget_fragments = (
            tuple(dict.fromkeys((*candidate.seeds, *candidate.fragments)))
            if include_seed_chars
            else tuple(fragment for fragment in candidate.fragments if fragment not in candidate.seeds)
        )
        size = definition_union_size(budget_fragments)
        if size > max_chars:
            packed.append(current)
            current = plan
        else:
            current = candidate
    if current is not None:
        packed.append(current)
    return tuple(packed)


def merge_definition_unit_plans(
    left: DefinitionUnitPlan,
    right: DefinitionUnitPlan,
) -> DefinitionUnitPlan:
    """Merge independent review surfaces without losing graph or receipt identity."""
    return DefinitionUnitPlan(
        seeds=tuple(dict.fromkeys((*left.seeds, *right.seeds))),
        seed_files=tuple(dict.fromkeys((*left.seed_files, *right.seed_files))),
        dependencies=tuple(dict.fromkeys((*left.dependencies, *right.dependencies))),
        evidence=tuple(dict.fromkeys((*left.evidence, *right.evidence))),
        unresolved=tuple(dict.fromkeys((*left.unresolved, *right.unresolved))),
    )


def _reachable_dependency_subgraph(
    starts: tuple[DefinitionDependency, ...],
    by_source: dict[DefinitionFragment, list[DefinitionDependency]],
    depth: int,
) -> tuple[tuple[DefinitionDependency, ...], dict[DefinitionDependency, int]]:
    """Traverse unique edges without expanding every combinatorial path."""
    reached: list[DefinitionDependency] = []
    hop_by_edge: dict[DefinitionDependency, int] = {}
    frontier = list(starts)
    for hop in range(1, depth + 1):
        next_frontier: list[DefinitionDependency] = []
        for edge in frontier:
            previous_hop = hop_by_edge.get(edge)
            if previous_hop is not None and previous_hop <= hop:
                continue
            hop_by_edge[edge] = hop
            reached.append(edge)
            if edge.kind == "call":
                next_frontier.extend(by_source.get(edge.target, ()))
        frontier = next_frontier
        if not frontier:
            break
    return tuple(reached), hop_by_edge


def definition_union_size(fragments: tuple[DefinitionFragment, ...]) -> int:
    """Count overlapping source definitions once when enforcing a unit budget."""
    total = 0
    by_file: dict[str, list[tuple[int, int]]] = {}
    for fragment in fragments:
        by_file.setdefault(fragment.file, []).append((fragment.start, fragment.end))
    for ranges in by_file.values():
        current_start = current_end = -1
        for start, end in sorted(ranges):
            if start > current_end:
                if current_end >= 0:
                    total += current_end - current_start
                current_start, current_end = start, end
            else:
                current_end = max(current_end, end)
        if current_end >= 0:
            total += current_end - current_start
    return total
