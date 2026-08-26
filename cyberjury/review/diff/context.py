"""Build prompt context for a diff from repository facts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from cyberjury.detection import Detection, load_detection
from cyberjury.profiles.base import ReviewProfile
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    RelationshipEvidence,
    definition_evidence,
    definition_plan_source_files,
    definition_relationships,
    render_relationships,
    with_scoped_fact_limitations,
)
from cyberjury.review.definitions import (
    DefinitionFragment,
    DefinitionUnitPlan,
    FactsGraph,
    dependency_closure,
)
from cyberjury.review.diff.model import (
    ChangedLineRanges,
    DiffUnit,
    ReviewNamesByPath,
    changed_definition_fragments,
    changed_line_ranges,
    changed_paths,
    hunk_call_names_by_path,
    prepare_diff_units,
)
from cyberjury.review.diff.prompts import (
    file_context,
    related_file_context,
    render_context,
    required_definition_chars,
)
from cyberjury.review.facts import FactLimitation, FactsByFile, extract_facts
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

type GraphMap = dict[str, object]

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff


@dataclass(frozen=True, kw_only=True)
class DiffContext(GroundingContext):
    """Context snippets collected around changed diff lines."""

    source: Literal["diff"] = "diff"


@dataclass(frozen=True, kw_only=True)
class _ContextPlan:
    callgraph: dict[str, object]
    seed_text: str
    required_fragments: dict[str, tuple[DefinitionFragment, ...]]
    related_files: tuple[str, ...]
    relationships: tuple[RelationshipEvidence, ...]
    required: tuple[str, ...]
    focus_names: set[str]


@dataclass(frozen=True, kw_only=True)
class DiffContextCollector:
    """Interface for collecting source context for diff review."""

    root: Path
    detection: Detection
    by_file: FactsByFile
    graph: FactsGraph
    facts_limitations: tuple[FactLimitation, ...] = ()
    review_paths: tuple[str, ...] = ()
    review_names_by_path: ReviewNamesByPath = field(default_factory=dict)

    def collect(self, diff: str, definition_plan: DefinitionUnitPlan | None = None) -> DiffContext:
        """Collect source context for changed files in a diff."""
        paths = changed_paths(diff, self.detection)
        if not paths:
            return DiffContext(text="", files=())
        ranges = changed_line_ranges(diff, self.detection)
        changed, related, coverage = _context_blocks(
            self.root,
            paths,
            self.by_file,
            self.graph,
            ranges,
            review_paths=self.review_paths,
            review_names_by_path=self.review_names_by_path,
            definition_plan=definition_plan,
        )
        related_first = len(paths) >= _SETTINGS.related_context_first_min_changed_files
        entries = [*related, *changed] if related_first else [*changed, *related]
        text = render_context(
            changed,
            related,
            related_first=related_first,
            preserve_required=definition_plan is not None,
        )
        relationships = definition_relationships(definition_plan) if definition_plan is not None else ()
        relationship_text = render_relationships(relationships)
        if relationship_text:
            text = f"{relationship_text}\n\n{text}"
        files = tuple(dict.fromkeys(rel for rel, _block in entries if rel in paths))
        evidence = (
            definition_evidence(self.root, definition_plan, include_seeds=True) if definition_plan is not None else ()
        )
        context = DiffContext(text=text, files=files, coverage=coverage, evidence=evidence)
        scope_files = tuple(
            dict.fromkeys((*(rel for rel, _block in entries), *definition_plan_source_files(definition_plan)))
        )
        return with_scoped_fact_limitations(context, self.facts_limitations, source_files=scope_files)

    def prepare(self, diff: str) -> list[DiffUnit]:
        """Prepare diff units with inseparable target, path, and grounding receipts."""
        return prepare_diff_units(
            diff,
            root=self.root,
            detection=self.detection,
            graph=self.graph,
            collect=self.collect,
            settings=_SETTINGS,
        )


def collect_diff_context(repository: str | Path, diff: str, profile: ReviewProfile) -> DiffContext:
    """Collect facts and current source for changed files in a repository diff."""
    return build_diff_context_collector(repository, profile, review_diff=diff).collect(diff)


def build_diff_context_collector(
    repository: str | Path,
    profile: ReviewProfile,
    *,
    facts_root: str | Path | None = None,
    review_diff: str = "",
) -> DiffContextCollector:
    """Extract repository facts once, then render context for one or more diff batches."""
    root = Path(repository).resolve()
    facts_base = Path(facts_root).resolve() if facts_root is not None else root
    prefix = _relative_prefix(root, facts_base)
    detection = load_detection(profile.paths.detection_file)
    review_paths = changed_paths(review_diff, detection)
    review_names_by_path = hunk_call_names_by_path(review_diff, detection)
    backend = profile.facts_backend
    if backend is None:
        return DiffContextCollector(
            root=root,
            detection=detection,
            by_file={},
            graph={},
            review_paths=review_paths,
            review_names_by_path=review_names_by_path,
        )
    facts = extract_facts(backend, facts_base, purpose="diff context")
    data = facts.data if isinstance(facts.data, dict) else {}
    by_file = cast("FactsByFile", data.get("by_file")) if isinstance(data.get("by_file"), dict) else {}
    graph = cast("FactsGraph", data.get("graph")) if isinstance(data.get("graph"), dict) else {}
    return DiffContextCollector(
        root=root,
        detection=detection,
        by_file=_prefix_facts_by_file(by_file, prefix),
        graph=_prefix_graph(graph, prefix),
        facts_limitations=_prefix_fact_limitations(facts.limitations, prefix),
        review_paths=review_paths,
        review_names_by_path=review_names_by_path,
    )


def _relative_prefix(root: Path, facts_base: Path) -> str:
    if facts_base == root:
        return ""
    if not facts_base.is_relative_to(root):
        raise BackendUnavailable(f"facts root {facts_base} is outside repository root {root}")
    return facts_base.relative_to(root).as_posix()


def _prefix_path(path: str, prefix: str) -> str:
    return f"{prefix}/{path}" if prefix else path


def _prefix_facts_by_file(values: FactsByFile, prefix: str) -> FactsByFile:
    if not prefix:
        return values
    return {_prefix_path(path, prefix): value for path, value in values.items()}


def _prefix_fact_limitations(
    values: tuple[FactLimitation, ...],
    prefix: str,
) -> tuple[FactLimitation, ...]:
    if not prefix:
        return values
    return tuple(
        FactLimitation(
            source=_prefix_path(item.source, prefix),
            analyzer=item.analyzer,
            reason=item.reason,
            line=item.line,
            column=item.column,
        )
        for item in values
    )


def _prefix_map(values: GraphMap, prefix: str) -> GraphMap:
    if not prefix:
        return values
    return {_prefix_path(str(path), prefix): value for path, value in values.items()}


def _prefix_import_targets(values: GraphMap, prefix: str) -> dict[str, list[str]]:
    if not prefix:
        return cast("dict[str, list[str]]", values)
    return {
        _prefix_path(str(path), prefix): [_prefix_path(str(target), prefix) for target in targets or ()]
        for path, targets in values.items()
    }


def _prefix_dependencies(values: list | tuple, prefix: str) -> list[object]:
    if not prefix:
        return list(values)
    prefixed: list[object] = []
    for raw in values:
        if not isinstance(raw, dict):
            prefixed.append(raw)
            continue
        dependency = dict(raw)
        source_file = dependency.get("source_file")
        if isinstance(source_file, str):
            dependency["source_file"] = _prefix_path(source_file, prefix)
        for key in ("source", "target"):
            fragment = dependency.get(key)
            if isinstance(fragment, dict) and isinstance(fragment.get("file"), str):
                dependency[key] = {**fragment, "file": _prefix_path(fragment["file"], prefix)}
        prefixed.append(dependency)
    return prefixed


def _prefix_graph(graph: FactsGraph, prefix: str) -> FactsGraph:
    if not prefix:
        return graph
    out: FactsGraph = dict(graph)
    callgraph = graph.get("callgraph")
    if isinstance(callgraph, dict):
        out["callgraph"] = _prefix_map(callgraph, prefix)
    imports = graph.get("imports")
    if isinstance(imports, dict):
        out["imports"] = _prefix_map(imports, prefix)
    references = graph.get("references")
    if isinstance(references, dict):
        out["references"] = _prefix_map(references, prefix)
    import_targets = graph.get("import_targets")
    if isinstance(import_targets, dict):
        out["import_targets"] = _prefix_import_targets(import_targets, prefix)
    dependencies = graph.get("dependencies")
    if isinstance(dependencies, list | tuple):
        out["dependencies"] = _prefix_dependencies(dependencies, prefix)
    unresolved = graph.get("unresolved_dependencies")
    if isinstance(unresolved, list | tuple):
        out["unresolved_dependencies"] = _prefix_dependencies(unresolved, prefix)
    return out


def _context_blocks(
    root: Path,
    paths: tuple[str, ...],
    by_file: FactsByFile,
    graph: FactsGraph,
    ranges: ChangedLineRanges,
    *,
    review_paths: tuple[str, ...] = (),
    review_names_by_path: ReviewNamesByPath | None = None,
    definition_plan: DefinitionUnitPlan | None = None,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], GroundingCoverage]:
    plan = _plan_context(
        root,
        paths,
        graph,
        ranges,
        review_paths=review_paths,
        review_names_by_path=review_names_by_path,
        definition_plan=definition_plan,
    )
    changed_blocks = (
        [] if definition_plan is not None else _changed_context_blocks(root, paths, by_file, ranges, plan.callgraph)
    )
    related_blocks, included = _related_context_blocks(
        root,
        by_file,
        plan,
        preserve_required=definition_plan is not None,
    )
    coverage = _context_coverage(
        plan.required,
        (*included, *(relationship.identity for relationship in plan.relationships)),
        definition_plan,
    )
    return changed_blocks, related_blocks, coverage


def _plan_context(
    root: Path,
    paths: tuple[str, ...],
    graph: FactsGraph,
    ranges: ChangedLineRanges,
    *,
    review_paths: tuple[str, ...],
    review_names_by_path: ReviewNamesByPath | None,
    definition_plan: DefinitionUnitPlan | None,
) -> _ContextPlan:
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    seeds = _changed_seeds(root, paths, ranges)
    seed_text = "\n".join(seeds.values())
    if definition_plan is None:
        changed_definitions = changed_definition_fragments(root, paths, ranges, graph)
        dependencies = dependency_closure(changed_definitions, graph, depth=2, seed_files=paths)
        fragments = tuple(dependency.target for dependency in dependencies)
    else:
        seed_identities = {fragment.identity for fragment in definition_plan.seeds}
        fragments = tuple(
            fragment for fragment in definition_plan.fragments if fragment.identity not in seed_identities
        )
    required_fragments = _fragments_by_file(fragments)
    related_files = (
        tuple(required_fragments)
        if definition_plan is not None
        else _related_files(
            paths,
            graph,
            seed_text=seed_text,
            preferred_paths=review_paths,
            preferred_names=review_names_by_path or {},
            required_target_files=tuple(required_fragments),
        )
    )
    relationships = definition_relationships(definition_plan) if definition_plan is not None else ()
    required = (
        *(fragment.identity for fragments in required_fragments.values() for fragment in fragments),
        *(relationship.identity for relationship in relationships),
    )
    return _ContextPlan(
        callgraph=callgraph,
        seed_text=seed_text,
        required_fragments=required_fragments,
        related_files=related_files,
        relationships=relationships,
        required=required,
        focus_names=_focus_names(paths, callgraph),
    )


def _fragments_by_file(
    fragments: tuple[DefinitionFragment, ...],
) -> dict[str, tuple[DefinitionFragment, ...]]:
    grouped: dict[str, tuple[DefinitionFragment, ...]] = {}
    for fragment in fragments:
        grouped[fragment.file] = tuple(dict.fromkeys((*grouped.get(fragment.file, ()), fragment)))
    return grouped


def _changed_context_blocks(
    root: Path,
    paths: tuple[str, ...],
    by_file: FactsByFile,
    ranges: ChangedLineRanges,
    callgraph: dict[str, object],
) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for rel in paths:
        block = file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            ranges.get(rel, ()),
            _file_defs(callgraph.get(rel)),
        )
        if block:
            blocks.append((rel, block))
    return blocks


def _related_context_blocks(
    root: Path,
    by_file: FactsByFile,
    plan: _ContextPlan,
    *,
    preserve_required: bool,
) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    related_blocks: list[tuple[str, str]] = []
    included: list[str] = []
    related_chars = 0
    remaining_required = sum(len(fragments) for fragments in plan.required_fragments.values())
    related_limit = (
        _SETTINGS.target_repository_context_chars_per_unit
        if remaining_required
        else int(_SETTINGS.target_repository_context_chars_per_unit * _SETTINGS.max_related_context_fraction)
    )
    for rel in plan.related_files:
        required_for_file = plan.required_fragments.get(rel, ())
        remaining = related_limit - related_chars - (2 if related_blocks else 0)
        if remaining <= 0 and not required_for_file:
            break
        remaining = max(1, remaining)
        if required_for_file:
            required_chars = required_definition_chars(
                root,
                rel,
                required_for_file,
            )
            block_limit = min(
                remaining,
                max(required_chars, remaining * len(required_for_file) // remaining_required),
            )
            remaining_required -= len(required_for_file)
        else:
            block_limit = min(_SETTINGS.target_definition_context_chars_per_file, remaining)
        block, block_included = related_file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            _file_defs(plan.callgraph.get(rel)),
            plan.focus_names,
            plan.seed_text,
            required_for_file,
            max_chars=block_limit,
            allow_required_overflow=preserve_required,
        )
        if not block:
            continue
        related_blocks.append((rel, block))
        related_chars += len(block) + (2 if len(related_blocks) > 1 else 0)
        included.extend(block_included)
    return related_blocks, tuple(included)


def _context_coverage(
    required: tuple[str, ...],
    included: tuple[str, ...],
    definition_plan: DefinitionUnitPlan | None,
) -> GroundingCoverage:
    included_set = set(included)
    return GroundingCoverage(
        required=required,
        included=included,
        omitted=(*(identity for identity in required if identity not in included_set),),
        unresolved=tuple(item.identity for item in definition_plan.unresolved) if definition_plan is not None else (),
    )


def _focus_names(paths: tuple[str, ...], callgraph: dict) -> set[str]:
    return {str(name) for rel in paths for name in _file_defs(callgraph.get(rel))}


def _changed_seeds(root: Path, paths: tuple[str, ...], ranges: ChangedLineRanges) -> dict[str, str]:
    seeds: dict[str, str] = {}
    for rel in paths:
        path = (root / rel).resolve()
        try:
            path.relative_to(root)
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        lines = source.splitlines()
        parts: list[str] = []
        for start, end in ranges.get(rel, ()):
            if start <= len(lines):
                parts.extend(lines[start - 1 : min(end, len(lines))])
        seeds[rel] = "\n".join(parts)
    return seeds


def _related_files(
    paths: tuple[str, ...],
    graph: FactsGraph,
    *,
    seed_text: str = "",
    preferred_paths: tuple[str, ...] = (),
    preferred_names: ReviewNamesByPath | None = None,
    required_target_files: tuple[str, ...] = (),
) -> tuple[str, ...]:
    callgraph = _graph_map(graph, "callgraph")
    imports = _graph_map(graph, "imports")
    import_targets = _graph_map(graph, "import_targets")
    referenced_names = _referenced_graph_names(paths, callgraph, imports)
    required_target_scores = dict.fromkeys(required_target_files, 1)
    direct_target_scores = _direct_target_scores(paths, import_targets, required_target_scores)
    out = dict.fromkeys(direct_target_scores)
    for rel in _forward_import_files(paths, import_targets):
        out.setdefault(rel, None)
    for rel in _files_defining_names(paths, callgraph, referenced_names):
        out.setdefault(rel, None)
    for rel in _reverse_call_files(paths, callgraph):
        out.setdefault(rel, None)
    for rel in _reverse_import_files(paths, callgraph, imports, import_targets):
        out.setdefault(rel, None)
    preferred = set(preferred_paths).difference(paths)
    preferred_names_by_path = preferred_names or {}
    return tuple(
        sorted(
            out,
            key=lambda rel: (
                rel not in required_target_scores,
                rel not in preferred,
                -_changed_peer_name_score(rel, callgraph, preferred_names_by_path, seed_text),
                rel not in direct_target_scores,
                -required_target_scores.get(rel, 0),
                -_related_name_hits(rel, callgraph, imports, seed_text),
                rel,
            ),
        )
    )


def _graph_map(graph: FactsGraph, key: str) -> GraphMap:
    value = graph.get(key)
    return cast("GraphMap", value) if isinstance(value, dict) else {}


def _referenced_graph_names(paths: tuple[str, ...], callgraph: GraphMap, imports: GraphMap) -> set[str]:
    names: set[str] = set()
    for rel in paths:
        for definitions in _file_defs(callgraph.get(rel)).values():
            for item in definitions:
                calls = item.get("calls") if isinstance(item, dict) else ()
                names.update(str(call) for call in calls or ())
        names.update(str(name) for name in imports.get(rel) or ())
    return names


def _direct_target_scores(
    paths: tuple[str, ...],
    import_targets: GraphMap,
    required_target_scores: dict[str, int],
) -> dict[str, int]:
    scores = dict(required_target_scores)
    for rel in paths:
        for raw_target in import_targets.get(rel) or ():
            target = str(raw_target)
            if target not in paths:
                scores.setdefault(target, 0)
    return scores


def _files_defining_names(
    paths: tuple[str, ...],
    callgraph: GraphMap,
    referenced_names: set[str],
) -> tuple[str, ...]:
    return tuple(
        str(rel)
        for rel, definitions in callgraph.items()
        if rel not in paths and isinstance(definitions, dict) and any(name in definitions for name in referenced_names)
    )


def _changed_peer_name_score(
    rel: str,
    callgraph: GraphMap,
    preferred_names: ReviewNamesByPath,
    seed_text: str,
) -> int:
    definitions = set(_file_defs(callgraph.get(rel)))
    changed_definitions = definitions.intersection(preferred_names.get(rel, ()))
    return sum(len(name) for name in changed_definitions if re.search(rf"\b{re.escape(name)}\b", seed_text))


def _forward_import_files(paths: tuple[str, ...], import_targets: GraphMap) -> tuple[str, ...]:
    frontier = list(paths)
    seen = set(paths)
    out: list[str] = []
    for _ in range(2):
        next_frontier: list[str] = []
        for rel in frontier:
            for target in import_targets.get(rel) or ():
                target = str(target)
                if target in seen:
                    continue
                seen.add(target)
                out.append(target)
                next_frontier.append(target)
        frontier = next_frontier
    return tuple(out)


def _related_name_hits(rel: str, callgraph: GraphMap, imports: GraphMap, seed_text: str) -> int:
    names = {*_file_defs(callgraph.get(rel)), *(str(name) for name in imports.get(rel) or ())}
    return sum(1 for name in names if re.search(rf"\b{re.escape(name)}\b", seed_text))


def _reverse_call_files(paths: tuple[str, ...], callgraph: GraphMap) -> tuple[str, ...]:
    focus_names = _focus_names(paths, callgraph)
    out: dict[str, None] = {}
    for rel, defs_by_name in callgraph.items():
        rel = str(rel)
        if rel in paths or not isinstance(defs_by_name, dict):
            continue
        for entries in defs_by_name.values():
            if any(
                focus_names.intersection(str(call) for call in item.get("calls") or ())
                for item in entries or ()
                if isinstance(item, dict)
            ):
                out.setdefault(rel, None)
                break
    return tuple(out)


def _reverse_import_files(
    paths: tuple[str, ...], callgraph: GraphMap, imports: GraphMap, import_targets: GraphMap
) -> tuple[str, ...]:
    target_files = set(paths)
    target_names = {str(name) for rel in paths for name in _file_defs(callgraph.get(rel))}
    out: dict[str, None] = {}
    for _ in range(2):
        grew = False
        for rel, targets in import_targets.items():
            rel = str(rel)
            if rel in target_files:
                continue
            if not any(str(target) in target_files for target in targets or ()):
                continue
            imported = {str(name) for name in imports.get(rel) or ()}
            if target_names and imported and not imported.intersection(target_names):
                continue
            out.setdefault(rel, None)
            target_files.add(rel)
            target_names.update(imported)
            target_names.update(str(name) for name in _file_defs(callgraph.get(rel)))
            grew = True
        if not grew:
            break
    return tuple(out)


def _file_defs(value: object) -> GraphMap:
    return cast("GraphMap", value) if isinstance(value, dict) else {}
