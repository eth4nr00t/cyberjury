"""Build prompt context for a diff from repository facts."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast

from cyberjury.detection import Detection, load_detection
from cyberjury.profiles.base import ReviewProfile
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    candidate_call_context,
    definition_evidence,
    definition_plan_source_files,
    delivered_source_block,
    publish_candidate_evidence,
    with_scoped_fact_limitations,
)
from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan, FactsGraph
from cyberjury.review.diff.model import (
    ChangedLineRanges,
    DiffUnit,
    changed_line_ranges,
    changed_paths,
    prepare_diff_units,
    reviewable_changed_paths,
)
from cyberjury.review.diff.prompts import (
    file_context,
    related_file_context,
    render_context,
    required_definition_chars,
)
from cyberjury.review.facts import (
    FactLimitation,
    FactsByFile,
    FactsResolutionReceipt,
    NativeAnalysisReceipt,
    extract_facts,
)
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.navigation import SourceNavigator
from cyberjury.review.paths import source_navigation_files
from cyberjury.review.relationships import (
    RelationshipEvidenceBundle,
    rebase_relationship_evidence,
    relationship_evidence_from_data,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.snapshot import SourceSnapshot, source_snapshot_files

type GraphMap = dict[str, object]

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff
_MAX_LINKED_SOURCE_CHARS_PER_FILE = 3_500
_MAX_INITIAL_CANDIDATE_SOURCE_CHARS = 4_000
_FILE_KEYED_GRAPH_MAPS = ("callgraph", "syntax_imports")


@dataclass(frozen=True, kw_only=True)
class _ContextPlan:
    callgraph: dict[str, object]
    seed_text: str
    required_fragments: dict[str, tuple[DefinitionFragment, ...]]
    related_files: tuple[str, ...]
    required: tuple[str, ...]
    focus_names: set[str]
    linked_names_by_file: dict[str, tuple[str, ...]]


@dataclass(frozen=True, kw_only=True)
class DiffContextCollector:
    """Interface for collecting source context for diff review."""

    root: Path
    detection: Detection
    by_file: FactsByFile
    graph: FactsGraph
    navigator: SourceNavigator | None = None
    facts_limitations: tuple[FactLimitation, ...] = ()
    review_paths: tuple[str, ...] = ()
    source_snapshot: SourceSnapshot | None = None
    native_analysis: NativeAnalysisReceipt | None = None
    facts_resolution: FactsResolutionReceipt | None = None
    relationship_evidence: RelationshipEvidenceBundle = field(default_factory=RelationshipEvidenceBundle)

    def _collect(self, diff: str, definition_plan: DefinitionUnitPlan) -> GroundingContext:
        paths = reviewable_changed_paths(diff, self.detection)
        if not paths:
            return GroundingContext(text="", files=(), source="diff")
        ranges = changed_line_ranges(diff, self.detection)
        changed, related, coverage = _context_blocks(
            self.root,
            paths,
            self.by_file,
            self.graph,
            ranges,
            review_paths=self.review_paths,
            definition_plan=definition_plan,
            detection=self.detection,
        )
        structured_plan = bool(definition_plan.seeds or definition_plan.evidence)
        related_first = len(paths) >= _SETTINGS.related_context_first_min_changed_files
        entries = [*related, *changed] if related_first else [*changed, *related]
        text = render_context(
            changed,
            related,
            related_first=related_first,
            preserve_required=structured_plan,
        )
        candidate = candidate_call_context(
            self.root,
            definition_plan,
            self.relationship_evidence,
            max_chars=min(
                _SETTINGS.max_relationship_chars_per_unit,
                _SETTINGS.target_repository_context_chars_per_unit,
            ),
            callsite_ids=_callsite_ids_in_ranges(
                self.root,
                self.relationship_evidence,
                ranges,
            ),
        )
        if candidate.text:
            text = "\n\n".join(part for part in (candidate.text, text) if part)
        files = tuple(dict.fromkeys(rel for rel, _block in entries if rel in paths))
        evidence = definition_evidence(self.root, definition_plan)
        delivered = _initial_candidate_sources(candidate.source_evidence, len(text))
        delivered_ids = {item.id for item in delivered}
        context = GroundingContext(
            source="diff",
            text=text,
            files=files,
            coverage=coverage,
            evidence=publish_candidate_evidence(
                evidence,
                tuple(item for item in candidate.source_evidence if item.id not in delivered_ids),
            ),
            source_evidence=delivered,
            navigator=self.navigator,
            source_snapshot=self.source_snapshot,
        )
        planned_scope_files = tuple(
            dict.fromkeys(
                (
                    *(rel for rel, _block in entries),
                    *definition_plan_source_files(definition_plan),
                    *(item.source_span.file for item in candidate.source_evidence if item.source_span is not None),
                )
            )
        )
        snapshot_files = set(self.source_snapshot.files) if self.source_snapshot is not None else None
        scope_files = tuple(file for file in planned_scope_files if snapshot_files is None or file in snapshot_files)
        context = replace(context, snapshot_files=scope_files)
        return with_scoped_fact_limitations(context, self.facts_limitations, source_files=scope_files)

    def plan(self, diff: str) -> list[DiffUnit]:
        """Plan deterministic diff units without performing initial grounding."""
        self._validate_snapshot()
        return prepare_diff_units(
            diff,
            root=self.root,
            detection=self.detection,
            graph=self.graph,
            settings=_SETTINGS,
        )

    def ground(self, units: list[DiffUnit]) -> list[DiffUnit]:
        """Bind every planned diff unit to its exact initial evidence envelope."""
        self._validate_snapshot()
        if any(unit.definition_plan is None for unit in units):
            raise ValueError("diff unit grounding requires a definition plan")
        grounded = [replace(unit, grounding=self._collect(unit.diff, unit.definition_plan)) for unit in units]
        self._validate_snapshot()
        return grounded

    def _validate_snapshot(self) -> None:
        if self.source_snapshot is not None and not self.source_snapshot.matches():
            raise BackendUnavailable("repository source changed after diff facts extraction")


def _initial_candidate_sources(items: tuple[SourceEvidence, ...], context_chars: int) -> tuple[SourceEvidence, ...]:
    """Deliver short candidate callees within the same initial context budget."""
    remaining = min(
        _MAX_INITIAL_CANDIDATE_SOURCE_CHARS,
        max(0, _SETTINGS.target_repository_context_chars_per_unit - context_chars),
    )
    delivered = []
    for item in items:
        cost = len(delivered_source_block(item)) + 2
        if cost <= remaining:
            delivered.append(item)
            remaining -= cost
    return tuple(delivered)


def _callsite_ids_in_ranges(
    root: Path,
    relationships: RelationshipEvidenceBundle,
    ranges: ChangedLineRanges,
) -> frozenset[str]:
    """Select callsites physically present in the current patch hunks."""
    sources: dict[str, str] = {}
    selected = set()
    for callsite in relationships.callsites:
        file_ranges = ranges.get(callsite.source.path, ())
        if not file_ranges:
            continue
        source = sources.get(callsite.source.path)
        if source is None:
            source = _read_normalized_source(root, callsite.source.path)
            sources[callsite.source.path] = source
        start_line = source.count("\n", 0, callsite.source.start) + 1
        end_line = source.count("\n", 0, max(callsite.source.start, callsite.source.end - 1)) + 1
        if any(start_line <= end and start <= end_line for start, end in file_ranges):
            selected.add(callsite.id)
    return frozenset(selected)


def build_diff_context_collector(
    repository: str | Path,
    profile: ReviewProfile,
    *,
    facts_root: str | Path | None = None,
    review_diff: str | None = None,
    source_snapshot: SourceSnapshot | None = None,
) -> DiffContextCollector:
    """Extract repository facts once, then render context for one or more diff batches."""
    review_was_specified = review_diff is not None
    review_diff = review_diff or ""
    root = Path(repository).resolve()
    facts_base = Path(facts_root).resolve() if facts_root is not None else root
    prefix = _relative_prefix(root, facts_base)
    detection = load_detection(profile.paths.detection_file)
    review_paths = changed_paths(review_diff, detection)
    if source_snapshot is None:
        snapshot_files = tuple(_prefix_path(file, prefix) for file in source_snapshot_files(facts_base))
        source_snapshot = SourceSnapshot.capture(
            root,
            snapshot_files,
            scope_provider=lambda: tuple(_prefix_path(file, prefix) for file in source_snapshot_files(facts_base)),
        )
    elif source_snapshot.root != root or facts_base != root:
        raise ValueError("bound diff source snapshot must cover the repository root")
    elif not source_snapshot.matches():
        raise BackendUnavailable("repository source changed before diff facts extraction")
    if review_was_specified and not review_diff.strip():
        native_analysis = NativeAnalysisReceipt.create(
            producer="diff-empty",
            producer_version="1",
            source_count=0,
            definition_count=0,
            callsite_count=0,
            limitation_count=0,
            evidence={"reason": "no_reviewable_units", "source_revision": source_snapshot.snapshot_id},
        )
        facts_resolution = FactsResolutionReceipt.create(
            native_analysis=native_analysis,
            relationship_evidence=RelationshipEvidenceBundle().to_data(),
            limitations=(),
        )
        return DiffContextCollector(
            root=root,
            detection=detection,
            by_file={},
            graph={},
            source_snapshot=source_snapshot,
            native_analysis=native_analysis,
            facts_resolution=facts_resolution,
        )
    facts = extract_facts(profile.facts_backend, facts_base, purpose="diff context")
    if not source_snapshot.matches():
        raise BackendUnavailable("repository source changed during diff facts extraction")
    data = facts.data if isinstance(facts.data, dict) else {}
    by_file = cast("FactsByFile", data.get("by_file")) if isinstance(data.get("by_file"), dict) else {}
    graph = cast("FactsGraph", data.get("graph")) if isinstance(data.get("graph"), dict) else {}
    prefixed_graph = _prefix_graph(graph, prefix)
    navigation_files = source_navigation_files(root, detection)
    raw_relationships = data.get("relationship_evidence", {})
    relationships = (
        relationship_evidence_from_data(raw_relationships)
        if isinstance(raw_relationships, dict) and raw_relationships
        else RelationshipEvidenceBundle()
    )
    relationships = rebase_relationship_evidence(
        relationships,
        prefix,
        lambda rel: _read_normalized_source(root, rel),
    )
    return DiffContextCollector(
        root=root,
        detection=detection,
        by_file=_prefix_facts_by_file(by_file, prefix),
        graph=prefixed_graph,
        navigator=SourceNavigator.from_graph(
            root,
            prefixed_graph,
            source_files=navigation_files,
            relationship_evidence=relationships,
            test_files=(file for file in navigation_files if detection.is_test_path(file)),
            documentation_files=(
                file for file in navigation_files if Path(file).suffix.lower() in detection.doc_extensions
            ),
        ),
        facts_limitations=_prefix_fact_limitations(facts.limitations, prefix),
        review_paths=review_paths,
        source_snapshot=source_snapshot,
        native_analysis=facts.native_analysis,
        facts_resolution=facts.facts_resolution,
        relationship_evidence=relationships,
    )


def _read_normalized_source(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
        return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError, ValueError) as exc:
        raise BackendUnavailable(f"cannot read rebased relationship source {rel}: {exc}") from exc


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


def _prefix_graph(graph: FactsGraph, prefix: str) -> FactsGraph:
    if not prefix:
        return graph
    out: FactsGraph = dict(graph)
    for key in _FILE_KEYED_GRAPH_MAPS:
        values = graph.get(key)
        if isinstance(values, dict):
            out[key] = _prefix_map(values, prefix)
    return out


def _context_blocks(
    root: Path,
    paths: tuple[str, ...],
    by_file: FactsByFile,
    graph: FactsGraph,
    ranges: ChangedLineRanges,
    *,
    review_paths: tuple[str, ...],
    definition_plan: DefinitionUnitPlan,
    detection: Detection,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], GroundingCoverage]:
    plan = _plan_context(
        root,
        paths,
        graph,
        ranges,
        review_paths=review_paths,
        definition_plan=definition_plan,
        detection=detection,
    )
    structured_plan = bool(definition_plan.seeds or definition_plan.evidence)
    changed_blocks = [] if structured_plan else _changed_context_blocks(root, paths, by_file, ranges, plan.callgraph)
    related_blocks, included = _related_context_blocks(
        root,
        by_file,
        plan,
        preserve_required=structured_plan,
    )
    coverage = _context_coverage(plan.required, included)
    return changed_blocks, related_blocks, coverage


def _plan_context(
    root: Path,
    paths: tuple[str, ...],
    graph: FactsGraph,
    ranges: ChangedLineRanges,
    *,
    review_paths: tuple[str, ...],
    definition_plan: DefinitionUnitPlan,
    detection: Detection,
) -> _ContextPlan:
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    seeds = _changed_seeds(root, paths, ranges)
    seed_text = "\n".join(seeds.values())
    seed_identities = {fragment.identity for fragment in definition_plan.seeds}
    fragments = tuple(fragment for fragment in definition_plan.fragments if fragment.identity not in seed_identities)
    required_fragments = _fragments_by_file(fragments)
    linked_files, linked_names_by_file = _importing_files_for_seeds(
        graph,
        definition_plan.seeds,
        detection,
        review_paths,
        paths,
    )
    related_files = tuple(dict.fromkeys((*required_fragments, *linked_files)))
    required = tuple(fragment.identity for fragments in required_fragments.values() for fragment in fragments)
    return _ContextPlan(
        callgraph=callgraph,
        seed_text=seed_text,
        required_fragments=required_fragments,
        related_files=related_files,
        required=required,
        focus_names=_focus_names(paths, callgraph),
        linked_names_by_file=linked_names_by_file,
    )


def _importing_files_for_seeds(
    graph: FactsGraph,
    seeds: tuple[DefinitionFragment, ...],
    detection: Detection,
    review_paths: tuple[str, ...],
    unit_paths: tuple[str, ...],
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """Find source that imports a changed definition without asserting a binding."""
    seed_files_by_name: dict[str, set[str]] = {}
    for seed in seeds:
        if seed.name != "<file>":
            seed_files_by_name.setdefault(seed.name, set()).add(seed.file)
    imports = graph.get("syntax_imports")
    if not seed_files_by_name or not isinstance(imports, dict):
        return (), {}
    matches: dict[str, tuple[str, ...]] = {}
    source_matches: dict[str, int] = {}
    source_name_lengths: dict[str, int] = {}
    for file, rows in imports.items():
        if not isinstance(file, str) or detection.is_noise_path(file) or not isinstance(rows, list):
            continue
        linked_names: set[str] = set()
        matching_sources = 0
        matching_name_length = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            imported = row.get("imported")
            if not isinstance(imported, str) or imported not in seed_files_by_name:
                continue
            local = row.get("local")
            linked_names.add(local if isinstance(local, str) and local else imported)
            module = row.get("module")
            if isinstance(module, str):
                module_path = module.replace(".", "/")
                if any(
                    source.rsplit(".", 1)[0].endswith(f"/{module_path}") or source.rsplit(".", 1)[0] == module_path
                    for source in seed_files_by_name[imported]
                ):
                    matching_sources += 1
                    matching_name_length = max(matching_name_length, len(imported))
        linked = tuple(sorted(linked_names))
        if linked:
            matches[file] = linked
            source_matches[file] = matching_sources
            source_name_lengths[file] = matching_name_length
    candidates = matches
    if len(unit_paths) > 3:
        candidates = {file: names for file, names in matches.items() if file not in unit_paths}
    ranked = sorted(
        candidates,
        key=lambda file: (
            -source_name_lengths[file],
            -source_matches[file],
            file not in review_paths,
            -sum(map(len, matches[file])),
            file,
        ),
    )[: 1 if len(unit_paths) <= 3 else 3]
    return tuple(ranked), {file: matches[file] for file in ranked}


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
            if plan.linked_names_by_file.get(rel):
                block_limit = min(block_limit, _MAX_LINKED_SOURCE_CHARS_PER_FILE)
        block, block_included = related_file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            _file_defs(plan.callgraph.get(rel)),
            plan.focus_names,
            plan.seed_text,
            required_for_file,
            linked_names=plan.linked_names_by_file.get(rel, ()),
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
) -> GroundingCoverage:
    included_set = set(included)
    return GroundingCoverage(
        required=required,
        included=included,
        omitted=(*(identity for identity in required if identity not in included_set),),
    )


def _focus_names(paths: tuple[str, ...], callgraph: dict) -> set[str]:
    return {str(name) for rel in paths for name in _file_defs(callgraph.get(rel))}


def _changed_seeds(root: Path, paths: tuple[str, ...], ranges: ChangedLineRanges) -> dict[str, str]:
    seeds: dict[str, str] = {}
    for rel in paths:
        path = (root / rel).resolve()
        try:
            path.relative_to(root)
            if not path.is_file():
                continue
            source = path.read_text(encoding="utf-8")
        except ValueError as exc:
            raise BackendUnavailable(f"changed source path escapes the repository: {rel}") from exc
        except (OSError, UnicodeDecodeError) as exc:
            raise BackendUnavailable(f"changed source could not be read for grounding {rel}: {exc}") from exc
        lines = source.splitlines()
        parts: list[str] = []
        for start, end in ranges.get(rel, ()):
            if start <= len(lines):
                parts.extend(lines[start - 1 : min(end, len(lines))])
        seeds[rel] = "\n".join(parts)
    return seeds


def _file_defs(value: object) -> GraphMap:
    return cast("GraphMap", value) if isinstance(value, dict) else {}
