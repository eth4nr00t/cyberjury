"""Build a language-agnostic repository map and bounded review units.

The model lists files deterministically and selects candidate entrypoints from profile
data. Unit construction represents every candidate and backend selected facts seed in
a dependency plan or fallback unit, with no model calls or vulnerability specific logic.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.review.context import definition_relationships
from cyberjury.review.definitions import (
    DefinitionFragment,
    definition_fragments,
    definition_references,
    plan_definition_units,
)
from cyberjury.review.facts import FactFragment, FactUnitSpec, normalize_fact_unit_specs
from cyberjury.review.paths import repository_files, safe_repository_path
from cyberjury.review.repository.context import Unit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


@dataclass(frozen=True, kw_only=True)
class RepositoryModel:
    """Language-agnostic file map used to seed repository review units."""

    root: str
    files: tuple[str, ...]


class RepositorySourceError(RuntimeError):
    """A source required for deterministic worklist discovery is unavailable."""


def build_repository_model_from_dir(root: str | Path, detection: Detection | None = None) -> RepositoryModel:
    """Build a repository file map from a directory."""
    return RepositoryModel(root=str(root), files=repository_files(root, detection))


def build_repository_model(root: str | Path, files: Sequence[str]) -> RepositoryModel:
    """Build a repository model for a caller that already has the relative file list."""
    return RepositoryModel(root=str(root), files=tuple(sorted(files)))


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _read_discovery_text(path: Path) -> str:
    try:
        size = path.stat().st_size
        if size > _SETTINGS.max_scanned_source_bytes_per_file:
            raise RepositorySourceError(
                f"candidate discovery source {path} exceeds {_SETTINGS.max_scanned_source_bytes_per_file} bytes"
            )
        return path.read_text(encoding="utf-8")
    except RepositorySourceError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise RepositorySourceError(f"candidate discovery could not read source {path}: {exc}") from exc


def candidate_entrypoint_files(
    files: Sequence[str],
    *,
    root: str | Path | None = None,
    globs: Sequence[str] = (),
    markers: Sequence[str] = (),
    detection: Detection | None = None,
) -> list[str]:
    """Files likely to define entrypoints.

    A file is a candidate when its path matches one of `globs`, or when `root` is given and
    its content contains one of `markers` the guide declares, such as a handler class or a
    route registration. The marker scan is what recovers framework entrypoints that no
    filename glob would catch, and it stays data-driven because the markers come from the
    guide. Returns a sorted list with no duplicates.
    """
    det = detection or load_detection()
    globs = tuple(globs)
    markers = tuple(markers)
    base = Path(root) if root is not None else None
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if any(fnmatch.fnmatch(f, g) for g in globs):
            out.append(f)
            continue
        if markers and base is not None and Path(f).suffix.lower() in det.source_extensions:
            text = _read_discovery_text(base / f)
            if text and any(m in text for m in markers):
                out.append(f)
    return sorted(dict.fromkeys(out))


def files_with_exported_symbols(
    files: Sequence[str],
    *,
    root: str | Path | None = None,
    patterns: Sequence[str] = (),
    detection: Detection | None = None,
) -> list[str]:
    """Non-test source files that define symbols exported through language syntax.

    A library has no application entrypoint, so its exported symbols are the attack surface:
    a consumer passes attacker-influenced data into them. Used as the fallback denominator
    when no application entrypoint seeds, so a library is reviewed from its public surface
    inward rather than not at all. `patterns` are per-language export regexes a guide
    declares, such as a capitalized Go function, which keeps the selection data-driven and
    the engine generic. A file whose symbols are all private matches nothing and is left
    out, so unreachable internal code is not seeded. Returns a sorted list with no
    duplicates.
    """
    det = detection or load_detection()
    if not patterns or root is None:
        return []
    compiled = [re.compile(p, re.MULTILINE) for p in patterns]
    base = Path(root)
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if Path(f).suffix.lower() not in det.source_extensions:
            continue
        text = _read_discovery_text(base / f)
        if text and any(c.search(text) for c in compiled):
            out.append(f)
    return sorted(dict.fromkeys(out))


def construct_boundaries(text: str) -> list[int]:
    """Find lexical window candidates at unindented source lines.

    A nonspace character at the start of a line marks a candidate. The heuristic can include
    imports, comments, and closing delimiters, so it does not claim to parse language
    constructs. Window edges prefer these candidates to avoid arbitrary midline splits.
    """
    starts: list[int] = []
    decorated = False
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        top_level = bool(stripped) and len(stripped) == len(line)
        if top_level and stripped.startswith("@"):
            if not decorated:
                starts.append(offset)
            decorated = True
        elif top_level:
            if not decorated:
                starts.append(offset)
            decorated = False
        elif stripped:
            decorated = False
        offset += len(line)
    return starts


def char_spans(text: str) -> list[tuple[int, int] | None]:
    """The char windows that cover `text`.

    Text that fits one window is reviewed intact, span None. Larger text is split at top-
    level construct boundaries so each class or function lands intact in one window. A single
    construct longer than a window is hard split with an overlap, so even then no boundary
    silently drops a construct's tail. Shared by the coded run's unit builder and the
    scaffold's unit seeding, so both paths split a large entrypoint file the same way.
    """
    size = len(text)
    if size <= _SETTINGS.max_source_chars_per_unit:
        return [None]
    boundaries = construct_boundaries(text)
    spans: list[tuple[int, int] | None] = []
    start = 0
    while True:
        target = start + _SETTINGS.max_source_chars_per_unit
        if target >= size:
            spans.append((start, size))
            return spans
        within = [b for b in boundaries if start < b <= target]
        if within:
            end = within[-1]
            next_start = end
        else:
            end = target
            next_start = end - _SETTINGS.hard_split_overlap_chars
        spans.append((start, end))
        start = next_start


def span_line_range(text: str, span: tuple[int, int]) -> tuple[int, int]:
    """Convert a character span to its one-based inclusive line range.

    This lets a seeded unit identify its source slice by line number rather than an
    opaque char offset.
    """
    start, end = span
    first = text.count("\n", 0, start) + 1
    last = text.count("\n", 0, max(start, end - 1)) + 1
    return first, last


def logic_layer_files(
    files: Sequence[str], *, globs: Sequence[str] = (), detection: Detection | None = None
) -> list[str]:
    """Find non-test files that match downstream logic layer globs.

    Examples include managers, controllers, DAO modules, and services. These are not entrypoints but the
    call targets to trace into from an entrypoint, so a review does not stop at the view.
    Returns a sorted list with no duplicates.
    """
    det = detection or load_detection()
    globs = tuple(globs)
    out = {f for f in files if not det.is_test_path(f) and any(fnmatch.fnmatch(f, g) for g in globs)}
    return sorted(out)


def _file_text(root: str, rel: str) -> str:
    path = safe_repository_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _definition_units(
    root: str,
    candidate_files: Sequence[str],
    fact_specs: Sequence[FactUnitSpec] | None,
    graph: dict[str, object] | None,
) -> list[Unit]:
    """Adapt repository seeds to shared dependency subgraph plans."""
    facts_graph = graph or {}
    fragment_index = definition_fragments(facts_graph)
    candidates = set(candidate_files)
    seeds = [fragment for fragments in fragment_index.values() for fragment in fragments if fragment.file in candidates]
    by_range = {
        (fragment.file, fragment.start, fragment.end): fragment
        for fragments in fragment_index.values()
        for fragment in fragments
    }
    for spec in fact_specs or ():
        for fragment in spec.get("fragments", []):
            matched = by_range.get((fragment.file, fragment.start, fragment.end))
            if matched is not None and matched not in seeds:
                seeds.append(matched)
    plans = plan_definition_units(
        tuple(seeds),
        facts_graph,
        depth=_SETTINGS.import_closure_depth,
        max_chars=_SETTINGS.target_gathered_source_chars_per_unit,
        seed_files=tuple(candidate_files),
        references_by_seed=definition_references(
            tuple(seeds),
            lambda path: _file_text(root, path),
        ),
        max_relationship_chars=_SETTINGS.max_relationship_chars_per_unit,
    )
    bases = []
    for plan in plans:
        roots = tuple(dict.fromkeys((*(seed.file for seed in plan.seeds), *plan.seed_files)))
        bases.append(f"dependencies:{roots[0]}" if len(roots) == 1 else "dependencies:combined")
    totals = Counter(bases)
    positions: Counter[str] = Counter()
    names: list[str] = []
    for base in bases:
        positions[base] += 1
        names.append(base if totals[base] == 1 else f"{base}#{positions[base]}")
    ordered_fragments = [
        tuple(
            dict.fromkeys(
                (
                    *(seed for seed in plan.seeds if seed not in plan.fragments),
                    *plan.fragments,
                )
            )
        )
        for plan in plans
    ]
    return [
        Unit(
            name=names[index - 1],
            root=root,
            files=tuple(dict.fromkeys(fragment.file for fragment in ordered_fragments[index - 1])),
            fragments=tuple(_fragment_tuple(fragment) for fragment in ordered_fragments[index - 1]),
            fragment_identities=tuple(fragment.identity for fragment in ordered_fragments[index - 1]),
            relationships=definition_relationships(plan),
            unresolved_identities=tuple(item.identity for item in plan.unresolved),
            definition_plan=plan,
        )
        for index, plan in enumerate(plans, 1)
    ]


def _fragment_tuple(fragment: DefinitionFragment) -> FactFragment:
    return FactFragment(fragment.file, fragment.start, fragment.end)


def _fact_unit_specs(root: str, fact_specs: Sequence[FactUnitSpec] | None) -> list[Unit]:
    """Materialize focused facts specs without interpreting profile knowledge."""
    units: list[Unit] = []
    for spec in fact_specs or ():
        fragments = tuple(spec.get("fragments", []))
        if not fragments:
            continue
        name = str(spec.get("name") or "")
        files = tuple(dict.fromkeys(fragment.file for fragment in fragments))
        units.append(Unit(name=name or files[0], root=root, files=files, fragments=fragments))
    return units


def build_units(
    root: str | Path,
    candidate_files: Sequence[str],
    trace_targets: Sequence[str],
    fact_unit_specs: Sequence[FactUnitSpec] | None = None,
    facts_graph: dict[str, object] | None = None,
) -> list[Unit]:
    """Cover repository seeds through shared paths with file window fallbacks."""
    root = str(root)
    targets = list(dict.fromkeys(trace_targets))
    normalized_specs = normalize_fact_unit_specs(list(fact_unit_specs or ()))
    definition_units = _definition_units(root, candidate_files, normalized_specs, facts_graph)
    covered_fragment_sets = [set(unit.fragments) for unit in definition_units]
    uncovered_fact_units = [
        unit
        for unit in _fact_unit_specs(root, normalized_specs)
        if not any(set(unit.fragments).issubset(covered) for covered in covered_fragment_sets)
    ]
    units: list[Unit] = []
    for candidate in candidate_files:
        related = tuple(
            target for target in targets if target != candidate and _path_owner(target) == _path_owner(candidate)
        )
        related_groups = _trace_groups(root, candidate, related)
        spans = char_spans(_file_text(root, candidate))
        for span_index, span in enumerate(spans, 1):
            base_name = candidate if len(spans) == 1 else f"{candidate}#{span_index}"
            for group_index, group in enumerate(related_groups, 1):
                name = base_name if len(related_groups) == 1 else f"{base_name}@trace{group_index}"
                units.append(Unit(name=name, root=root, files=(candidate, *group), span=span))
    units += definition_units
    units += uncovered_fact_units
    return units


def _path_owner(path: str) -> str:
    parts = Path(path).parts
    return parts[0] if len(parts) > 1 else ""


def _trace_groups(root: str, candidate: str, related: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    if not related:
        return ((),)
    candidate_chars = min(len(_file_text(root, candidate)), _SETTINGS.max_source_chars_per_unit)
    available = max(1, _SETTINGS.target_gathered_source_chars_per_unit - candidate_chars)
    groups: list[tuple[str, ...]] = []
    current: list[str] = []
    current_chars = 0
    for target in related:
        target_chars = min(len(_file_text(root, target)), _SETTINGS.max_secondary_source_chars_per_file)
        if current and (
            len(current) >= _SETTINGS.max_related_files_per_unit or current_chars + target_chars > available
        ):
            groups.append(tuple(current))
            current = []
            current_chars = 0
        current.append(target)
        current_chars += target_chars
    if current:
        groups.append(tuple(current))
    return tuple(groups)
