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
    definition_union_size,
    plan_definition_units,
)
from cyberjury.review.facts import FactFragment, FactsResolutionReceipt, FactUnitSpec, normalize_fact_unit_specs
from cyberjury.review.paths import repository_files, safe_repository_path
from cyberjury.review.repository.context import Unit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice

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


def _unit_source_text(root: str | Path, rel: str) -> str:
    path = safe_repository_path(root, rel)
    if path is None:
        raise RepositorySourceError(f"unit planning references unsafe source path {rel!r}")
    try:
        if not path.is_file():
            raise OSError("not a regular file")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RepositorySourceError(f"unit planning could not read source {rel}: {exc}") from exc


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
    plans = tuple(plan for plan in plans if plan.dependencies)
    bases = []
    for plan in plans:
        roots = tuple(dict.fromkeys((*(seed.file for seed in plan.seeds), *plan.seed_files)))
        bases.append(f"relationships:{roots[0]}" if len(roots) == 1 else "relationships:combined")
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
            kind="relationship",
            owned_paths=tuple(dict.fromkeys((*(seed.file for seed in plan.seeds), *plan.seed_files))),
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
    """Pack focused facts specs by source identity and code size."""
    groups: list[tuple[tuple[str, ...], tuple[FactFragment, ...], tuple[str, ...]]] = []
    current_files: tuple[str, ...] = ()
    current_fragments: tuple[FactFragment, ...] = ()
    current_labels: tuple[str, ...] = ()
    for spec in fact_specs or ():
        fragments = tuple(spec.get("fragments", []))
        if not fragments:
            continue
        for file, _start, end in fragments:
            if end > len(_unit_source_text(root, file)):
                raise RepositorySourceError(f"focused unit fragment exceeds source {file}")
        files = tuple(dict.fromkeys(fragment.file for fragment in fragments))
        label = str(spec.get("name") or f"{fragments[0].file}:{fragments[0].start}:{fragments[0].end}")
        combined = tuple(dict.fromkeys((*current_fragments, *fragments)))
        combined_size = definition_union_size(
            tuple(DefinitionFragment(file, file, start, end) for file, start, end in combined)
        )
        if current_fragments and (files != current_files or combined_size > _SETTINGS.max_source_chars_per_unit):
            groups.append((current_files, current_fragments, current_labels))
            current_files = ()
            current_fragments = ()
            current_labels = ()
            combined = fragments
        current_files = files
        current_fragments = combined
        current_labels = (*current_labels, label)
    if current_fragments:
        groups.append((current_files, current_fragments, current_labels))
    totals = Counter(files for files, _fragments, _labels in groups)
    positions: Counter[tuple[str, ...]] = Counter()
    units = []
    for files, fragments, labels in groups:
        positions[files] += 1
        base = f"focused:{','.join(files)}"
        name = base if totals[files] == 1 else f"{base}#{positions[files]}"
        units.append(
            Unit(
                name=name,
                root=root,
                files=files,
                kind="focused",
                owned_paths=files,
                labels=labels,
                fragments=fragments,
            )
        )
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
    source_files = tuple(dict.fromkeys((*candidate_files, *trace_targets)))
    normalized_specs = normalize_fact_unit_specs(list(fact_unit_specs or ()))
    definition_units = _definition_units(root, candidate_files, normalized_specs, facts_graph)
    focused_units = _fact_unit_specs(root, normalized_specs)
    units = _source_units(root, source_files, focused_units)
    units += definition_units
    units += focused_units
    for unit in units:
        _unit_source_slices(Path(root), unit)
    names = [unit.name for unit in units]
    if len(names) != len(set(names)):
        raise ValueError("repository unit names must be unique across source, relationship, and focused units")
    return units


def _source_units(root: str, source_files: tuple[str, ...], focused_units: list[Unit]) -> list[Unit]:
    claimed = _focused_ranges(focused_units)
    units: list[Unit] = []
    for source_file in source_files:
        text = _unit_source_text(root, source_file)
        if not text:
            continue
        focused = claimed.get(source_file, ())
        if not focused:
            spans = char_spans(text)
            units.extend(
                Unit(
                    name=source_file if len(spans) == 1 else f"{source_file}#{index}",
                    root=root,
                    files=(source_file,),
                    owned_paths=(source_file,),
                    span=span,
                )
                for index, span in enumerate(spans, 1)
            )
            continue
        if any(end > len(text) for start, end in focused):
            raise ValueError(f"focused unit fragment exceeds repository source {source_file}")
        residual = _residual_fragments(source_file, text, focused)
        groups = _pack_source_fragments(residual)
        units.extend(
            Unit(
                name=source_file if len(groups) == 1 else f"{source_file}#{index}",
                root=root,
                files=(source_file,),
                kind="source",
                owned_paths=(source_file,),
                fragments=group,
            )
            for index, group in enumerate(groups, 1)
        )
    return units


def _focused_ranges(units: list[Unit]) -> dict[str, tuple[tuple[int, int], ...]]:
    grouped: dict[str, list[tuple[int, int]]] = {}
    for unit in units:
        for file, start, end in unit.fragments:
            ranges = grouped.setdefault(file, [])
            if any(start < other_end and other_start < end for other_start, other_end in ranges):
                raise ValueError(f"focused unit fragments overlap in {file}")
            ranges.append((start, end))
    return {file: tuple(sorted(ranges)) for file, ranges in grouped.items()}


def _residual_fragments(
    file: str,
    text: str,
    claimed: tuple[tuple[int, int], ...],
) -> tuple[FactFragment, ...]:
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in claimed:
        if cursor < start:
            gaps.append((cursor, start))
        cursor = end
    if cursor < len(text):
        gaps.append((cursor, len(text)))
    fragments: list[FactFragment] = []
    for start, end in gaps:
        for span in char_spans(text[start:end]):
            local_start, local_end = span or (0, end - start)
            fragments.append(FactFragment(file, start + local_start, start + local_end))
    return tuple(fragments)


def _pack_source_fragments(fragments: tuple[FactFragment, ...]) -> tuple[tuple[FactFragment, ...], ...]:
    groups: list[tuple[FactFragment, ...]] = []
    current: list[FactFragment] = []
    current_chars = 0
    for fragment in fragments:
        size = fragment.end - fragment.start
        if current and current_chars + size > _SETTINGS.max_source_chars_per_unit:
            groups.append(tuple(current))
            current = []
            current_chars = 0
        current.append(fragment)
        current_chars += size
    if current:
        groups.append(tuple(current))
    return tuple(groups)


def repository_unit_plan_receipt(
    root: str | Path,
    units: Sequence[Unit],
    facts_resolution: FactsResolutionReceipt,
    *,
    expected_owned_paths: tuple[str, ...],
) -> UnitPlanReceipt:
    """Project repository units into the shared observable planning schema."""
    base = Path(root)
    records: list[UnitPlanRecord] = []
    for unit in units:
        slices = _unit_source_slices(base, unit)
        if unit.kind == "source":
            source_chars = sum(source.end - source.start for source in slices)
            over_target = (
                (f"source chars exceed {_SETTINGS.max_source_chars_per_unit}",)
                if source_chars > _SETTINGS.max_source_chars_per_unit
                else ()
            )
        elif unit.kind == "focused":
            over_target = _repository_over_target(slices, unit)
        else:
            over_target = _repository_over_target(slices, unit)
        plan = unit.definition_plan
        definition_labels = tuple(f"definition:{seed.identity}" for seed in plan.seeds) if plan is not None else ()
        labels = tuple(dict.fromkeys((*unit.labels, *definition_labels)))
        records.append(
            UnitPlanRecord.create(
                kind=unit.kind,
                name=unit.name,
                labels=labels,
                owned_paths=unit.owned_paths,
                source_slices=slices,
                seed_ids=tuple(f"source:{path}" for path in unit.owned_paths),
                relationship_ids=tuple(relationship.identity for relationship in unit.relationships),
                unresolved_ids=unit.unresolved_identities,
                over_target_reasons=over_target,
            )
        )
    expected_paths = tuple(dict.fromkeys(expected_owned_paths))
    empty_paths = tuple(path for path in expected_paths if not _unit_source_text(base, path))
    _validate_repository_source_coverage(base, tuple(records), expected_paths, empty_paths)
    receipt = UnitPlanReceipt.create(
        facts_resolution=facts_resolution,
        units=tuple(records),
        expected_owned_paths=expected_paths,
        excluded_empty_paths=empty_paths,
        expected_seed_ids=tuple(f"source:{path}" for path in expected_paths if path not in empty_paths),
    )
    if receipt.unowned_paths or receipt.unowned_seed_ids:
        raise ValueError("repository unit planning left expected paths or seeds unowned")
    return receipt


def _validate_repository_source_coverage(
    root: Path,
    units: tuple[UnitPlanRecord, ...],
    expected_paths: tuple[str, ...],
    empty_paths: tuple[str, ...],
) -> None:
    """Require source and focused units to cover every nonempty input byte."""
    by_path: dict[str, list[tuple[int, int]]] = {}
    for unit in units:
        if unit.kind not in {"source", "focused"}:
            continue
        for source in unit.source_slices:
            by_path.setdefault(source.path, []).append((source.start, source.end))
    empty = set(empty_paths)
    for path in expected_paths:
        if path in empty:
            continue
        size = len(_unit_source_text(root, path))
        cursor = 0
        for start, end in sorted(by_path.get(path, ())):
            if start > cursor:
                raise ValueError(f"repository unit planning left source range {path}:{cursor}:{start} uncovered")
            cursor = max(cursor, end)
        if cursor < size:
            raise ValueError(f"repository unit planning left source range {path}:{cursor}:{size} uncovered")


def _unit_source_slices(root: Path, unit: Unit) -> tuple[UnitSourceSlice, ...]:
    if unit.fragments:
        for file, _start, end in unit.fragments:
            if end > len(_unit_source_text(root, file)):
                raise RepositorySourceError(f"unit {unit.name} fragment exceeds source {file}")
        return tuple(UnitSourceSlice(path=file, start=start, end=end) for file, start, end in unit.fragments)
    file = unit.files[0]
    text = _unit_source_text(root, file)
    start, end = unit.span or (0, len(text))
    return (UnitSourceSlice(path=file, start=start, end=end),) if end > start else ()


def _repository_over_target(
    slices: tuple[UnitSourceSlice, ...],
    unit: Unit,
) -> tuple[str, ...]:
    fragments = tuple(DefinitionFragment(source.path, source.path, source.start, source.end) for source in slices)
    reasons = []
    if definition_union_size(fragments) > _SETTINGS.target_gathered_source_chars_per_unit:
        reasons.append(f"source chars exceed {_SETTINGS.target_gathered_source_chars_per_unit}")
    relationship_chars = sum(len(relationship.identity) for relationship in unit.relationships) + sum(
        len(identity) for identity in unit.unresolved_identities
    )
    if relationship_chars > _SETTINGS.max_relationship_chars_per_unit:
        reasons.append(f"relationship chars exceed {_SETTINGS.max_relationship_chars_per_unit}")
    return tuple(reasons)
