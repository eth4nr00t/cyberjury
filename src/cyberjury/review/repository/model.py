"""Build a language-independent source map and bounded review units."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from cyberjury.review.definitions import DefinitionFragment, DefinitionUnitPlan, definition_fragments
from cyberjury.review.facts import FactsResolutionReceipt
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.repository.context import Unit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


class RepositorySourceError(RuntimeError):
    """A source required for deterministic worklist discovery is unavailable."""


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
    silently drops a construct's tail.
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


def build_units(
    root: str | Path,
    candidate_files: Sequence[str],
    facts_graph: dict[str, object] | None = None,
) -> list[Unit]:
    """Cover every repository seed file with source windows bound to its exact definitions."""
    root = str(root)
    source_files = tuple(dict.fromkeys(candidate_files))
    units = _bind_source_definition_plans(_source_units(root, source_files), facts_graph)
    for unit in units:
        _unit_source_slices(Path(root), unit)
    names = [unit.name for unit in units]
    if len(names) != len(set(names)):
        raise ValueError("repository unit names must be unique")
    return units


def _bind_source_definition_plans(units: list[Unit], graph: dict[str, object] | None) -> list[Unit]:
    """Bind source windows to exact definitions without creating duplicate review work."""
    by_file: dict[str, list[DefinitionFragment]] = {}
    for fragments in definition_fragments(graph or {}).values():
        for fragment in fragments:
            if fragment.name != "<file>":
                by_file.setdefault(fragment.file, []).append(fragment)
    assigned: dict[int, list[DefinitionFragment]] = {}
    for file, fragments in by_file.items():
        candidates = [(index, unit) for index, unit in enumerate(units) if unit.files == (file,)]
        for fragment in fragments:
            ranked = [
                (_source_unit_overlap(unit, fragment), -index, index)
                for index, unit in candidates
                if _source_unit_overlap(unit, fragment) > 0
            ]
            if ranked:
                _overlap, _position, owner = max(ranked)
                assigned.setdefault(owner, []).append(fragment)
    bound = []
    for index, unit in enumerate(units):
        seeds = tuple(sorted(assigned.get(index, ()), key=lambda value: (value.start, value.end, value.name)))
        plan = DefinitionUnitPlan(seeds=seeds, seed_files=(unit.files[0],)) if seeds else None
        bound.append(replace(unit, definition_plan=plan))
    return bound


def _source_unit_overlap(unit: Unit, fragment: DefinitionFragment) -> int:
    """Measure exact source overlap for deterministic single unit ownership."""
    if unit.files[0] != fragment.file:
        return 0
    start, end = unit.span or (0, fragment.end)
    return max(0, min(end, fragment.end) - max(start, fragment.start))


def _source_units(root: str, source_files: tuple[str, ...]) -> list[Unit]:
    units: list[Unit] = []
    for source_file in source_files:
        text = _unit_source_text(root, source_file)
        if not text:
            continue
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
    return units


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
        source_chars = sum(source.end - source.start for source in slices)
        over_target = (
            (f"source chars exceed {_SETTINGS.max_source_chars_per_unit}",)
            if source_chars > _SETTINGS.max_source_chars_per_unit
            else ()
        )
        plan = unit.definition_plan
        labels = tuple(f"definition:{seed.identity}" for seed in plan.seeds) if plan is not None else ()
        records.append(
            UnitPlanRecord.create(
                kind="source",
                name=unit.name,
                labels=labels,
                owned_paths=unit.owned_paths,
                source_slices=slices,
                seed_ids=tuple(f"source:{path}" for path in unit.owned_paths),
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
    """Require source units to cover every nonempty input byte."""
    by_path: dict[str, list[tuple[int, int]]] = {}
    for unit in units:
        if unit.kind != "source":
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
    file = unit.files[0]
    text = _unit_source_text(root, file)
    start, end = unit.span or (0, len(text))
    return (UnitSourceSlice(path=file, start=start, end=end),) if end > start else ()
