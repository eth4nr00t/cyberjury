"""Build a language-independent source map and bounded review units."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from cyberjury.numbering import split_lines
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.relationships import DefinitionEvidence
from cyberjury.review.repository.context import Unit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.unit_plans import UnitPlanRecord, UnitSourceSlice

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
    for line in split_lines(text, keepends=True):
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


def char_spans(text: str) -> list[tuple[int, int]]:
    """The char windows that cover `text`.

    Text that fits one window is reviewed intact. Larger text is split at top-level construct
    boundaries so each class or function lands intact in one window. A single construct
    longer than a window is hard split with an overlap, so even then no boundary silently
    drops a construct's tail.
    """
    size = len(text)
    if size <= _SETTINGS.max_source_chars_per_unit:
        return [(0, size)]
    boundaries = construct_boundaries(text)
    spans: list[tuple[int, int]] = []
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
    definitions: tuple[DefinitionEvidence, ...],
) -> list[Unit]:
    """Cover every repository source file with windows bound to its exact definitions."""
    root = str(root)
    units: list[Unit] = []
    for source_file in dict.fromkeys(candidate_files):
        spans = char_spans(_unit_source_text(root, source_file))
        units.extend(
            Unit(
                name=source_file if len(spans) == 1 else f"{source_file}#{index}",
                root=root,
                file=source_file,
                span=span,
            )
            for index, span in enumerate(spans, 1)
        )
    return _bind_source_definition_plans(units, definitions)


def _bind_source_definition_plans(units: list[Unit], definitions: tuple[DefinitionEvidence, ...]) -> list[Unit]:
    by_file: dict[str, list[DefinitionEvidence]] = {}
    for definition in definitions:
        if definition.kind != "file":
            by_file.setdefault(definition.source.path, []).append(definition)
    assigned: dict[int, list[DefinitionEvidence]] = {}
    for file, file_definitions in by_file.items():
        candidates = [(index, unit) for index, unit in enumerate(units) if unit.file == file]
        for definition in file_definitions:
            ranked = [
                (overlap, -index, index)
                for index, unit in candidates
                if (overlap := _source_unit_overlap(unit, definition)) > 0
            ]
            if ranked:
                _overlap, _position, owner = max(ranked)
                assigned.setdefault(owner, []).append(definition)
    bound = []
    for index, unit in enumerate(units):
        seeds = tuple(
            sorted(
                assigned.get(index, ()),
                key=lambda value: (value.source.start, value.source.end, value.name),
            )
        )
        plan = DefinitionUnitPlan(seeds=seeds, seed_files=(unit.file,)) if seeds else None
        bound.append(replace(unit, definition_plan=plan))
    return bound


def _source_unit_overlap(unit: Unit, definition: DefinitionEvidence) -> int:
    start, end = unit.span
    return max(0, min(end, definition.source.end) - max(start, definition.source.start))


def repository_unit_plan_record(unit: Unit) -> UnitPlanRecord:
    """Project one repository unit into the shared observable planning schema."""
    return UnitPlanRecord.create(
        kind="source",
        name=unit.name,
        owned_paths=(unit.file,),
        source_slices=(UnitSourceSlice(path=unit.file, start=unit.span[0], end=unit.span[1]),),
    )
