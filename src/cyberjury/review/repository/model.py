"""The language-independent source map and bounded repository units."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from cyberjury.numbering import split_lines
from cyberjury.review.context import GroundingContext
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.relationships import DefinitionEvidence
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.unit_plans import UnitPlanRecord, UnitSourceSlice

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


@dataclass(frozen=True, kw_only=True)
class RepositoryUnit:
    """One unit of the worklist: one source file, or one char span of it."""

    name: str
    root: str
    file: str
    span: tuple[int, int]
    id: str = ""
    definition_plan: DefinitionUnitPlan | None = None
    grounding: GroundingContext | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        """Return the one source path this unit reviews."""
        return (self.file,)


def construct_boundaries(text: str) -> list[int]:
    """Find lexical window candidates at unindented source lines."""
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
    """Split text into bounded windows at top-level boundaries, overlapping hard splits."""
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


def build_units(
    root: str | Path,
    candidate_files: Sequence[str],
    definitions: tuple[DefinitionEvidence, ...],
) -> list[RepositoryUnit]:
    """Cover every repository source file with windows bound to its exact definitions."""
    root = str(root)
    units: list[RepositoryUnit] = []
    for source_file in dict.fromkeys(candidate_files):
        spans = char_spans((Path(root) / source_file).read_text(encoding="utf-8"))
        units.extend(
            RepositoryUnit(
                name=source_file if len(spans) == 1 else f"{source_file}#{index}",
                root=root,
                file=source_file,
                span=span,
            )
            for index, span in enumerate(spans, 1)
        )
    return _bind_source_definition_plans(units, definitions)


def _bind_source_definition_plans(
    units: list[RepositoryUnit], definitions: tuple[DefinitionEvidence, ...]
) -> list[RepositoryUnit]:
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


def _source_unit_overlap(unit: RepositoryUnit, definition: DefinitionEvidence) -> int:
    start, end = unit.span
    return max(0, min(end, definition.source.end) - max(start, definition.source.start))


def repository_unit_plan_record(unit: RepositoryUnit) -> UnitPlanRecord:
    """Project one repository unit into the shared observable planning schema."""
    return UnitPlanRecord.create(
        kind="source",
        name=unit.name,
        owned_paths=(unit.file,),
        source_slices=(UnitSourceSlice(path=unit.file, start=unit.span[0], end=unit.span[1]),),
    )
