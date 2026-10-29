"""Diff unit planning from changed definitions, packed into bounded review surfaces."""

from __future__ import annotations

from pathlib import Path

from cyberjury.numbering import line_span
from cyberjury.review.definitions import DefinitionUnitPlan, definitions_by_name
from cyberjury.review.diff.model import (
    ChangedLineRanges,
    DiffUnit,
    changed_line_ranges,
    chunk_path,
    diff_paths,
    pack_diff_chunks,
    split_diff_by_file,
)
from cyberjury.review.paths import read_repository_source
from cyberjury.review.relationships import DefinitionEvidence
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff


def build_diff_units(
    diff: str,
    *,
    root: Path,
    definitions: tuple[DefinitionEvidence, ...],
) -> list[DiffUnit]:
    """Plan diff units without reading or rendering their initial grounding."""
    paths = diff_paths(diff)
    chunks_by_path = {chunk_path(chunk): chunk for chunk in split_diff_by_file(diff)}
    ranges = changed_line_ranges(diff)
    seeds = changed_definitions(root, paths, ranges, definitions)
    plans = _pack_surface_plans(list(plan_definition_units(seeds)), chunks_by_path)
    covered = {seed.source.path for plan in plans for seed in plan.seeds}
    fallback_diff = "".join(chunks_by_path[path] for path in paths if path not in covered)
    fallback_batches = pack_diff_chunks(fallback_diff, _SETTINGS.target_patch_chars_per_unit)
    provisional: list[tuple[str, tuple[str, ...], DefinitionUnitPlan]] = []
    for plan in plans:
        unit_diff = "".join(chunks_by_path[path] for path in dict.fromkeys(seed.source.path for seed in plan.seeds))
        batches = pack_diff_chunks(unit_diff, _SETTINGS.target_patch_chars_per_unit)
        provisional.extend((batch, diff_paths(batch), plan) for batch in batches)
    provisional.extend(
        (batch, diff_paths(batch), DefinitionUnitPlan(seed_files=diff_paths(batch))) for batch in fallback_batches
    )
    return [
        DiffUnit(
            index=index,
            diff=unit_diff,
            paths=unit_paths,
            definition_plan=plan,
        )
        for index, (unit_diff, unit_paths, plan) in enumerate(provisional, 1)
    ]


def plan_definition_units(seeds: tuple[DefinitionEvidence, ...]) -> tuple[DefinitionUnitPlan, ...]:
    """Build one plan per seed file, in seed order, holding that file's seed definitions."""
    return tuple(
        DefinitionUnitPlan(seeds=tuple(seed for seed in seeds if seed.source.path == anchor), seed_files=(anchor,))
        for anchor in dict.fromkeys(seed.source.path for seed in seeds)
    )


def _merge_definition_unit_plans(
    left: DefinitionUnitPlan,
    right: DefinitionUnitPlan,
) -> DefinitionUnitPlan:
    return DefinitionUnitPlan(
        seeds=tuple(dict.fromkeys((*left.seeds, *right.seeds))),
        seed_files=tuple(dict.fromkeys((*left.seed_files, *right.seed_files))),
    )


def _pack_surface_plans(
    plans: list[DefinitionUnitPlan],
    chunks_by_path: dict[str, str],
) -> list[DefinitionUnitPlan]:
    packed: list[DefinitionUnitPlan] = []
    current: DefinitionUnitPlan | None = None
    for plan in plans:
        if current is None:
            current = plan
            continue
        candidate = _merge_definition_unit_plans(current, plan)
        patch_chars = sum(
            len(chunks_by_path[path]) for path in dict.fromkeys(seed.source.path for seed in candidate.seeds)
        )
        if (
            patch_chars > _SETTINGS.target_patch_chars_per_unit
            or len(candidate.seeds) > _SETTINGS.max_definition_evidence_items_per_unit
        ):
            packed.append(current)
            current = plan
        else:
            current = candidate
    if current is not None:
        packed.append(current)
    return packed


def changed_definitions(
    root: Path,
    paths: tuple[str, ...],
    ranges: ChangedLineRanges,
    definitions: tuple[DefinitionEvidence, ...],
) -> tuple[DefinitionEvidence, ...]:
    """Return exact definitions that contain a changed line."""
    defined = {definition.source.path for definition in definitions}
    sources = {
        path: read_repository_source(root, path, label="diff planning") or "" for path in paths if path in defined
    }
    changed: list[DefinitionEvidence] = []
    for definition in definitions_by_name(definitions):
        file, start, end = definition.source.path, definition.source.start, definition.source.end
        source = sources.get(file, "")
        if not source:
            continue
        start_line, end_line = line_span(source, start, end)
        if any(
            start_line <= changed_end and end_line >= changed_start
            for changed_start, changed_end in ranges.get(file, ())
        ):
            changed.append(definition)
    return tuple(changed)
