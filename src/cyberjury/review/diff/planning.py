"""Plan diff units from changed definitions and pack them into bounded review surfaces."""

from __future__ import annotations

from pathlib import Path

from cyberjury.review.definitions import DefinitionUnitPlan, definitions_by_name
from cyberjury.review.detection import Detection
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
    detection: Detection,
    definitions: tuple[DefinitionEvidence, ...],
) -> list[DiffUnit]:
    """Plan diff units without reading or rendering their initial grounding."""
    if not diff.strip():
        return []
    paths = diff_paths(diff)
    chunks_by_path = {chunk_path(chunk): chunk for chunk in split_diff_by_file(diff)}
    ranges = changed_line_ranges(diff, detection)
    seeds = changed_definitions(root, paths, ranges, definitions)
    plans = _pack_surface_plans(list(plan_definition_units(seeds, seed_files=paths)), chunks_by_path)
    covered = {
        file
        for plan in plans
        for file in (
            *(seed.source.path for seed in plan.seeds),
            *plan.seed_files,
        )
    }
    fallback_diff = "".join(chunks_by_path[path] for path in paths if path not in covered)
    fallback_batches = pack_diff_chunks(fallback_diff, _SETTINGS.target_patch_chars_per_unit)
    provisional: list[tuple[str, tuple[str, ...], DefinitionUnitPlan]] = []
    for plan in plans:
        unit_paths = tuple(
            dict.fromkeys(
                file
                for file in (
                    *(seed.source.path for seed in plan.seeds),
                    *plan.seed_files,
                )
                if file in chunks_by_path
            )
        )
        unit_diff = "".join(chunks_by_path[path] for path in unit_paths)
        if unit_diff:
            batches = (
                pack_diff_chunks(unit_diff, _SETTINGS.target_patch_chars_per_unit)
                if len(unit_paths) == 1
                else [unit_diff]
            )
            provisional.extend((batch, diff_paths(batch), plan) for batch in batches)
    provisional.extend(
        (batch, diff_paths(batch), DefinitionUnitPlan(seed_files=diff_paths(batch))) for batch in fallback_batches
    )
    total = len(provisional)
    return [
        DiffUnit(
            index=index,
            total=total,
            diff=unit_diff,
            paths=unit_paths,
            definition_plan=plan,
        )
        for index, (unit_diff, unit_paths, plan) in enumerate(provisional, 1)
    ]


def plan_definition_units(
    seeds: tuple[DefinitionEvidence, ...],
    *,
    seed_files: tuple[str, ...],
) -> tuple[DefinitionUnitPlan, ...]:
    """Build one plan per seed file, in seed order, holding that file's seed definitions."""
    plans = []
    for anchor in dict.fromkeys(seed.source.path for seed in seeds):
        anchor_seeds = tuple(seed for seed in seeds if seed.source.path == anchor)
        plans.append(
            DefinitionUnitPlan(
                seeds=anchor_seeds,
                seed_files=(anchor,) if anchor in seed_files else (),
            )
        )
    return tuple(plans)


def merge_definition_unit_plans(
    left: DefinitionUnitPlan,
    right: DefinitionUnitPlan,
) -> DefinitionUnitPlan:
    """Merge independent review surfaces without losing seed or receipt identity."""
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
        candidate = merge_definition_unit_plans(current, plan)
        candidate_paths = tuple(dict.fromkeys((*(seed.source.path for seed in candidate.seeds), *candidate.seed_files)))
        patch_chars = sum(len(chunks_by_path.get(path, "")) for path in candidate_paths)
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
        start_line = source[:start].count("\n") + 1
        end_line = source[: max(start, end - 1)].count("\n") + 1
        if any(
            start_line <= changed_end and end_line >= changed_start
            for changed_start, changed_end in ranges.get(file, ())
        ):
            changed.append(definition)
    return tuple(changed)
