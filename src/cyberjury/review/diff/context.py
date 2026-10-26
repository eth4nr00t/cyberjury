"""Plan diff units and ground each one in repository source and facts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from cyberjury.numbering import split_lines
from cyberjury.review.context import (
    GroundingContext,
    SourceEvidence,
    definition_plan_source_files,
    delivered_source_block,
    files_without_seed_definitions,
    numbered_source_range,
    publish_evidence,
    source_id,
    syntax_hints,
    with_scoped_fact_limitations,
)
from cyberjury.review.diff.model import (
    ChangedLineRanges,
    DiffUnit,
    changed_line_ranges,
    diff_paths,
    diff_unit_plan_record,
    reviewable_changed_paths,
)
from cyberjury.review.diff.planning import prepare_diff_units
from cyberjury.review.diff.prompts import diff_seed
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.paths import read_repository_source
from cyberjury.review.prepare import ReviewPlan, SharedGrounding
from cyberjury.review.prompts import one_line_source
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.result import SkippedFile
from cyberjury.review.seed_sources import CandidateCallContext, candidate_call_context, definition_evidence
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS, ReviewExecutionSettings

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff
_EXECUTION = DEFAULT_REVIEW_SETTINGS.execution


def plan_diff_units(diff: str, shared: SharedGrounding, skipped: tuple[SkippedFile, ...]) -> ReviewPlan[DiffUnit]:
    """Plan deterministic diff units that together own every reviewable changed path."""
    units = prepare_diff_units(
        diff,
        root=shared.root,
        detection=shared.detection,
        definitions=shared.facts.relationships.definitions,
        settings=_SETTINGS,
    )
    return ReviewPlan(
        units=units,
        records=tuple(diff_unit_plan_record(unit) for unit in units),
        expected_owned_paths=diff_paths(diff),
        skipped_files=skipped,
    )


def ground_diff_unit(
    unit: DiffUnit,
    shared: SharedGrounding,
    *,
    execution: ReviewExecutionSettings = _EXECUTION,
) -> GroundingContext:
    """Bind one planned diff unit to its exact initial evidence envelope."""
    diff, definition_plan = unit.diff, unit.definition_plan
    root = shared.root
    relationships = shared.facts.relationships
    paths = reviewable_changed_paths(diff, shared.detection)
    seed = diff_seed(diff)
    if not paths:
        return GroundingContext(text="", seed=seed, files=())
    ranges = changed_line_ranges(diff, shared.detection)
    evidence = definition_evidence(root, definition_plan)
    candidate = (
        candidate_call_context(
            root,
            definition_plan,
            relationships,
            max_chars=min(
                _SETTINGS.max_relationship_chars_per_unit,
                _SETTINGS.target_repository_context_chars_per_unit,
            ),
            callsite_ids=_callsite_ids_in_ranges(root, relationships, ranges),
            catalog=evidence,
            deliver_chars=execution.max_initial_candidate_source_chars,
        )
        if definition_plan.seeds
        else CandidateCallContext()
    )
    notices, windows = changed_file_sources(
        root,
        files_without_seed_definitions(definition_plan, paths),
        ranges,
        budget=max(0, _SETTINGS.target_repository_context_chars_per_unit - len(candidate.text)),
    )
    text = "\n\n".join(part for part in (notices, candidate.text) if part)
    delivered = (*candidate.delivered, *windows)
    files = tuple(dict.fromkeys(item.source_span.file for item in windows))
    context = GroundingContext(
        text=text,
        seed=seed,
        files=files,
        evidence=publish_evidence(evidence, candidate.published),
        source_evidence=delivered,
        syntax_hints=syntax_hints(
            definition_plan,
            paths,
            shared.facts.by_file,
            max_chars_per_file=execution.max_syntax_hint_chars_per_file,
        ),
        navigator=shared.navigator,
        source_snapshot=shared.snapshot,
    )
    planned_scope_files = tuple(
        dict.fromkeys((*files, *definition_plan_source_files(definition_plan), *candidate.source_files))
    )
    snapshot_files = set(shared.snapshot.files)
    scope_files = tuple(file for file in planned_scope_files if file in snapshot_files)
    context = replace(context, snapshot_files=scope_files)
    return with_scoped_fact_limitations(context, shared.facts.limitations, source_files=scope_files)


def changed_file_sources(
    root: Path,
    paths: tuple[str, ...],
    ranges: ChangedLineRanges,
    *,
    budget: int = _SETTINGS.target_repository_context_chars_per_unit,
) -> tuple[str, tuple[SourceEvidence, ...]]:
    """Deliver bounded current source of changed files without seed definitions, centered on their changed lines."""
    sources = [
        (rel, source)
        for rel in paths
        if (source := read_repository_source(root, rel, label="diff context")) is not None
    ]
    if not sources or budget < 1:
        return "", ()
    share = max(1, (budget - 2 * (len(sources) - 1)) // len(sources))
    notices: list[str] = []
    delivered: list[SourceEvidence] = []
    for rel, source in sources:
        lines = split_lines(source, keepends=True)
        changed = ranges.get(rel, ())
        notices.extend(
            f"{one_line_source(rel)}: changed lines {start}-{end} are outside current source length {len(lines)}."
            for start, end in changed
            if start > len(lines) + 1
        )
        remaining = share
        for first, last in _source_windows(lines, changed):
            evidence = _fitting_window(rel, source, lines, first, last, remaining)
            if evidence is None:
                break
            delivered.append(evidence)
            remaining -= len(delivered_source_block(evidence)) + 2
            if evidence.source_span.end_line < last:
                break
    return "\n".join(notices), tuple(delivered)


def _leading_lines(lines: list[str], max_chars: int) -> int:
    used = 0
    for number, line in enumerate(lines, 1):
        used += len(line)
        if used > max_chars:
            return number - 1
    return len(lines)


def _source_windows(lines: list[str], changed: tuple[tuple[int, int], ...]) -> list[tuple[int, int]]:
    if not lines:
        return []
    if not changed:
        last = _leading_lines(lines, _SETTINGS.max_full_source_chars_per_context_file)
        return [(1, last)] if last else []
    context = _SETTINGS.hunk_context_lines_per_side
    windows = [
        (max(1, start - context), min(len(lines), end + context)) for start, end in changed if start <= len(lines) + 1
    ]
    prefix = _leading_lines(lines, _SETTINGS.max_changed_source_prefix_chars)
    merged: list[tuple[int, int]] = []
    for first, last in sorted(window for window in (*windows, (1, prefix)) if window[0] <= window[1]):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return sorted(merged, key=lambda window: not any(window[0] <= end and start <= window[1] for start, end in changed))


def _fitting_window(
    rel: str,
    source: str,
    lines: list[str],
    first: int,
    last: int,
    budget: int,
) -> SourceEvidence | None:
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def window(end_line: int) -> SourceEvidence:
        start, end = offsets[first - 1], offsets[end_line]
        identity = f"{rel}:lines {first}-{end_line}:{start}:{end}"
        text, span = numbered_source_range(rel, source, start, end)
        return SourceEvidence(id=source_id(identity), identity=identity, text=text, source_span=span)

    def fits(end_line: int) -> bool:
        return len(delivered_source_block(window(end_line))) + 2 <= budget

    if fits(last):
        return window(last)
    if not fits(first):
        return None
    low, high = first, last
    while low < high:
        middle = (low + high + 1) // 2
        if fits(middle):
            low = middle
        else:
            high = middle - 1
    return window(low)


def _callsite_ids_in_ranges(
    root: Path,
    relationships: RelationshipEvidenceBundle,
    ranges: ChangedLineRanges,
) -> frozenset[str]:
    sources: dict[str, str] = {}
    selected = set()
    for callsite in relationships.callsites:
        file_ranges = ranges.get(callsite.source.path, ())
        if not file_ranges:
            continue
        source = sources.get(callsite.source.path)
        if source is None:
            source = _read_source(root, callsite.source.path)
            sources[callsite.source.path] = source
        start_line = source.count("\n", 0, callsite.source.start) + 1
        end_line = source.count("\n", 0, max(callsite.source.start, callsite.source.end - 1)) + 1
        if any(start_line <= end and start <= end_line for start, end in file_ranges):
            selected.add(callsite.id)
    return frozenset(selected)


def _read_source(root: Path, rel: str) -> str:
    source = read_repository_source(root, rel, label="relationship")
    if source is None:
        raise BackendUnavailable(f"relationship source {rel} is missing")
    return source
