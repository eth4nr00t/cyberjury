"""Parse a unified diff into bounded, reviewable file batches."""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Literal

from cyberjury.detection import Detection
from cyberjury.review.context import GroundingContext
from cyberjury.review.definitions import (
    DefinitionFragment,
    DefinitionUnitPlan,
    FactsGraph,
    definition_fragments,
    definition_union_size,
    merge_definition_unit_plans,
    plan_definition_units,
)
from cyberjury.review.facts import FactsResolutionReceipt
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS, DiffReviewSettings
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff
_SOURCE_RENDERING_HEADROOM = 0.9
_QUOTED_GIT_HEADER_RE = re.compile(r'^diff --git "(?:\\.|[^"])*" ("(?:\\.|[^"])*")$')
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

type ChangedLineRanges = dict[str, tuple[tuple[int, int], ...]]


@dataclass(frozen=True, kw_only=True)
class DiffLineRanges:
    """Current hunk lines and exact changed lines on both patch sides."""

    current: ChangedLineRanges
    old: ChangedLineRanges
    new: ChangedLineRanges


@dataclass(frozen=True, kw_only=True)
class DiffUnit:
    """One diff batch and its reportable source paths."""

    index: int
    total: int
    diff: str
    paths: tuple[str, ...]
    id: str = ""
    definition_plan: DefinitionUnitPlan | None = None
    grounding: GroundingContext | None = None


@dataclass(frozen=True, kw_only=True)
class HunkLine:
    """One parsed unified-diff line with both side counters at that position."""

    kind: Literal["add", "delete", "context"]
    text: str
    old_line: int
    new_line: int


@dataclass(frozen=True, kw_only=True)
class ParsedHunk:
    """One hunk whose lines share a single validated counter progression."""

    old_start: int
    new_start: int
    lines: tuple[HunkLine, ...]


def split_diff_by_file(diff: str) -> list[str]:
    """Split a unified diff at file boundaries."""
    chunks: list[str] = []
    current: list[str] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git ") and current:
            chunks.append("".join(current))
            current = []
        current.append(line)
    if current:
        chunks.append("".join(current))
    return chunks or ([diff] if diff.strip() else [])


@cache
def _parsed_hunks(chunk: str) -> tuple[ParsedHunk, ...]:
    hunks: list[ParsedHunk] = []
    lines: list[HunkLine] | None = None
    old_start = new_start = old_line = new_line = 0
    for raw in chunk.splitlines():
        header = _HUNK_RE.match(raw)
        if raw.startswith("@@") and header is None:
            raise ValueError("diff review contains a malformed unified diff hunk header")
        if header:
            if lines is not None:
                hunks.append(ParsedHunk(old_start=old_start, new_start=new_start, lines=tuple(lines)))
            old_start = old_line = int(header.group(1))
            new_start = new_line = int(header.group(3))
            lines = []
            continue
        if lines is None:
            continue
        if raw.startswith("+"):
            lines.append(HunkLine(kind="add", text=raw[1:], old_line=old_line, new_line=new_line))
            new_line += 1
        elif raw.startswith("-"):
            lines.append(HunkLine(kind="delete", text=raw[1:], old_line=old_line, new_line=new_line))
            old_line += 1
        elif raw.startswith(" "):
            lines.append(HunkLine(kind="context", text=raw[1:], old_line=old_line, new_line=new_line))
            old_line += 1
            new_line += 1
        elif not raw.startswith("\\"):
            raise ValueError("diff review contains a malformed unified diff hunk body")
    if lines is not None:
        hunks.append(ParsedHunk(old_start=old_start, new_start=new_start, lines=tuple(lines)))
    return tuple(hunks)


def chunk_path(chunk: str) -> str:
    """Read the target path from one per-file diff chunk."""
    plus = minus = git = ""
    for line in chunk.splitlines():
        if line.startswith("+++ ") and not plus:
            plus = line[4:].strip()
        elif line.startswith("--- ") and not minus:
            minus = line[4:].strip()
        elif line.startswith("diff --git ") and not git:
            git = line
        if plus and minus and git:
            break
    for candidate in (plus, minus):
        if candidate and candidate != "/dev/null":
            return _decode_git_path(candidate)
    return _git_header_path(git)


def _git_header_path(header: str) -> str:
    quoted = _QUOTED_GIT_HEADER_RE.match(header)
    if quoted:
        return _decode_git_path(quoted.group(1))
    try:
        fields = shlex.split(header)
    except ValueError:
        fields = []
    if len(fields) == 4 and fields[:2] == ["diff", "--git"]:
        return _decode_git_path(fields[3])
    _, separator, tail = header.rpartition(" b/")
    return _decode_git_path(f"b/{tail}") if separator else ""


def _decode_git_path(raw: str) -> str:
    """Decode one Git header path and remove its side prefix."""
    value = raw.strip()
    if not value or value == "/dev/null":
        return ""
    if value.startswith('"'):
        try:
            decoded = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return ""
        if not isinstance(decoded, str):
            return ""
        try:
            value = decoded.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            value = decoded
    else:
        value = value.split("\t", 1)[0]
    return value[2:] if value[:2] in ("a/", "b/") else value


def _side_path(chunk: str, marker: str) -> str:
    prefix = f"{marker} "
    return next(
        (_decode_git_path(line[len(prefix) :]) for line in chunk.splitlines() if line.startswith(prefix)),
        "",
    )


def canonical_diff_path(path: str, available: Iterable[str]) -> str:
    """Match one reported path to a patch path, accepting a Git side prefix."""
    normalized = path.strip().replace("\\", "/").removeprefix("./")
    paths = set(available)
    if normalized in paths:
        return normalized
    stripped = normalized[2:] if normalized[:2] in ("a/", "b/") else normalized
    return stripped if stripped in paths else normalized


def diff_paths(diff: str) -> tuple[str, ...]:
    """Return every decoded target path represented by a diff."""
    return tuple(dict.fromkeys(path for chunk in split_diff_by_file(diff) if (path := chunk_path(chunk))))


def has_diff_hunk(diff: str) -> bool:
    """Return whether nonempty input contains a reportable unified diff hunk."""
    return any(_parsed_hunks(chunk) for chunk in split_diff_by_file(diff))


def batch_paths(batch: str) -> tuple[str, ...]:
    """Return every readable path represented by one diff batch."""
    paths = diff_paths(batch)
    return paths or ("<unknown>",)


def strip_unreviewable_files(diff: str, detection: Detection) -> tuple[str, tuple[str, ...]]:
    """Remove noise and test files before they consume review work."""
    kept: list[str] = []
    skipped: list[str] = []
    for chunk in split_diff_by_file(diff):
        path = chunk_path(chunk)
        binary_patch = any(line.startswith(("Binary files ", "GIT binary patch")) for line in chunk.splitlines())
        if path and (binary_patch or detection.is_noise_path(path)):
            skipped.append(path)
        else:
            kept.append(chunk)
    return "".join(kept), tuple(skipped)


def pack_diff_chunks(diff: str, max_chars: int = _SETTINGS.target_patch_chars_per_unit) -> list[str]:
    """Pack file and hunk chunks in source order under a soft line boundary."""
    if max_chars < 1:
        raise ValueError("diff unit size must be positive")
    chunks = [part for chunk in split_diff_by_file(diff) for part in _split_oversized_file_chunk(chunk, max_chars)]
    batches: list[str] = []
    current: list[str] = []
    current_size = 0

    def flush() -> None:
        nonlocal current, current_size
        if current:
            batches.append("".join(current))
            current = []
            current_size = 0

    for chunk in chunks:
        if current and current_size + len(chunk) > max_chars:
            flush()
        current.append(chunk)
        current_size += len(chunk)
    flush()
    return batches


def _split_oversized_file_chunk(chunk: str, max_chars: int) -> list[str]:
    if len(chunk) <= max_chars:
        return [chunk]
    lines = chunk.splitlines()
    first_hunk = next((index for index, line in enumerate(lines) if line.startswith("@@ ")), None)
    if first_hunk is None:
        return [chunk]
    header = "\n".join(lines[:first_hunk]) + "\n"
    parsed = _parsed_hunks(chunk)
    rendered_hunks = [part for hunk in parsed for part in _split_hunk(header, hunk, max_chars)]
    if not rendered_hunks:
        return [chunk]
    batches: list[str] = []
    current = header
    for hunk in rendered_hunks:
        if current != header and len(current) + len(hunk) > max_chars:
            batches.append(current)
            current = header
        current += hunk
    if current != header:
        batches.append(current)
    return batches


def _split_hunk(header: str, hunk: ParsedHunk, max_chars: int) -> list[str]:
    groups: list[tuple[int, int, tuple[HunkLine, ...]]] = []
    old_line = hunk.old_start
    new_line = hunk.new_start
    group_old = old_line
    group_new = new_line
    current: list[HunkLine] = []
    current_chars = 0
    header_headroom = len("@@ -0000000000,0000000000 +0000000000,0000000000 @@\n")
    available = max(1, max_chars - len(header) - header_headroom)
    for line in hunk.lines:
        rendered_chars = len(line.text) + 2
        if current and current_chars + rendered_chars > available:
            groups.append((group_old, group_new, tuple(current)))
            current = []
            current_chars = 0
            group_old = old_line
            group_new = new_line
        current.append(line)
        current_chars += rendered_chars
        if line.kind != "add":
            old_line += 1
        if line.kind != "delete":
            new_line += 1
    if current:
        groups.append((group_old, group_new, tuple(current)))
    return [_render_hunk(old_start, new_start, lines) for old_start, new_start, lines in groups]


def _render_hunk(old_start: int, new_start: int, lines: tuple[HunkLine, ...]) -> str:
    old_count = sum(line.kind != "add" for line in lines)
    new_count = sum(line.kind != "delete" for line in lines)
    prefixes = {"add": "+", "delete": "-", "context": " "}
    body = "".join(f"{prefixes[line.kind]}{line.text}\n" for line in lines)
    return f"@@ -{old_start},{old_count} +{new_start},{new_count} @@\n{body}"


def changed_paths(diff: str, detection: Detection) -> tuple[str, ...]:
    """Return changed source paths after profile noise filters."""
    seen: dict[str, None] = {}
    for path in diff_paths(diff):
        if detection.is_noise_path(path):
            continue
        if Path(path).suffix.lower() not in detection.source_extensions:
            continue
        seen.setdefault(path, None)
    return tuple(seen)


def reviewable_changed_paths(diff: str, detection: Detection) -> tuple[str, ...]:
    """Return every changed path retained by the profile noise boundary."""
    return tuple(path for path in diff_paths(diff) if not detection.is_noise_path(path))


def changed_line_ranges(diff: str, detection: Detection) -> ChangedLineRanges:
    """Return current definition anchors for additions, replacements, and deletions."""
    anchors: dict[str, list[tuple[int, int]]] = {
        path: list(ranges)
        for path, ranges in diff_line_ranges(diff, detection).new.items()
        if Path(path).suffix.lower() in detection.source_extensions
    }
    for chunk in split_diff_by_file(diff):
        path = chunk_path(chunk)
        if not path or detection.is_noise_path(path) or Path(path).suffix.lower() not in detection.source_extensions:
            continue
        for hunk in _parsed_hunks(chunk):
            pending_deletions: list[int] = []
            for line in hunk.lines:
                if line.kind == "delete":
                    pending_deletions.append(line.new_line)
                elif line.kind == "add":
                    pending_deletions.clear()
                else:
                    _flush_deletion_anchors(anchors, path, pending_deletions)
            _flush_deletion_anchors(anchors, path, pending_deletions)
    return {path: tuple(_merge_ranges(ranges)) for path, ranges in anchors.items()}


def _flush_deletion_anchors(
    anchors: dict[str, list[tuple[int, int]]],
    path: str,
    pending: list[int],
) -> None:
    for line_number in pending:
        anchors.setdefault(path, []).extend(
            (
                (max(1, line_number - 1), max(1, line_number - 1)),
                (line_number, line_number),
            )
        )
    pending.clear()


def _append_line(output: dict[str, list[tuple[int, int]]], path: str, line: int, detection: Detection) -> None:
    if path and not detection.is_noise_path(path):
        output.setdefault(path, []).append((line, line))


def diff_line_ranges(diff: str, detection: Detection) -> DiffLineRanges:
    """Return post change hunk lines and exact old and new change anchors."""
    current: dict[str, list[tuple[int, int]]] = {}
    old: dict[str, list[tuple[int, int]]] = {}
    new: dict[str, list[tuple[int, int]]] = {}
    for chunk in split_diff_by_file(diff):
        fallback = chunk_path(chunk)
        old_path = _side_path(chunk, "---") or fallback
        new_path = _side_path(chunk, "+++") or fallback
        for hunk in _parsed_hunks(chunk):
            for line in hunk.lines:
                if line.kind == "add":
                    _append_line(new, new_path, line.new_line, detection)
                    _append_line(current, new_path, line.new_line, detection)
                elif line.kind == "context":
                    _append_line(current, new_path, line.new_line, detection)
                else:
                    _append_line(old, old_path, line.old_line, detection)
    return DiffLineRanges(
        current={path: tuple(_merge_ranges(ranges)) for path, ranges in current.items()},
        old={path: tuple(_merge_ranges(ranges)) for path, ranges in old.items()},
        new={path: tuple(_merge_ranges(ranges)) for path, ranges in new.items()},
    )


def prepare_diff_units(
    diff: str,
    *,
    root: Path,
    detection: Detection,
    graph: FactsGraph,
    settings: DiffReviewSettings = _SETTINGS,
) -> list[DiffUnit]:
    """Plan diff units without reading or rendering their initial grounding."""
    if not diff.strip():
        return []
    chunks = split_diff_by_file(diff)
    paths = batch_paths(diff)
    chunks_by_path: dict[str, str] = {}
    for chunk in chunks:
        path = chunk_path(chunk)
        if not path:
            raise ValueError("diff review contains a file section without a source path")
        if path in chunks_by_path:
            raise ValueError(f"diff review contains repeated file sections for {path}")
        chunks_by_path[path] = chunk
    ranges = changed_line_ranges(diff, detection)
    seeds = changed_definition_fragments(root, paths, ranges, graph)
    plans = _pack_surface_plans(list(plan_definition_units(seeds, seed_files=paths)), chunks_by_path, settings)
    covered = {
        file
        for plan in plans
        for file in (
            *(seed.file for seed in plan.seeds),
            *plan.seed_files,
        )
    }
    fallback_diff = "".join(chunks_by_path[path] for path in paths if path not in covered)
    fallback_batches = pack_diff_chunks(fallback_diff, settings.target_patch_chars_per_unit)
    provisional: list[tuple[str, tuple[str, ...], DefinitionUnitPlan]] = []
    for plan in plans:
        unit_paths = tuple(
            dict.fromkeys(
                file
                for file in (
                    *(seed.file for seed in plan.seeds),
                    *plan.seed_files,
                )
                if file in chunks_by_path
            )
        )
        unit_diff = "".join(chunks_by_path[path] for path in unit_paths)
        if unit_diff:
            batches = (
                pack_diff_chunks(unit_diff, settings.target_patch_chars_per_unit)
                if len(unit_paths) == 1
                else [unit_diff]
            )
            provisional.extend((batch, batch_paths(batch), plan) for batch in batches)
    provisional.extend(
        (batch, batch_paths(batch), DefinitionUnitPlan(seed_files=batch_paths(batch))) for batch in fallback_batches
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


def diff_unit_plan_receipt(
    units: list[DiffUnit],
    facts_resolution: FactsResolutionReceipt,
    *,
    expected_owned_paths: tuple[str, ...],
    settings: DiffReviewSettings = _SETTINGS,
) -> UnitPlanReceipt:
    """Project diff units into the shared observable planning schema."""
    records: list[UnitPlanRecord] = []
    for unit in units:
        plan = unit.definition_plan or DefinitionUnitPlan(seed_files=unit.paths)
        source_fragments = tuple(dict.fromkeys((*plan.seeds, *plan.fragments)))
        slices = tuple(
            UnitSourceSlice(path=fragment.file, start=fragment.start, end=fragment.end) for fragment in source_fragments
        )
        seed_ids = tuple(f"patch:{path}" for path in unit.paths)
        secondary = tuple(fragment for fragment in plan.fragments if fragment not in plan.seeds)
        over_target = []
        if len(unit.diff) > settings.target_patch_chars_per_unit:
            over_target.append(f"patch chars exceed {settings.target_patch_chars_per_unit}")
        if definition_union_size(secondary) > settings.target_repository_context_chars_per_unit:
            over_target.append(f"source chars exceed {settings.target_repository_context_chars_per_unit}")
        records.append(
            UnitPlanRecord.create(
                kind="diff",
                name=f"diff:{unit.index}:{','.join(unit.paths)}",
                labels=tuple(f"definition:{seed.identity}" for seed in plan.seeds),
                owned_paths=unit.paths,
                source_slices=slices,
                seed_ids=seed_ids,
                patch_text=unit.diff,
                over_target_reasons=tuple(over_target),
            )
        )
    receipt = UnitPlanReceipt.create(
        facts_resolution=facts_resolution,
        units=tuple(records),
        expected_owned_paths=expected_owned_paths,
        expected_seed_ids=tuple(f"patch:{path}" for path in expected_owned_paths),
    )
    if receipt.unowned_paths or receipt.unowned_seed_ids:
        raise ValueError("diff unit planning left expected paths or seeds unowned")
    return receipt


def _pack_surface_plans(
    plans: list[DefinitionUnitPlan],
    chunks_by_path: dict[str, str],
    settings: DiffReviewSettings,
) -> list[DefinitionUnitPlan]:
    packed: list[DefinitionUnitPlan] = []
    current: DefinitionUnitPlan | None = None
    context_target = int(settings.target_repository_context_chars_per_unit * _SOURCE_RENDERING_HEADROOM)
    for plan in plans:
        if current is None:
            current = plan
            continue
        candidate = merge_definition_unit_plans(current, plan)
        candidate_paths = tuple(dict.fromkeys((*(seed.file for seed in candidate.seeds), *candidate.seed_files)))
        patch_chars = sum(len(chunks_by_path.get(path, "")) for path in candidate_paths)
        secondary_fragments = tuple(fragment for fragment in candidate.fragments if fragment not in candidate.seeds)
        evidence_chars = definition_union_size(secondary_fragments)
        if (
            patch_chars > settings.target_patch_chars_per_unit
            or evidence_chars > context_target
            or len(candidate.fragments) > settings.max_definition_evidence_items_per_unit
        ):
            packed.append(current)
            current = plan
        else:
            current = candidate
    if current is not None:
        packed.append(current)
    return packed


def changed_definition_fragments(
    root: Path,
    paths: tuple[str, ...],
    ranges: ChangedLineRanges,
    graph: FactsGraph,
) -> tuple[DefinitionFragment, ...]:
    """Return exact definitions that contain a changed line."""
    wanted = set(paths)
    sources = {path: _source_for_planning(root, path) for path in paths}
    candidates: list[tuple[DefinitionFragment, int, int]] = []
    for fragments in definition_fragments(graph).values():
        for fragment in fragments:
            if fragment.file not in wanted:
                continue
            source = sources.get(fragment.file, "")
            if not source:
                continue
            start_line = source[: fragment.start].count("\n") + 1
            end_line = source[: max(fragment.start, fragment.end - 1)].count("\n") + 1
            if any(
                start_line <= changed_end and end_line >= changed_start
                for changed_start, changed_end in ranges.get(fragment.file, ())
            ):
                candidates.append((fragment, start_line, end_line))
    return tuple(dict.fromkeys(fragment for fragment, _start_line, _end_line in candidates))


def _source_for_planning(root: Path, rel: str) -> str:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return ""


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
