"""Parse a unified diff into bounded, reviewable file batches."""

from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.review.context import GroundingContext
from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    DefinitionUnitPlan,
    FactsGraph,
    definition_fragments,
    definition_references,
    definition_union_size,
    merge_definition_unit_plans,
    plan_definition_units,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS, DiffReviewSettings

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff
_SOURCE_RENDERING_HEADROOM = 0.9
_CALL_NAME_TAIL = _SETTINGS.min_call_name_chars - 1
_CALL_LIKE_NAME = re.compile(rf"\b([A-Za-z_$][A-Za-z0-9_$]{{{_CALL_NAME_TAIL},}})\s*\(")
_CALLABLE_ASSIGNMENT_NAME = re.compile(rf"\b([A-Za-z_$][A-Za-z0-9_$]{{{_CALL_NAME_TAIL},}})\s*=\s*(?:async\s*)?\(")
_DEF_PATTERNS = (
    re.compile(r"\b(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("),
    re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"),
    re.compile(r"\b(?:function|modifier)\s+([A-Za-z_]\w*)\s*\("),
    re.compile(r"\b(?:constructor|fallback|receive)\s*\("),
    re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*\{"),
)
_CALL_RE = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]{4,})\s*\(")
_CONTROL_NAMES = {"catch", "else", "for", "if", "return", "switch", "while"}
_QUOTED_GIT_HEADER_RE = re.compile(r'^diff --git "(?:\\.|[^"])*" ("(?:\\.|[^"])*")$')
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

type ChangedLineRanges = dict[str, tuple[tuple[int, int], ...]]
type ReviewNamesByPath = dict[str, frozenset[str]]


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
    definition_plan: DefinitionUnitPlan | None = None
    grounding: GroundingContext | None = None


@dataclass(frozen=True, kw_only=True)
class PatchFile:
    """Changed symbols and calls extracted from one patch file."""

    path: str
    definitions: tuple[str, ...]
    calls: tuple[str, ...]


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


def diff_paths(diff: str) -> tuple[str, ...]:
    """Return every decoded target path represented by a diff."""
    return tuple(dict.fromkeys(path for chunk in split_diff_by_file(diff) if (path := chunk_path(chunk))))


def batch_paths(batch: str) -> tuple[str, ...]:
    """Return every readable path represented by one diff batch."""
    paths = diff_paths(batch)
    return paths or ("<unknown>",)


def strip_unreviewable_files(diff: str, detection: Detection | None = None) -> tuple[str, tuple[str, ...]]:
    """Remove noise and test files before they consume review work."""
    configured = detection or load_detection()
    kept: list[str] = []
    skipped: list[str] = []
    for chunk in split_diff_by_file(diff):
        path = chunk_path(chunk)
        if path and (configured.is_noise_path(path) or configured.is_test_path(path)):
            skipped.append(path)
        else:
            kept.append(chunk)
    return "".join(kept), tuple(skipped)


def pack_diff_chunks(diff: str, max_chars: int = _SETTINGS.target_patch_chars_per_unit) -> list[str]:
    """Pack per-file chunks in source order without splitting one file mid hunk."""
    chunks = split_diff_by_file(diff)
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


def diff_units(diff: str) -> list[DiffUnit]:
    """Build the complete ordered worklist for one diff review."""
    max_chars = _SETTINGS.target_patch_chars_per_unit
    batches = pack_diff_chunks(diff, max_chars) if len(diff) > max_chars else [diff]
    return [
        DiffUnit(index=index, total=len(batches), diff=batch, paths=batch_paths(batch))
        for index, batch in enumerate(batches, 1)
    ]


def changed_paths(diff: str, detection: Detection | None = None) -> tuple[str, ...]:
    """Return changed source paths after profile noise filters."""
    configured = detection or load_detection()
    seen: dict[str, None] = {}
    for path in diff_paths(diff):
        if configured.is_noise_path(path):
            continue
        if Path(path).suffix.lower() not in configured.source_extensions:
            continue
        seen.setdefault(path, None)
    return tuple(seen)


def patch_files(diff: str, detection: Detection | None = None) -> tuple[PatchFile, ...]:
    """Extract changed definitions and calls without reading a repository."""
    files: list[PatchFile] = []
    for chunk in split_diff_by_file(diff):
        path = chunk_path(chunk)
        active = _active_lines(chunk)
        is_source = detection is None or Path(path).suffix.lower() in detection.source_extensions
        definitions = _definitions(active) if is_source else set()
        calls = tuple(sorted(_calls(active).difference(definitions))) if is_source else ()
        files.append(
            PatchFile(
                path=path or "<unknown>",
                definitions=tuple(sorted(definitions)),
                calls=calls,
            )
        )
    return tuple(files)


def diff_local_context(
    diff: str,
    *,
    max_chars: int = _SETTINGS.max_diff_grounding_chars_per_review,
    detection: Detection | None = None,
) -> str:
    """Render only patch-visible symbols and relationships as model context."""
    files = patch_files(diff, detection)
    if not files:
        return ""
    definitions = {name for item in files for name in item.definitions}
    edges: list[tuple[str, str]] = []
    for item in files:
        for name in item.calls:
            targets = [target for target in files if name in target.definitions and target.path != item.path]
            edges.extend((item.path, f"{target.path}:{name}") for target in targets)
    lines = [
        "Patch-local grounding, extracted only from the changed text:",
        "Use these relationships to trace the patch. No unchanged repository code is included.",
    ]
    if edges:
        lines.append("Patch-visible call relationships:")
        lines.extend(f"- {source_path} uses {target}" for source_path, target in sorted(set(edges)))
        edge_paths = {path for edge in edges for path in (edge[0], edge[1].rsplit(":", 1)[0])}
        lines.extend(
            f"- {item.path}: changed definitions {', '.join(item.definitions)}"
            for item in files
            if item.path in edge_paths and item.definitions
        )
    else:
        lines.extend(
            f"- {item.path}: changed definitions {', '.join(item.definitions)}" for item in files if item.definitions
        )
    if not edges and definitions:
        lines.append("No cross-file call relationship is visible in the changed text.")
    text = "\n".join(lines)
    return text if len(text) <= max_chars else text[: max_chars - 32] + "\n... [grounding truncated]"


def _active_lines(chunk: str) -> str:
    return "\n".join(
        line[1:] for line in chunk.splitlines() if line.startswith(("+", " ")) and not line.startswith(("+++", "---"))
    )


def _definitions(text: str) -> set[str]:
    names: set[str] = set()
    for pattern in _DEF_PATTERNS:
        for match in pattern.finditer(text):
            name = next((group for group in match.groups() if group), "constructor")
            if name not in _CONTROL_NAMES:
                names.add(name)
    return names


def _calls(text: str) -> set[str]:
    relevant_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("//", "*", "#")) or stripped.startswith("returns"):
            continue
        if re.match(r"(?:event|error)\s+[A-Za-z_]\w*\s*\(", stripped):
            continue
        if re.match(r"(?:function|modifier)\b", stripped) and "{" not in stripped and "=>" not in stripped:
            continue
        relevant_lines.append(line)
    without_definitions = "\n".join(relevant_lines)
    for pattern in _DEF_PATTERNS:
        without_definitions = pattern.sub("", without_definitions)
    return {name for name in _CALL_RE.findall(without_definitions) if name not in _CONTROL_NAMES}


def changed_line_ranges(diff: str, detection: Detection | None = None) -> ChangedLineRanges:
    """Return changed new-side line ranges for reviewable source files."""
    configured = detection or load_detection()
    return {
        path: ranges
        for path, ranges in diff_line_ranges(diff, configured).new.items()
        if Path(path).suffix.lower() in configured.source_extensions
    }


def _append_line(output: dict[str, list[tuple[int, int]]], path: str, line: int, detection: Detection) -> None:
    if path and not detection.is_noise_path(path):
        output.setdefault(path, []).append((line, line))


def diff_line_ranges(diff: str, detection: Detection | None = None) -> DiffLineRanges:
    """Return post change hunk lines and exact old and new change anchors."""
    configured = detection or load_detection()
    current: dict[str, list[tuple[int, int]]] = {}
    old: dict[str, list[tuple[int, int]]] = {}
    new: dict[str, list[tuple[int, int]]] = {}
    for chunk in split_diff_by_file(diff):
        fallback = chunk_path(chunk)
        old_path = _side_path(chunk, "---") or fallback
        new_path = _side_path(chunk, "+++") or fallback
        old_line: int | None = None
        new_line: int | None = None
        for line in chunk.splitlines():
            hunk = _HUNK_RE.match(line)
            if hunk:
                old_line = int(hunk.group(1))
                new_line = int(hunk.group(3))
                continue
            if old_line is None or new_line is None:
                continue
            if line.startswith("+"):
                _append_line(new, new_path, new_line, configured)
                _append_line(current, new_path, new_line, configured)
                new_line += 1
            elif line.startswith(" "):
                _append_line(current, new_path, new_line, configured)
                old_line += 1
                new_line += 1
            elif line.startswith("-"):
                _append_line(old, old_path, old_line, configured)
                old_line += 1
            elif not line.startswith("\\"):
                old_line = new_line = None
    return DiffLineRanges(
        current={path: tuple(_merge_ranges(ranges)) for path, ranges in current.items()},
        old={path: tuple(_merge_ranges(ranges)) for path, ranges in old.items()},
        new={path: tuple(_merge_ranges(ranges)) for path, ranges in new.items()},
    )


def changed_call_names(text: str) -> set[str]:
    """Return lexical call names used for batching and context retrieval."""
    return {*_CALL_LIKE_NAME.findall(text), *_CALLABLE_ASSIGNMENT_NAME.findall(text)}


def hunk_call_names_by_path(diff: str, detection: Detection) -> ReviewNamesByPath:
    """Return patch-visible call names grouped by changed path."""
    names: dict[str, set[str]] = {}
    for chunk in split_diff_by_file(diff):
        current = chunk_path(chunk)
        in_hunk = False
        for line in chunk.splitlines():
            if line.startswith("@@ "):
                in_hunk = True
                continue
            if not current or not in_hunk or not line.startswith((" ", "+", "-")):
                continue
            if detection.is_noise_path(current) or Path(current).suffix.lower() not in detection.source_extensions:
                continue
            names.setdefault(current, set()).update(changed_call_names(line[1:]))
    return {path: frozenset(values) for path, values in names.items()}


def prepare_diff_units(
    diff: str,
    *,
    root: Path,
    detection: Detection,
    graph: FactsGraph,
    collect: Callable[[str, DefinitionUnitPlan], GroundingContext],
    settings: DiffReviewSettings = _SETTINGS,
) -> list[DiffUnit]:
    """Build diff units from connected changed definitions and fallback patches."""
    chunks = split_diff_by_file(diff)
    paths = batch_paths(diff)
    chunks_by_path = {chunk_path(chunk): chunk for chunk in chunks}
    ranges = changed_line_ranges(diff, detection)
    seeds = changed_definition_fragments(root, paths, ranges, graph)
    plans = list(
        plan_definition_units(
            seeds,
            graph,
            depth=2,
            max_chars=max(
                1,
                int(
                    min(
                        settings.target_patch_chars_per_unit,
                        settings.target_repository_context_chars_per_unit // 2,
                    )
                    * _SOURCE_RENDERING_HEADROOM
                ),
            ),
            seed_files=paths,
            include_seed_chars=False,
            references_by_seed=definition_references(seeds, lambda path: _source_for_planning(root, path)),
            pack_surfaces=False,
        )
    )
    plans = _merge_connected_surface_plans(plans)
    plans = _pack_surface_plans(plans, chunks_by_path, settings)
    covered = {
        file
        for plan in plans
        for file in (
            *(seed.file for seed in plan.seeds),
            *plan.seed_files,
        )
    }
    fallback_diff = "".join(chunks_by_path[path] for path in paths if path not in covered)
    plans.extend(
        DefinitionUnitPlan(seed_files=batch_paths(batch))
        for batch in pack_diff_chunks(fallback_diff, settings.target_patch_chars_per_unit)
    )
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
            provisional.append((unit_diff, unit_paths, plan))
    total = len(provisional)
    return [
        DiffUnit(
            index=index,
            total=total,
            diff=unit_diff,
            paths=unit_paths,
            definition_plan=plan,
            grounding=collect(unit_diff, plan),
        )
        for index, (unit_diff, unit_paths, plan) in enumerate(provisional, 1)
    ]


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
        evidence_chars = definition_union_size(candidate.fragments) + sum(
            len(edge.identity) for edge in candidate.dependencies
        )
        if patch_chars > settings.target_patch_chars_per_unit or evidence_chars > context_target:
            packed.append(current)
            current = plan
        else:
            current = candidate
    if current is not None:
        packed.append(current)
    return packed


def _merge_connected_surface_plans(plans: list[DefinitionUnitPlan]) -> list[DefinitionUnitPlan]:
    groups = _PlanGroups.create(len(plans))
    owners = _seed_owners(plans)
    for index, plan in enumerate(plans):
        for edge in plan.dependencies:
            _connect_dependency(groups, owners, index, edge)
    grouped: dict[int, DefinitionUnitPlan] = {}
    order: list[int] = []
    for index, plan in enumerate(plans):
        group = groups.root(index)
        if group not in grouped:
            grouped[group] = plan
            order.append(group)
        else:
            grouped[group] = merge_definition_unit_plans(grouped[group], plan)
    return [grouped[group] for group in order]


@dataclass
class _PlanGroups:
    parents: list[int]

    @classmethod
    def create(cls, size: int) -> _PlanGroups:
        return cls(list(range(size)))

    def root(self, index: int) -> int:
        while self.parents[index] != index:
            self.parents[index] = self.parents[self.parents[index]]
            index = self.parents[index]
        return index

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.root(left), self.root(right)
        if left_root != right_root:
            self.parents[right_root] = left_root


def _seed_owners(plans: list[DefinitionUnitPlan]) -> dict[DefinitionFragment, set[int]]:
    owners: dict[DefinitionFragment, set[int]] = {}
    for index, plan in enumerate(plans):
        for seed in plan.seeds:
            owners.setdefault(seed, set()).add(index)
    return owners


def _connect_dependency(
    groups: _PlanGroups,
    owners: dict[DefinitionFragment, set[int]],
    plan_index: int,
    edge: DefinitionDependency,
) -> None:
    if edge.resolution != "exact":
        return
    source_owners = owners.get(edge.source, (plan_index,)) if edge.source is not None else (plan_index,)
    for source_owner in source_owners:
        for target_owner in owners.get(edge.target, ()):
            groups.union(source_owner, target_owner)


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
            end_line = source[: fragment.end].count("\n") + 1
            if any(
                start_line <= changed_end and end_line >= changed_start
                for changed_start, changed_end in ranges.get(fragment.file, ())
            ):
                candidates.append((fragment, start_line, end_line))
    selected: list[DefinitionFragment] = []
    for fragment, start_line, end_line in candidates:
        changed_lines = {
            line
            for changed_start, changed_end in ranges.get(fragment.file, ())
            for line in range(max(start_line, changed_start), min(end_line, changed_end) + 1)
        }
        nested_lines = {
            line
            for other, other_start, other_end in candidates
            if other.file == fragment.file
            and fragment.start <= other.start
            and fragment.end >= other.end
            and (fragment.start < other.start or fragment.end > other.end)
            for line in changed_lines
            if other_start <= line <= other_end
        }
        if changed_lines.difference(nested_lines):
            selected.append(fragment)
    return tuple(dict.fromkeys(selected))


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
