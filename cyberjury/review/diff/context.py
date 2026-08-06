"""Build prompt context for a diff from repository facts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.domains.base import BackendUnavailable, Domain

_GIT_PATH_RE = re.compile(r"^diff --git a/\S+ b/(\S+)")
_PATH_RE = re.compile(r"^(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", re.MULTILINE)
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_MAX_CONTEXT_CHARS = 24_000
_MAX_FILE_CHARS = 12_000
_MAX_FACTS_CHARS = 1_200
_MAX_RELATED_FILES = 6
_MAX_DEFINITION_CHARS = 6_000
_HUNK_CONTEXT_LINES = 5


@dataclass(frozen=True, kw_only=True)
class DiffContext:
    text: str
    files: tuple[str, ...]


def changed_paths(diff: str, detection: Detection | None = None) -> tuple[str, ...]:
    """The source paths changed by a unified diff, after domain noise filters."""
    det = detection or load_detection()
    seen: dict[str, None] = {}
    for raw in _PATH_RE.findall(diff):
        if raw == "/dev/null":
            continue
        path = raw[2:] if raw[:2] in ("a/", "b/") else raw
        if det.is_noise_path(path):
            continue
        if Path(path).suffix.lower() not in det.source_extensions:
            continue
        seen.setdefault(path, None)
    return tuple(seen)


def collect_diff_context(repository: str | Path, diff: str, domain: Domain) -> DiffContext:
    """Collect facts and current source for changed files in a repository diff."""
    root = Path(repository).resolve()
    backend = domain.facts_backend
    if backend is None:
        return DiffContext(text="", files=())
    if not backend.available():
        raise BackendUnavailable(f"the facts backend cannot run for diff context. {backend.install_hint}")
    detection = load_detection(domain.paths.detection_file)
    paths = changed_paths(diff, detection)
    if not paths:
        return DiffContext(text="", files=())
    try:
        facts = backend.extract(root)
    except Exception as exc:
        raise BackendUnavailable(f"facts extraction failed, so this diff review has no grounding: {exc}") from exc
    data = facts.data if isinstance(facts.data, dict) else {}
    by_file = data.get("by_file") if isinstance(data.get("by_file"), dict) else {}
    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    ranges = changed_line_ranges(diff, detection)
    entries = _context_blocks(root, paths, by_file, graph, ranges)
    blocks = [block for _rel, block in entries]
    text = _join_capped(blocks, _MAX_CONTEXT_CHARS)
    files = tuple(rel for rel, _block in entries if rel in paths)
    return DiffContext(text=text, files=files)


def changed_line_ranges(diff: str, detection: Detection | None = None) -> dict[str, tuple[tuple[int, int], ...]]:
    """Changed new-side line ranges by file, filtered to reviewable source files."""
    det = detection or load_detection()
    out: dict[str, list[tuple[int, int]]] = {}
    current = ""
    for line in diff.splitlines():
        git = _GIT_PATH_RE.match(line)
        if git:
            current = git.group(1)
            continue
        if line.startswith("+++ "):
            raw = line[4:].strip()
            if raw == "/dev/null":
                current = ""
                continue
            current = raw[2:] if raw[:2] in ("a/", "b/") else raw
            continue
        hunk = _HUNK_RE.match(line)
        if not hunk or not current:
            continue
        if det.is_noise_path(current) or Path(current).suffix.lower() not in det.source_extensions:
            continue
        start = int(hunk.group(1))
        count = int(hunk.group(2) or "1")
        end = start + max(count, 1) - 1
        out.setdefault(current, []).append((start, end))
    return {path: tuple(_merge_ranges(ranges)) for path, ranges in out.items()}


def _context_blocks(
    root: Path,
    paths: tuple[str, ...],
    by_file: dict,
    graph: dict,
    ranges: dict[str, tuple[tuple[int, int], ...]],
) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    related = _related_files(paths, graph)
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    for rel in paths:
        block = _file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            ranges.get(rel, ()),
            _file_defs(callgraph.get(rel)),
        )
        if block:
            blocks.append((rel, block))
    if len(paths) == 1:
        for rel in related[:_MAX_RELATED_FILES]:
            block = _file_context(root, rel, str(by_file.get(rel) or ""), (), _file_defs(callgraph.get(rel)))
            if block:
                blocks.append((rel, block))
    return blocks


def _related_files(paths: tuple[str, ...], graph: dict) -> tuple[str, ...]:
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    imports = graph.get("imports") if isinstance(graph.get("imports"), dict) else {}
    names: set[str] = set()
    for rel in paths:
        for defs in _file_defs(callgraph.get(rel)).values():
            for item in defs:
                calls = item.get("calls") if isinstance(item, dict) else ()
                names.update(str(c) for c in calls or ())
        names.update(str(n) for n in imports.get(rel) or ())
    out: dict[str, None] = {}
    for rel, defs_by_name in callgraph.items():
        if rel in paths or not isinstance(defs_by_name, dict):
            continue
        if any(name in defs_by_name for name in names):
            out.setdefault(str(rel), None)
    return tuple(out)


def _file_defs(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _file_context(
    root: Path,
    rel: str,
    facts: str,
    ranges: tuple[tuple[int, int], ...],
    defs_by_name: dict,
) -> str:
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return ""
    if not path.is_file():
        return ""
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""
    source_prefix = source
    if len(source_prefix) > _MAX_FILE_CHARS:
        source_prefix = source_prefix[:_MAX_FILE_CHARS] + "\n... [source truncated]"
    if ranges:
        rendered_source = _source_windows(source, ranges)
        source_block = f"Current source around changed lines:\n{rendered_source}"
        prefix_block = f"Current file source prefix:\n{_numbered_source(source_prefix)}"
        definition_block = _definition_snippets(source, defs_by_name, rendered_source, ranges)
    elif len(source) > _MAX_FILE_CHARS:
        source = source[:_MAX_FILE_CHARS] + "\n... [source truncated]"
        rendered_source = _numbered_source(source)
        source_block = f"Current source:\n{rendered_source}"
        prefix_block = ""
        definition_block = ""
    else:
        rendered_source = _numbered_source(source)
        source_block = f"Current source:\n{rendered_source}"
        prefix_block = ""
        definition_block = ""
    pieces = [f"File: {rel}"]
    facts_block = ""
    if facts:
        if len(facts) > _MAX_FACTS_CHARS:
            facts = facts[:_MAX_FACTS_CHARS] + "\n... [facts truncated]"
        facts_block = f"Facts:\n{facts}"
    if ranges:
        if definition_block:
            pieces.append(f"Related definitions:\n{definition_block}")
        pieces.append(source_block)
        if prefix_block:
            pieces.append(prefix_block)
        if facts_block:
            pieces.append(facts_block)
    else:
        if facts_block:
            pieces.append(facts_block)
        pieces.append(source_block)
    return "\n".join(pieces)


def _numbered_source(source: str) -> str:
    return "\n".join(f"{i:4}: {line}" for i, line in enumerate(source.splitlines(), 1))


def _source_windows(source: str, ranges: tuple[tuple[int, int], ...]) -> str:
    lines = source.splitlines()
    chunks: list[str] = []
    for start, end in ranges:
        if chunks:
            chunks.append("... [source gap]")
        before_start = max(1, start - _HUNK_CONTEXT_LINES)
        before_end = start - 1
        after_start = end + 1
        after_end = min(len(lines), end + _HUNK_CONTEXT_LINES)
        chunks.append(f"Before changed lines {start}-{end}:")
        if before_start <= before_end:
            chunks.extend(f"{i:4}: {lines[i - 1]}" for i in range(before_start, before_end + 1))
        else:
            chunks.append("... [start of file]")
        chunks.append("... [changed lines are in the diff]")
        chunks.append(f"After changed lines {start}-{end}:")
        if after_start <= after_end:
            chunks.extend(f"{i:4}: {lines[i - 1]}" for i in range(after_start, after_end + 1))
        else:
            chunks.append("... [end of file]")
    return "\n".join(chunks)


def _definition_snippets(
    source: str,
    defs_by_name: dict,
    seed_text: str,
    changed_ranges: tuple[tuple[int, int], ...],
) -> str:
    if not defs_by_name:
        return ""
    names = _referenced_names(seed_text, defs_by_name)
    snippets: list[tuple[int, str]] = []
    seen: set[str] = set()
    for _ in range(2):
        pending = [name for name in names if name not in seen]
        if not pending:
            break
        names = []
        for name in pending:
            seen.add(name)
            for item in defs_by_name.get(name) or ():
                if _definition_overlaps_changed(source, item, changed_ranges):
                    continue
                snippet = _definition_snippet(source, name, item)
                if not snippet:
                    continue
                snippets.append((_definition_start(item), snippet))
                names.extend(_referenced_names(snippet, defs_by_name))
    out: list[str] = []
    total = 0
    for _start, snippet in snippets:
        add = len(snippet) + 2
        if out and total + add > _MAX_DEFINITION_CHARS:
            out.append("... [definitions truncated]")
            break
        out.append(snippet)
        total += add
    return "\n\n".join(out)


def _referenced_names(text: str, defs_by_name: dict) -> list[str]:
    found: list[str] = []
    for name in defs_by_name:
        if name in found:
            continue
        if re.search(rf"\b{re.escape(str(name))}\b", text):
            found.append(str(name))
    return found


def _definition_snippet(source: str, name: str, item: object) -> str:
    start, end = _definition_range(item)
    if start < 0 or end <= start:
        return ""
    start_line, end_line = _definition_line_span(source, item)
    if start_line < 0 or end_line < start_line:
        return ""
    lines = source.splitlines()
    rendered = "\n".join(f"{i:4}: {lines[i - 1]}" for i in range(start_line, end_line + 1))
    return f"Definition {name}:\n{rendered}"


def _definition_range(item: object) -> tuple[int, int]:
    if not isinstance(item, dict):
        return (-1, -1)
    raw = item.get("range")
    if not isinstance(raw, list | tuple) or len(raw) < 2:
        return (-1, -1)
    start = raw[0]
    end = raw[1]
    if not isinstance(start, int) or not isinstance(end, int):
        return (-1, -1)
    return (start, end)


def _definition_start(item: object) -> int:
    return _definition_range(item)[0]


def _definition_line_span(source: str, item: object) -> tuple[int, int]:
    start, end = _definition_range(item)
    if start < 0 or end <= start:
        return (-1, -1)
    lines = source.splitlines()
    start_line = max(1, source[:start].count("\n") + 1)
    end_line = min(len(lines), source[:end].count("\n") + 1)
    return (start_line, end_line)


def _definition_overlaps_changed(
    source: str,
    item: object,
    changed_ranges: tuple[tuple[int, int], ...],
) -> bool:
    start_line, end_line = _definition_line_span(source, item)
    if start_line < 0:
        return False
    return any(start_line <= changed_end and end_line >= changed_start for changed_start, changed_end in changed_ranges)


def _merge_ranges(ranges) -> list[tuple[int, int]]:
    ordered = sorted((int(a), int(b)) for a, b in ranges)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def _join_capped(blocks: list[str], limit: int) -> str:
    if len(blocks) > 1:
        separator_budget = 2 * (len(blocks) - 1)
        budget = max(1, (limit - separator_budget) // len(blocks))
        joined = "\n\n".join(_clip_block(block, budget) for block in blocks)
        if len(joined) <= limit:
            return joined
        return _truncate(joined, limit, "... [diff context truncated]")
    out: list[str] = []
    total = 0
    for block in blocks:
        add = len(block) + 2
        if out and total + add > limit:
            out.append("... [diff context truncated]")
            break
        if not out and add > limit:
            return _truncate(block, limit, "... [diff context truncated]")
        out.append(block)
        total += add
    return "\n\n".join(out)


def _clip_block(block: str, limit: int) -> str:
    if len(block) <= limit:
        return block
    return _truncate(block, limit, "... [file context truncated]")


def _truncate(text: str, limit: int, marker: str) -> str:
    if len(text) <= limit:
        return text
    if limit <= len(marker) + 1:
        return text[:limit]
    return text[: limit - len(marker) - 1] + "\n" + marker
