"""Build prompt context for a diff from repository facts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cyberjury.detection import Detection, load_detection
from cyberjury.profiles.base import ReviewProfile
from cyberjury.review.context import GroundingContext
from cyberjury.review.diff.model import chunk_path, split_diff_by_file
from cyberjury.review.facts import BackendUnavailable, extract_facts
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_GIT_PATH_RE = re.compile(r"^diff --git a/\S+ b/(\S+)")
_PATH_RE = re.compile(r"^(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", re.MULTILINE)
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff
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


@dataclass(frozen=True, kw_only=True)
class DiffContext(GroundingContext):
    """Context snippets collected around changed diff lines."""

    source: Literal["diff"] = "diff"


@dataclass(frozen=True, kw_only=True)
class PatchFile:
    """Changed symbols and calls extracted from one patch file."""

    path: str
    definitions: tuple[str, ...]
    calls: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class DiffContextCollector:
    """Interface for collecting source context for diff review."""

    root: Path
    detection: Detection
    by_file: dict
    graph: dict
    review_paths: tuple[str, ...] = ()
    review_names_by_path: dict[str, frozenset[str]] = field(default_factory=dict)

    def text_for_diff(self, diff: str) -> str:
        """Return source context text relevant to one diff."""
        return self.collect(diff).text

    def collect(self, diff: str) -> DiffContext:
        """Collect source context for changed files in a diff."""
        paths = changed_paths(diff, self.detection)
        if not paths:
            return DiffContext(text="", files=())
        ranges = changed_line_ranges(diff, self.detection)
        changed, related = _context_blocks(
            self.root,
            paths,
            self.by_file,
            self.graph,
            ranges,
            review_paths=self.review_paths,
            review_names_by_path=self.review_names_by_path,
        )
        related_first = len(paths) >= _SETTINGS.related_context_first_min_changed_files
        entries = [*related, *changed] if related_first else [*changed, *related]
        text = _render_context(changed, related, related_first=related_first)
        files = tuple(rel for rel, _block in entries if rel in paths)
        return DiffContext(text=text, files=files)


def changed_paths(diff: str, detection: Detection | None = None) -> tuple[str, ...]:
    """The source paths changed by a unified diff, after profile noise filters."""
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


def patch_files(diff: str, detection: Detection | None = None) -> tuple[PatchFile, ...]:
    """Extract changed definitions and calls without reading a repository."""
    files: list[PatchFile] = []
    for chunk in split_diff_by_file(diff):
        path = chunk_path(chunk)
        active = _active_lines(chunk)
        is_source = _is_source_path(path, detection)
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
            for target in targets:
                edges.append((item.path, target.path + ":" + name))
    lines = [
        "Patch-local grounding, extracted only from the changed text:",
        "Use these relationships to trace the patch. No unchanged repository code is included.",
    ]
    if edges:
        lines.append("Patch-visible call relationships:")
        for source_path, target in sorted(set(edges)):
            lines.append(f"- {source_path} uses {target}")
        edge_paths = {path for edge in edges for path in (edge[0], edge[1].rsplit(":", 1)[0])}
        for item in files:
            if item.path in edge_paths and item.definitions:
                lines.append(f"- {item.path}: changed definitions {', '.join(item.definitions)}")
    else:
        for item in files:
            if item.definitions:
                lines.append(f"- {item.path}: changed definitions {', '.join(item.definitions)}")
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


def _is_source_path(path: str, detection: Detection | None) -> bool:
    return detection is None or Path(path).suffix.lower() in detection.source_extensions


def collect_diff_context(repository: str | Path, diff: str, profile: ReviewProfile) -> DiffContext:
    """Collect facts and current source for changed files in a repository diff."""
    return build_diff_context_collector(repository, profile, review_diff=diff).collect(diff)


def build_diff_context_collector(
    repository: str | Path,
    profile: ReviewProfile,
    *,
    facts_root: str | Path | None = None,
    review_diff: str = "",
) -> DiffContextCollector:
    """Extract repository facts once, then render context for one or more diff batches."""
    root = Path(repository).resolve()
    facts_base = Path(facts_root).resolve() if facts_root is not None else root
    prefix = _relative_prefix(root, facts_base)
    detection = load_detection(profile.paths.detection_file)
    review_paths = changed_paths(review_diff, detection)
    review_names_by_path = _hunk_call_names_by_path(review_diff, detection)
    backend = profile.facts_backend
    if backend is None:
        return DiffContextCollector(
            root=root,
            detection=detection,
            by_file={},
            graph={},
            review_paths=review_paths,
            review_names_by_path=review_names_by_path,
        )
    facts = extract_facts(backend, facts_base, purpose="diff context")
    data = facts.data if isinstance(facts.data, dict) else {}
    by_file = data.get("by_file") if isinstance(data.get("by_file"), dict) else {}
    graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
    return DiffContextCollector(
        root=root,
        detection=detection,
        by_file=_prefix_map(by_file, prefix),
        graph=_prefix_graph(graph, prefix),
        review_paths=review_paths,
        review_names_by_path=review_names_by_path,
    )


def _relative_prefix(root: Path, facts_base: Path) -> str:
    if facts_base == root:
        return ""
    if not facts_base.is_relative_to(root):
        raise BackendUnavailable(f"facts root {facts_base} is outside repository root {root}")
    return facts_base.relative_to(root).as_posix()


def _prefix_path(path: str, prefix: str) -> str:
    return f"{prefix}/{path}" if prefix else path


def _prefix_map(values: dict, prefix: str) -> dict:
    if not prefix:
        return values
    return {_prefix_path(str(path), prefix): value for path, value in values.items()}


def _prefix_import_targets(values: dict, prefix: str) -> dict:
    if not prefix:
        return values
    return {
        _prefix_path(str(path), prefix): [_prefix_path(str(target), prefix) for target in targets or ()]
        for path, targets in values.items()
    }


def _prefix_graph(graph: dict, prefix: str) -> dict:
    if not prefix:
        return graph
    out = dict(graph)
    callgraph = graph.get("callgraph")
    if isinstance(callgraph, dict):
        out["callgraph"] = _prefix_map(callgraph, prefix)
    imports = graph.get("imports")
    if isinstance(imports, dict):
        out["imports"] = _prefix_map(imports, prefix)
    import_targets = graph.get("import_targets")
    if isinstance(import_targets, dict):
        out["import_targets"] = _prefix_import_targets(import_targets, prefix)
    return out


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


def changed_call_names(text: str) -> set[str]:
    """Keep batching and context retrieval on the same lexical relationship signal."""
    return {*_CALL_LIKE_NAME.findall(text), *_CALLABLE_ASSIGNMENT_NAME.findall(text)}


def _hunk_call_names_by_path(diff: str, detection: Detection) -> dict[str, frozenset[str]]:
    names: dict[str, set[str]] = {}
    current = ""
    in_hunk = False
    for line in diff.splitlines():
        git = _GIT_PATH_RE.match(line)
        if git:
            current = git.group(1)
            in_hunk = False
            continue
        if line.startswith("+++ "):
            raw = line[4:].strip()
            current = "" if raw == "/dev/null" else raw.removeprefix("b/")
            continue
        if line.startswith("@@ "):
            in_hunk = True
            continue
        if not current or not in_hunk or not line.startswith((" ", "+", "-")):
            continue
        if detection.is_noise_path(current) or Path(current).suffix.lower() not in detection.source_extensions:
            continue
        names.setdefault(current, set()).update(changed_call_names(line[1:]))
    return {path: frozenset(values) for path, values in names.items()}


def _context_blocks(
    root: Path,
    paths: tuple[str, ...],
    by_file: dict,
    graph: dict,
    ranges: dict[str, tuple[tuple[int, int], ...]],
    *,
    review_paths: tuple[str, ...] = (),
    review_names_by_path: dict[str, frozenset[str]] | None = None,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    changed_blocks: list[tuple[str, str]] = []
    related_blocks: list[tuple[str, str]] = []
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    seed_text = _changed_seed(root, paths, ranges)
    related = _related_files(
        paths,
        graph,
        seed_text=seed_text,
        preferred_paths=review_paths,
        preferred_names=review_names_by_path or {},
    )
    direct_imported_names = _direct_imported_names(paths, callgraph, graph, seed_text)
    focus_names = _focus_names(paths, callgraph)
    for rel in paths:
        block = _file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            ranges.get(rel, ()),
            _file_defs(callgraph.get(rel)),
        )
        if block:
            changed_blocks.append((rel, block))
    related_chars = 0
    related_limit = int(_SETTINGS.max_repository_context_chars_per_unit * _SETTINGS.max_related_context_fraction)
    related_slots = min(len(related), _SETTINGS.max_related_files_for_budget_split)
    related_block_limit = min(
        _SETTINGS.target_definition_context_chars_per_file,
        related_limit // related_slots if related_slots else related_limit,
    )
    for rel in related:
        block = _related_file_context(
            root,
            rel,
            str(by_file.get(rel) or ""),
            _file_defs(callgraph.get(rel)),
            focus_names,
            seed_text,
            direct_imported_names.get(rel, ()),
        )
        if not block:
            continue
        remaining = related_limit - related_chars - (2 if related_blocks else 0)
        if remaining <= 0:
            break
        block = _clip_block(block, min(remaining, related_block_limit))
        related_blocks.append((rel, block))
        related_chars += len(block) + (2 if len(related_blocks) > 1 else 0)
    return changed_blocks, related_blocks


def _focus_names(paths: tuple[str, ...], callgraph: dict) -> set[str]:
    return {str(name) for rel in paths for name in _file_defs(callgraph.get(rel))}


def _changed_seed(root: Path, paths: tuple[str, ...], ranges: dict[str, tuple[tuple[int, int], ...]]) -> str:
    parts: list[str] = []
    for rel in paths:
        path = (root / rel).resolve()
        try:
            path.relative_to(root)
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        lines = source.splitlines()
        for start, end in ranges.get(rel, ()):
            if start <= len(lines):
                parts.extend(lines[start - 1 : min(end, len(lines))])
    return "\n".join(parts)


def _related_files(
    paths: tuple[str, ...],
    graph: dict,
    *,
    seed_text: str = "",
    preferred_paths: tuple[str, ...] = (),
    preferred_names: dict[str, frozenset[str]] | None = None,
) -> tuple[str, ...]:
    callgraph = graph.get("callgraph") if isinstance(graph.get("callgraph"), dict) else {}
    imports = graph.get("imports") if isinstance(graph.get("imports"), dict) else {}
    import_targets = graph.get("import_targets") if isinstance(graph.get("import_targets"), dict) else {}
    referenced_names: set[str] = set()
    for rel in paths:
        for defs in _file_defs(callgraph.get(rel)).values():
            for item in defs:
                calls = item.get("calls") if isinstance(item, dict) else ()
                referenced_names.update(str(c) for c in calls or ())
        referenced_names.update(str(n) for n in imports.get(rel) or ())
    out: dict[str, None] = {}
    direct_target_scores = {
        target: len(imported_names)
        for target, imported_names in _direct_imported_names(paths, callgraph, graph, seed_text).items()
    }
    for rel in paths:
        for target in import_targets.get(rel) or ():
            target = str(target)
            if target in paths:
                continue
            direct_target_scores.setdefault(target, 0)
    for target in direct_target_scores:
        out.setdefault(target, None)
    for rel in _forward_import_files(paths, import_targets):
        out.setdefault(rel, None)
    for rel, defs_by_name in callgraph.items():
        if rel in paths or not isinstance(defs_by_name, dict):
            continue
        if any(name in defs_by_name for name in referenced_names):
            out.setdefault(str(rel), None)
    for rel in _reverse_call_files(paths, callgraph):
        out.setdefault(rel, None)
    for rel in _reverse_import_files(paths, callgraph, imports, import_targets):
        out.setdefault(rel, None)
    preferred = set(preferred_paths).difference(paths)
    preferred_names_by_path = preferred_names or {}
    return tuple(
        sorted(
            out,
            key=lambda rel: (
                rel not in preferred,
                -_changed_peer_name_score(rel, callgraph, preferred_names_by_path, seed_text),
                rel not in direct_target_scores,
                -direct_target_scores.get(rel, 0),
                -_related_name_hits(rel, callgraph, imports, seed_text),
                rel,
            ),
        )
    )


def _direct_imported_names(
    paths: tuple[str, ...],
    callgraph: dict,
    graph: dict,
    seed_text: str,
) -> dict[str, tuple[str, ...]]:
    imports = graph.get("imports") if isinstance(graph.get("imports"), dict) else {}
    import_targets = graph.get("import_targets") if isinstance(graph.get("import_targets"), dict) else {}
    out: dict[str, set[str]] = {}
    for rel in paths:
        imported = {str(name) for name in imports.get(rel) or ()}
        called = {
            str(name)
            for entries in _file_defs(callgraph.get(rel)).values()
            for item in entries or ()
            if isinstance(item, dict)
            for name in item.get("calls") or ()
        }
        for target in import_targets.get(rel) or ():
            target = str(target)
            if target in paths:
                continue
            definitions = set(_file_defs(callgraph.get(target)))
            names = {
                name
                for name in definitions.intersection(imported, called)
                if re.search(rf"\b{re.escape(name)}\b", seed_text)
            }
            if names:
                out.setdefault(target, set()).update(names)
    return {target: tuple(sorted(names)) for target, names in out.items()}


def _changed_peer_name_score(
    rel: str,
    callgraph: dict,
    preferred_names: dict[str, frozenset[str]],
    seed_text: str,
) -> int:
    definitions = set(_file_defs(callgraph.get(rel)))
    changed_definitions = definitions.intersection(preferred_names.get(rel, ()))
    return sum(len(name) for name in changed_definitions if re.search(rf"\b{re.escape(name)}\b", seed_text))


def _forward_import_files(paths: tuple[str, ...], import_targets: dict) -> tuple[str, ...]:
    frontier = list(paths)
    seen = set(paths)
    out: list[str] = []
    for _ in range(2):
        next_frontier: list[str] = []
        for rel in frontier:
            for target in import_targets.get(rel) or ():
                target = str(target)
                if target in seen:
                    continue
                seen.add(target)
                out.append(target)
                next_frontier.append(target)
        frontier = next_frontier
    return tuple(out)


def _related_name_hits(rel: str, callgraph: dict, imports: dict, seed_text: str) -> int:
    names = {*_file_defs(callgraph.get(rel)), *(str(name) for name in imports.get(rel) or ())}
    return sum(1 for name in names if re.search(rf"\b{re.escape(name)}\b", seed_text))


def _reverse_call_files(paths: tuple[str, ...], callgraph: dict) -> tuple[str, ...]:
    focus_names = _focus_names(paths, callgraph)
    out: dict[str, None] = {}
    for rel, defs_by_name in callgraph.items():
        rel = str(rel)
        if rel in paths or not isinstance(defs_by_name, dict):
            continue
        for entries in defs_by_name.values():
            if any(
                focus_names.intersection(str(call) for call in item.get("calls") or ())
                for item in entries or ()
                if isinstance(item, dict)
            ):
                out.setdefault(rel, None)
                break
    return tuple(out)


def _reverse_import_files(
    paths: tuple[str, ...], callgraph: dict, imports: dict, import_targets: dict
) -> tuple[str, ...]:
    target_files = set(paths)
    target_names = {str(name) for rel in paths for name in _file_defs(callgraph.get(rel))}
    out: dict[str, None] = {}
    for _ in range(2):
        grew = False
        for rel, targets in import_targets.items():
            rel = str(rel)
            if rel in target_files:
                continue
            if not any(str(target) in target_files for target in targets or ()):
                continue
            imported = {str(name) for name in imports.get(rel) or ()}
            if target_names and imported and not imported.intersection(target_names):
                continue
            out.setdefault(rel, None)
            target_files.add(rel)
            target_names.update(imported)
            target_names.update(str(name) for name in _file_defs(callgraph.get(rel)))
            grew = True
        if not grew:
            break
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
    if ranges:
        source_prefix = source
        if len(source_prefix) > _SETTINGS.max_changed_source_prefix_chars:
            source_prefix = source_prefix[: _SETTINGS.max_changed_source_prefix_chars] + "\n... [source truncated]"
        rendered_source = _source_windows(source, ranges)
        source_block = f"Current source around changed lines:\n{rendered_source}"
        prefix_block = f"Current file source prefix:\n{_numbered_source(source_prefix)}"
        definition_block = _definition_snippets(source, defs_by_name, rendered_source, ranges)
    elif len(source) > _SETTINGS.max_full_source_chars_per_context_file:
        source = source[: _SETTINGS.max_full_source_chars_per_context_file] + "\n... [source truncated]"
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
        if len(facts) > _SETTINGS.max_facts_chars_per_context_file:
            facts = facts[: _SETTINGS.max_facts_chars_per_context_file] + "\n... [facts truncated]"
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


def _related_file_context(
    root: Path,
    rel: str,
    facts: str,
    defs_by_name: dict,
    focus_names: set[str],
    seed_text: str,
    direct_imported_names: tuple[str, ...] = (),
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
    pieces = [f"File: {rel}"]
    if direct_imported_names:
        pieces.append(f"Imported definitions called by changed code: {', '.join(direct_imported_names)}")
    snippets = _caller_definition_snippets(source, defs_by_name, focus_names, seed_text)
    if snippets:
        pieces.append(f"Related definitions:\n{snippets}")
    else:
        if len(source) > _SETTINGS.max_full_source_chars_per_context_file:
            source = source[: _SETTINGS.max_full_source_chars_per_context_file] + "\n... [source truncated]"
        pieces.append(f"Current source:\n{_numbered_source(source)}")
    if facts:
        if len(facts) > _SETTINGS.max_facts_chars_per_context_file:
            facts = facts[: _SETTINGS.max_facts_chars_per_context_file] + "\n... [facts truncated]"
        pieces.append(f"Facts:\n{facts}")
    return "\n".join(pieces)


def _numbered_source(source: str) -> str:
    return "\n".join(f"{i:4}: {line}" for i, line in enumerate(source.splitlines(), 1))


def _source_windows(source: str, ranges: tuple[tuple[int, int], ...]) -> str:
    lines = source.splitlines()
    chunks: list[str] = []
    for start, end in ranges:
        if chunks:
            chunks.append("... [source gap]")
        if start > len(lines) + 1:
            chunks.append(f"Changed lines {start}-{end} are outside current source length {len(lines)}.")
            continue
        before_start = max(1, start - _SETTINGS.hunk_context_lines_per_side)
        before_end = min(len(lines), start - 1)
        after_start = end + 1
        after_end = min(len(lines), end + _SETTINGS.hunk_context_lines_per_side)
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
        if out and total + add > _SETTINGS.target_definition_context_chars_per_file:
            out.append("... [definitions truncated]")
            break
        out.append(snippet)
        total += add
    return "\n\n".join(out)


def _caller_definition_snippets(source: str, defs_by_name: dict, focus_names: set[str], seed_text: str = "") -> str:
    if not defs_by_name or not (focus_names or seed_text):
        return ""
    snippets: list[tuple[int, int, str]] = []
    for name, entries in defs_by_name.items():
        seed_hit = bool(re.search(rf"\b{re.escape(str(name))}\b", seed_text))
        for item in entries or ():
            calls = {str(call) for call in item.get("calls") or ()} if isinstance(item, dict) else set()
            if not seed_hit and not calls.intersection(focus_names):
                continue
            snippet = _definition_snippet(source, str(name), item)
            if snippet and len(snippet) <= _SETTINGS.max_caller_definition_chars:
                snippets.append((len(snippet), _definition_start(item), snippet))
    out: list[str] = []
    total = 0
    for size, _start, snippet in sorted(snippets):
        add = size + 2
        if out and total + add > _SETTINGS.target_definition_context_chars_per_file:
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


def _render_context(
    changed: list[tuple[str, str]],
    related: list[tuple[str, str]],
    *,
    related_first: bool,
) -> str:
    if not related:
        return _join_capped([block for _rel, block in changed], _SETTINGS.max_repository_context_chars_per_unit)
    related_limit = min(
        int(_SETTINGS.max_repository_context_chars_per_unit * _SETTINGS.max_related_context_fraction),
        len(related) * _SETTINGS.target_definition_context_chars_per_file,
    )
    related_text = _join_capped([block for _rel, block in related], related_limit)
    separator = 2 if changed and related_text else 0
    changed_limit = _SETTINGS.max_repository_context_chars_per_unit - len(related_text) - separator
    changed_text = _join_capped([block for _rel, block in changed], changed_limit)
    ordered = (related_text, changed_text) if related_first else (changed_text, related_text)
    return _truncate(
        "\n\n".join(text for text in ordered if text),
        _SETTINGS.max_repository_context_chars_per_unit,
        "... [diff context truncated]",
    )


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
