"""Build a language-agnostic repository map and bounded review units.

The model lists files deterministically and selects candidate entrypoints from profile
data. Unit construction covers those candidates and adds source fragments supplied by
the facts graph, with no model calls or vulnerability-specific Python logic.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.detection import Detection, load_detection
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.repository.context import Unit
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


@dataclass(frozen=True, kw_only=True)
class RepositoryModel:
    """Language-agnostic file map used to seed repository review units."""

    root: str
    files: tuple[str, ...]


def _read_files(root: Path, detection: Detection | None = None) -> tuple[str, ...]:
    """Relative paths of the files under root.

    Noise dirs and symlinks that escape the tree are skipped.
    """
    det = detection or load_detection()
    root = root.resolve()
    out: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if det.is_skipped_dir(rel.parts[:-1]):
            continue
        try:
            if not path.resolve().is_relative_to(root):
                continue
        except OSError:
            continue
        out.append(str(rel))
    return tuple(sorted(out))


def build_repository_model_from_dir(root: str | Path, detection: Detection | None = None) -> RepositoryModel:
    """Build a repository file map from a directory."""
    return RepositoryModel(root=str(root), files=_read_files(Path(root), detection))


def build_repository_model(root: str | Path, files: Sequence[str]) -> RepositoryModel:
    """Build a repository model for a caller that already has the relative file list."""
    return RepositoryModel(root=str(root), files=tuple(sorted(files)))


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _SETTINGS.max_scanned_source_bytes_per_file:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def candidate_entrypoint_files(
    files: Sequence[str],
    *,
    root: str | Path | None = None,
    globs: Sequence[str] = (),
    markers: Sequence[str] = (),
    detection: Detection | None = None,
) -> list[str]:
    """Files likely to define entrypoints.

    A file is a candidate when its path matches one of `globs`, or when `root` is given and
    its content contains one of `markers` the guide declares, such as a handler class or a
    route registration. The marker scan is what recovers framework entrypoints that no
    filename glob would catch, and it stays data-driven because the markers come from the
    guide. Returns a sorted list with no duplicates.
    """
    det = detection or load_detection()
    globs = tuple(globs)
    markers = tuple(markers)
    base = Path(root) if root is not None else None
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if any(fnmatch.fnmatch(f, g) for g in globs):
            out.append(f)
            continue
        if markers and base is not None and Path(f).suffix in det.source_extensions:
            text = _read_text(base / f)
            if text and any(m in text for m in markers):
                out.append(f)
    return sorted(dict.fromkeys(out))


def public_api_files(
    files: Sequence[str],
    *,
    root: str | Path | None = None,
    patterns: Sequence[str] = (),
    detection: Detection | None = None,
) -> list[str]:
    """Non-test source files that define public or exported API.

    A library has no application entrypoint, so its exported symbols are the attack surface:
    a consumer passes attacker-influenced data into them. Used as the fallback denominator
    when no application entrypoint seeds, so a library is reviewed from its public surface
    inward rather than not at all. `patterns` are per-language export regexes a guide
    declares, such as a capitalized Go function, which keeps the selection data-driven and
    the engine generic. A file whose symbols are all private matches nothing and is left
    out, so unreachable internal code is not seeded. Returns a sorted list with no
    duplicates.
    """
    det = detection or load_detection()
    if not patterns or root is None:
        return []
    compiled = [re.compile(p, re.MULTILINE) for p in patterns]
    base = Path(root)
    out: list[str] = []
    for f in files:
        if det.is_test_path(f):
            continue
        if Path(f).suffix not in det.source_extensions:
            continue
        text = _read_text(base / f)
        if text and any(c.search(text) for c in compiled):
            out.append(f)
    return sorted(dict.fromkeys(out))


def construct_boundaries(text: str) -> list[int]:
    """Find top-level construct boundaries in an indentation-based source file.

    A non-space character at the start of a line marks such a boundary in Python, Go, or
    JavaScript. Window edges snap to these so a class or function is reviewed whole, not
    split across units.
    """
    starts: list[int] = []
    at_line_start = True
    for i, ch in enumerate(text):
        if at_line_start and not ch.isspace():
            starts.append(i)
        at_line_start = ch == "\n"
    return starts


def char_spans(text: str) -> list[tuple[int, int] | None]:
    """The char windows that cover `text`.

    Text that fits one window is reviewed whole, span None. Larger text is split at top-
    level construct boundaries so each class or function lands whole in one window. A single
    construct longer than a window is hard split with an overlap, so even then no boundary
    silently drops a construct's tail. Shared by the coded run's unit builder and the
    scaffold's unit seeding, so both paths split a large entrypoint file the same way.
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


def span_line_range(text: str, span: tuple[int, int]) -> tuple[int, int]:
    """Convert a character span to its one-based inclusive line range.

    This lets a seeded unit identify its source slice by line number rather than an
    opaque char offset.
    """
    start, end = span
    first = text.count("\n", 0, start) + 1
    last = text.count("\n", 0, max(start, end - 1)) + 1
    return first, last


def logic_layer_files(
    files: Sequence[str], *, globs: Sequence[str] = (), detection: Detection | None = None
) -> list[str]:
    """Find non-test files that match downstream logic layer globs.

    Examples include managers, controllers, DAO modules, and services. These are not entrypoints but the
    call targets to trace into from an entrypoint, so a review does not stop at the view.
    Returns a sorted list with no duplicates.
    """
    det = detection or load_detection()
    globs = tuple(globs)
    out = {f for f in files if not det.is_test_path(f) and any(fnmatch.fnmatch(f, g) for g in globs)}
    return sorted(out)


def _file_text(root: str, rel: str) -> str:
    path = safe_repository_path(root, rel)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _windowed(root: str, file: str, fragments: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    """Bound oversized definitions with the same windows as large source files."""
    out: list[tuple[str, int, int]] = []
    text = ""
    for rel, start, end in fragments:
        if end - start <= _SETTINGS.target_import_context_chars_per_unit:
            out.append((rel, start, end))
            continue
        text = text or _file_text(root, file)
        windows = char_spans(text[start:end])
        if len(windows) == 1:
            out.append((rel, start, end))
            continue
        for window_start, window_end in windows:
            out.append((rel, start + window_start, start + window_end))
    return out


def _line_window(
    text: str,
    pos: int,
    *,
    before: int = _SETTINGS.callsite_context_lines_per_side,
    after: int = _SETTINGS.callsite_context_lines_per_side,
) -> tuple[int, int]:
    start = pos
    for _ in range(before + 1):
        previous = text.rfind("\n", 0, start)
        if previous < 0:
            start = 0
            break
        start = previous
    if start:
        start += 1
    end = pos
    for _ in range(after + 1):
        following = text.find("\n", end + 1)
        if following < 0:
            end = len(text)
            break
        end = following
    return start, end


def _callsite_fragments(root: str, source: str, name: str) -> list[tuple[str, int, int]]:
    """Keep bounded caller evidence beside an imported definition."""
    if len(name) < 3:
        return []
    text = _file_text(root, source)
    if not text:
        return []
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    out: list[tuple[str, int, int]] = []
    for match in pattern.finditer(text):
        fragment = (source, *_line_window(text, match.start()))
        if fragment not in out:
            out.append(fragment)
        if len(out) >= _SETTINGS.max_callsite_windows_per_symbol:
            break
    return out


def _add_import_fragment(
    per_file: dict[str, list[tuple[str, int, int]]],
    visited_files: set[str],
    next_frontier: list[str],
    *,
    source: str,
    candidate: str,
    fragment: tuple[str, int, int],
) -> None:
    file = fragment[0]
    if file in (source, candidate):
        return
    bucket = per_file.setdefault(file, [])
    if fragment not in bucket:
        bucket.append(fragment)
    if file not in visited_files:
        visited_files.add(file)
        next_frontier.append(file)


def _definition_index(callgraph: dict) -> dict[str, list[tuple[str, int, int]]]:
    index: dict[str, list[tuple[str, int, int]]] = {}
    for file, definitions in callgraph.items():
        for name, entries in (definitions or {}).items():
            for info in entries or ():
                span = (info or {}).get("range")
                if isinstance(span, (list, tuple)) and len(span) == 2:
                    index.setdefault(name, []).append((str(file), int(span[0]), int(span[1])))
    return index


def _import_closure_units(
    root: str,
    candidate_files: Sequence[str],
    graph: dict[str, object] | None,
) -> list[Unit]:
    """Pack two import hops from each candidate into focused source units."""
    callgraph = (graph or {}).get("callgraph") or {}
    imports = (graph or {}).get("imports") or {}
    import_targets = (graph or {}).get("import_targets") or {}
    index = _definition_index(callgraph)
    units: list[Unit] = []
    seen: set[frozenset] = set()
    for candidate in candidate_files:
        per_file: dict[str, list[tuple[str, int, int]]] = {}
        callers: dict[str, list[tuple[str, int, int]]] = {}
        frontier = [candidate]
        visited_files = {candidate}
        for _depth in range(_SETTINGS.import_closure_depth):
            next_frontier: list[str] = []
            for source in frontier:
                target_files = set(import_targets.get(source, ()))
                for name in imports.get(source, ()):
                    for fragment in index.get(name, ()):
                        _add_import_fragment(
                            per_file,
                            visited_files,
                            next_frontier,
                            source=source,
                            candidate=candidate,
                            fragment=fragment,
                        )
                if not target_files:
                    continue
                called_names = {
                    str(call)
                    for entries in (callgraph.get(source) or {}).values()
                    for info in entries or ()
                    for call in (info or {}).get("calls", ())
                }
                for name in called_names:
                    matching = [fragment for fragment in index.get(name, ()) if fragment[0] in target_files]
                    if matching:
                        bucket = callers.setdefault(matching[0][0], [])
                        for callsite in _callsite_fragments(root, source, name):
                            if callsite not in bucket:
                                bucket.append(callsite)
                    for fragment in matching:
                        _add_import_fragment(
                            per_file,
                            visited_files,
                            next_frontier,
                            source=source,
                            candidate=candidate,
                            fragment=fragment,
                        )
            frontier = next_frontier
            if not frontier:
                break
        for file, fragments in per_file.items():
            fragments = _windowed(root, file, fragments)
            fragments.sort(key=lambda fragment: fragment[1])
            chunks: list[list[tuple[str, int, int]]] = [[]]
            total = 0
            for fragment in fragments:
                size = fragment[2] - fragment[1]
                if chunks[-1] and total + size > _SETTINGS.target_import_context_chars_per_unit:
                    chunks.append([])
                    total = 0
                chunks[-1].append(fragment)
                total += size
            for chunk_index, chunk in enumerate(chunks):
                if not chunk:
                    continue
                suffix = f"#{chunk_index + 1}" if len(chunks) > 1 else ""
                unit_fragments = (*callers.get(file, ()), *chunk)
                key = frozenset(unit_fragments)
                if key in seen:
                    continue
                seen.add(key)
                files = tuple(dict.fromkeys(fragment[0] for fragment in unit_fragments))
                units.append(
                    Unit(
                        name=f"{candidate}->{file}{suffix}",
                        root=root,
                        files=files,
                        fragments=unit_fragments,
                    )
                )
    return units


def _fact_unit_specs(root: str, fact_specs: Sequence[dict[str, object]] | None) -> list[Unit]:
    """Materialize focused facts specs without interpreting profile knowledge."""
    units: list[Unit] = []
    for spec in fact_specs or ():
        fragments = tuple(
            (str(fragment[0]), int(fragment[1]), int(fragment[2]))
            for fragment in spec.get("fragments", [])
            if isinstance(fragment, (list, tuple)) and len(fragment) == 3
        )
        if not fragments:
            continue
        name = str(spec.get("name") or "")
        files = tuple(dict.fromkeys(fragment[0] for fragment in fragments))
        units.append(Unit(name=name or files[0], root=root, files=files, fragments=fragments))
    return units


def build_units(
    root: str | Path,
    candidate_files: Sequence[str],
    trace_targets: Sequence[str],
    fact_unit_specs: Sequence[dict[str, object]] | None = None,
    facts_graph: dict[str, object] | None = None,
) -> list[Unit]:
    """Cover every candidate and add focused fact and import closure units."""
    root = str(root)
    targets = list(trace_targets)
    units: list[Unit] = []
    for candidate in candidate_files:
        package = Path(candidate).parts[0] if Path(candidate).parts else ""
        related = tuple(target for target in targets if Path(target).parts and Path(target).parts[0] == package)[
            : _SETTINGS.max_related_files_per_unit
        ]
        spans = char_spans(_file_text(root, candidate))
        if len(spans) == 1:
            units.append(Unit(name=candidate, root=root, files=(candidate, *related)))
            continue
        for index, span in enumerate(spans):
            units.append(
                Unit(
                    name=f"{candidate}#{index + 1}",
                    root=root,
                    files=(candidate, *related),
                    span=span,
                )
            )
    units += _fact_unit_specs(root, fact_unit_specs)
    units += _import_closure_units(root, candidate_files, facts_graph)
    return units
