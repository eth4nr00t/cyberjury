"""RepositoryModel: a language-agnostic structural map of a repository.

Lists the repository's files deterministically, with zero model calls, cacheable. It does not
parse code or enumerate framework routes: identifying the actual entrypoints is
left to the agent, guided by the matched language/framework guides under
`knowledge/guides/languages` and `knowledge/guides/frameworks`. The only deterministic help is flagging
*candidate* entrypoint files by the globs a guide declares, which keeps every
language-specific and framework-specific detail in the guides and out of this module.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.detection import Detection, load_detection


@dataclass(frozen=True, kw_only=True)
class RepositoryModel:
    root: str
    files: tuple[str, ...]


def _read_files(root: Path, detection: Detection | None = None) -> tuple[str, ...]:
    """Relative paths of the files under root, skipping noise dirs and symlinks
    that escape the tree."""
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
                continue  # a symlink escaping the repository tree
        except OSError:
            continue
        out.append(str(rel))
    return tuple(sorted(out))


def build_repository_model_from_dir(root: str | Path, detection: Detection | None = None) -> RepositoryModel:
    return RepositoryModel(root=str(root), files=_read_files(Path(root), detection))


def build_repository_model(root: str | Path, files: Sequence[str]) -> RepositoryModel:
    """Build a RepositoryModel from an iterable of relative paths, for tests or callers
    that already have the file list."""
    return RepositoryModel(root=str(root), files=tuple(sorted(files)))


_SCAN_MAX_BYTES = 2_000_000


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > _SCAN_MAX_BYTES:
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
    """Files likely to define entrypoints. A file is a candidate when its path
    matches one of `globs`, or when `root` is given and its content contains one
    of `markers` the guide declares, such as a handler class or a route
    registration. The marker scan is what recovers framework entrypoints that no
    filename glob would catch, and it stays data-driven because the markers come
    from the guide. Returns a sorted list with no duplicates."""
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
    """Non-test source files that define public or exported API. A library has no application
    entrypoint, so its exported symbols are the attack surface: a consumer passes
    attacker-influenced data into them. Used as the fallback denominator when no application
    entrypoint seeds, so a library is reviewed from its public surface inward rather than not
    at all. `patterns` are per-language export regexes a guide declares, such as a capitalized
    Go function, which keeps the selection data-driven and the engine generic. A file whose
    symbols are all private matches nothing and is left out, so unreachable internal code is
    not seeded. Returns a sorted list with no duplicates."""
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


# a file longer than this many chars is reviewed in overlapping windows, not one unit
CHUNK_CHARS = 24_000
CHUNK_OVERLAP = 2_000


def construct_boundaries(text: str) -> list[int]:
    """Char indices where a line begins with a non-space character, the start of a
    top-level construct in an indented language such as Python, Go, or JavaScript. Window
    edges snap to these so a class or function is reviewed whole, not split across units."""
    starts: list[int] = []
    at_line_start = True
    for i, ch in enumerate(text):
        if at_line_start and not ch.isspace():
            starts.append(i)
        at_line_start = ch == "\n"
    return starts


def char_spans(text: str) -> list[tuple[int, int] | None]:
    """The char windows that cover `text`. Text that fits one window is reviewed whole, span
    None. Larger text is split at top-level construct boundaries so each class or function
    lands whole in one window. A single construct longer than a window is hard split with an
    overlap, so even then no boundary silently drops a construct's tail. Shared by the coded
    run's unit builder and the scaffold's agent-unit seeding, so both paths split a large
    entrypoint file the same way instead of the agent path reviewing it whole and diluting."""
    size = len(text)
    if size <= CHUNK_CHARS:
        return [None]
    boundaries = construct_boundaries(text)
    spans: list[tuple[int, int] | None] = []
    start = 0
    while True:
        target = start + CHUNK_CHARS
        if target >= size:
            spans.append((start, size))
            return spans
        within = [b for b in boundaries if start < b <= target]
        if within:
            # end at the furthest construct boundary in the window, so it splits cleanly
            end = within[-1]
            next_start = end
        else:
            # one construct is longer than a window, hard split it with an overlap
            end = target
            next_start = end - CHUNK_OVERLAP
        spans.append((start, end))
        start = next_start


def span_line_range(text: str, span: tuple[int, int]) -> tuple[int, int]:
    """The 1-based inclusive line range a char span covers, so a seeded unit points a
    sub-review at the slice it owns by line number rather than an opaque char offset."""
    start, end = span
    first = text.count("\n", 0, start) + 1
    # end sits at the next construct's first char, so step back one to stay in this slice
    last = text.count("\n", 0, max(start, end - 1)) + 1
    return first, last


def logic_layer_files(
    files: Sequence[str], *, globs: Sequence[str] = (), detection: Detection | None = None
) -> list[str]:
    """Non-test files whose path matches one of the downstream logic-layer globs,
    for example managers, controllers, dao, or services. These are not entrypoints
    but the call targets to trace into from an entrypoint, so a review does not
    stop at the view. Returns a sorted list with no duplicates."""
    det = detection or load_detection()
    globs = tuple(globs)
    out = {f for f in files if not det.is_test_path(f) and any(fnmatch.fnmatch(f, g) for g in globs)}
    return sorted(out)
