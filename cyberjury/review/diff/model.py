"""Parse a unified diff into bounded, reviewable file batches."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.detection import Detection, load_detection
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.diff


@dataclass(frozen=True, kw_only=True)
class DiffUnit:
    """One diff batch and its reportable source paths."""

    index: int
    total: int
    diff: str
    paths: tuple[str, ...]


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
            return candidate[2:] if candidate[:2] in ("a/", "b/") else candidate
    tail = git.partition(" b/")[2]
    return tail.strip() if tail else ""


def batch_paths(batch: str) -> tuple[str, ...]:
    """Return every readable path represented by one diff batch."""
    paths = tuple(path for chunk in split_diff_by_file(batch) if (path := chunk_path(chunk)))
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
