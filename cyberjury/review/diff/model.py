"""Parse a unified diff into reviewable, related file batches."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from cyberjury.detection import Detection, load_detection
from cyberjury.review.diff.context import changed_call_names

MAX_DIFF_CHARS = 60_000
_MAX_SHARED_NAME_FILES = 4


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


def pack_diff_chunks(diff: str, max_chars: int = MAX_DIFF_CHARS) -> list[str]:
    """Pack related per-file chunks without splitting one file mid hunk."""
    chunks = split_diff_by_file(diff)
    names = [changed_call_names(_changed_lines(chunk)) for chunk in chunks]
    frequencies = Counter(name for chunk_names in names for name in chunk_names)
    remaining = list(range(len(chunks)))
    batches: list[str] = []
    while remaining:
        members = [remaining.pop(0)]
        size = len(chunks[members[0]])
        current_names = set(names[members[0]])
        while candidates := [index for index in remaining if size + len(chunks[index]) <= max_chars]:
            chosen = max(
                candidates,
                key=lambda index: (_chunk_affinity(names[index], current_names, frequencies), -index),
            )
            remaining.remove(chosen)
            members.append(chosen)
            size += len(chunks[chosen])
            current_names.update(names[chosen])
        batches.append("".join(chunks[index] for index in members))
    return batches


def diff_units(diff: str) -> list[DiffUnit]:
    """Build the complete ordered worklist for one diff review."""
    batches = pack_diff_chunks(diff, MAX_DIFF_CHARS) if len(diff) > MAX_DIFF_CHARS else [diff]
    return [
        DiffUnit(index=index, total=len(batches), diff=batch, paths=batch_paths(batch))
        for index, batch in enumerate(batches, 1)
    ]


def _changed_lines(chunk: str) -> str:
    return "\n".join(
        line[1:] for line in chunk.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )


def _chunk_affinity(names: set[str], current: set[str], frequencies: Counter[str]) -> int:
    return sum(
        len(name) * (_MAX_SHARED_NAME_FILES + 1 - frequencies[name])
        for name in names.intersection(current)
        if 1 < frequencies[name] <= _MAX_SHARED_NAME_FILES
    )
