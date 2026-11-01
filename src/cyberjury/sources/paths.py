"""Canonical source path rules and read limits shared by snapshots and Git materialization."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath

MAX_SOURCE_FILES = 200_000
MAX_SOURCE_FILE_BYTES = 100_000_000
MAX_SOURCE_TREE_BYTES = 2_000_000_000
READ_CHUNK_BYTES = 1_048_576


class SourceSnapshotError(RuntimeError):
    """Source scope cannot be captured or no longer matches its manifest."""


def portable_paths(files: Iterable[str]) -> tuple[str, ...]:
    """Return sorted unique canonical POSIX relative paths that stay inside their root."""
    normalized: list[str] = []
    for value in files:
        if not value or "\\" in value:
            raise SourceSnapshotError("snapshot file paths must be nonempty POSIX relative paths")
        path = PurePosixPath(value)
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise SourceSnapshotError(f"snapshot file path is not UTF-8: {value!r}") from exc
        if path.is_absolute() or path.as_posix() != value or ".." in path.parts or "." in path.parts:
            raise SourceSnapshotError(f"snapshot file path is unsafe or noncanonical: {value!r}")
        normalized.append(value)
        if len(normalized) > MAX_SOURCE_FILES:
            raise SourceSnapshotError("source snapshot exceeds the file count limit")
    ordered = tuple(sorted(normalized))
    if len(set(ordered)) != len(ordered):
        raise SourceSnapshotError("snapshot file paths must be unique")
    return ordered


def safe_link_target(target: str) -> bool:
    """Accept only a nonempty, relative POSIX symlink target."""
    return bool(target) and "\x00" not in target and "\\" not in target and not Path(target).is_absolute()


def contained_target(root: Path, path: Path) -> Path | None:
    """Return the existing target a path resolves to when it stays inside the resolved root."""
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_relative_to(root) else None


def require_contained_symlinks(root: Path, files: Iterable[str]) -> None:
    """Fail when any materialized symlink is broken or resolves outside its root."""
    for relative in files:
        path = root / relative
        if path.is_symlink() and contained_target(root, path) is None:
            raise SourceSnapshotError(f"materialized source symlink is unsafe: {relative}")
