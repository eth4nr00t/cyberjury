"""Capture and revalidate one source-only repository file manifest."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Literal

from cyberjury.canonical import canonical_sha256
from cyberjury.sources.git import GitSourceError, worktree_files
from cyberjury.sources.paths import (
    MAX_SOURCE_FILES,
    SourceSnapshotError,
    portable_paths,
    require_contained_symlinks,
)

SNAPSHOT_SCHEMA = "cyberjury.snapshot/v1"
_MAX_SOURCE_FILE_BYTES = 100_000_000
_MAX_SNAPSHOT_BYTES = 2_000_000_000
_READ_CHUNK_BYTES = 1_048_576

type ScopeProvider = Callable[[], tuple[str, ...]]


def _snapshot_id(entries: tuple[SourceFileSnapshot, ...]) -> str:
    return canonical_sha256({"schema": SNAPSHOT_SCHEMA, "files": [entry.to_dict() for entry in entries]})


def capture_source_snapshot(root: str | Path) -> SourceSnapshot:
    """Capture one complete source tree under a stable file scope."""
    source_root = Path(root).resolve()
    return SourceSnapshot.capture(
        source_root,
        source_snapshot_files(source_root),
        scope_provider=lambda: source_snapshot_files(source_root),
    )


def source_snapshot_files(root: str | Path) -> tuple[str, ...]:
    """List the files a review covers: Git-visible files of a work tree, or every file of a plain directory."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise SourceSnapshotError(f"snapshot root is not a directory: {base}")
    if (base / ".git").exists():
        try:
            return portable_paths(
                path
                for path in worktree_files(base)
                if not (base / path).is_symlink() or _contained_file(base, base / path)
            )
        except GitSourceError as exc:
            raise SourceSnapshotError(str(exc)) from exc
    files: list[str] = []
    for current, directories, names in os.walk(base, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directories):
            path = current_path / name
            if name == ".git":
                continue
            if path.is_symlink():
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(names):
            path = current_path / name
            relative = path.relative_to(base)
            if path.is_symlink():
                if not _contained_file(base, path):
                    continue
            elif not path.is_file():
                raise SourceSnapshotError(f"source path is not a regular file: {relative.as_posix()}")
            files.append(relative.as_posix())
            if len(files) > MAX_SOURCE_FILES:
                raise SourceSnapshotError("source snapshot exceeds the file count limit")
    return portable_paths(files)


def _contained_file(base: Path, path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return resolved.is_relative_to(base) and resolved.is_file()


@dataclass(frozen=True, kw_only=True)
class SourceFileSnapshot:
    """Exact type, mode, and content identity for one source path."""

    path: str
    kind: Literal["regular", "symlink"]
    executable: bool | None
    size_bytes: int
    content_sha256: str
    link_target: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the strict file manifest wire form."""
        return {
            "path": self.path,
            "kind": self.kind,
            "executable": self.executable,
            "size_bytes": self.size_bytes,
            "content_sha256": self.content_sha256,
            "link_target": self.link_target,
        }


def _source_file(root: Path, relative: str, sink: BinaryIO | None = None) -> SourceFileSnapshot:
    path = root / relative
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        is_symlink = path.is_symlink()
        link_target = None
        if is_symlink:
            if not resolved.is_file():
                raise SourceSnapshotError(f"source symlink does not resolve to a regular file: {relative}")
            link_target = os.readlink(path)
        elif not stat.S_ISREG(metadata.st_mode):
            raise SourceSnapshotError(f"source path is not a regular file: {relative}")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > _MAX_SOURCE_FILE_BYTES:
                raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
            while chunk := stream.read(_READ_CHUNK_BYTES):
                size += len(chunk)
                if size > _MAX_SOURCE_FILE_BYTES:
                    raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
                digest.update(chunk)
                if sink is not None:
                    sink.write(chunk)
            after = os.fstat(stream.fileno())
        changed = _stable_stat(before) != _stable_stat(after) or _stable_stat(path.lstat()) != _stable_stat(metadata)
        if is_symlink:
            if changed or os.readlink(path) != link_target:
                raise SourceSnapshotError(f"source symlink changed while being read: {relative}")
            return SourceFileSnapshot(
                path=relative,
                kind="symlink",
                executable=None,
                size_bytes=size,
                content_sha256=digest.hexdigest(),
                link_target=link_target,
            )
        if changed:
            raise SourceSnapshotError(f"source file changed while being read: {relative}")
        return SourceFileSnapshot(
            path=relative,
            kind="regular",
            executable=bool(stat.S_IMODE(metadata.st_mode) & 0o111),
            size_bytes=size,
            content_sha256=digest.hexdigest(),
        )
    except SourceSnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SourceSnapshotError(f"cannot snapshot source file {relative!r}: {exc}") from exc


def _stable_stat(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@dataclass(frozen=True, kw_only=True)
class SourceSnapshot:
    """Source-only manifest with optional live scope revalidation."""

    root: Path
    entries: tuple[SourceFileSnapshot, ...]
    snapshot_id: str
    _scope_provider: ScopeProvider | None = field(default=None, repr=False, compare=False)

    @classmethod
    def capture(
        cls,
        root: str | Path,
        files: Iterable[str],
        *,
        scope_provider: ScopeProvider | None = None,
    ) -> SourceSnapshot:
        """Capture a canonical manifest without contract or analyzer identity."""
        canonical_root = Path(root).resolve()
        entries: list[SourceFileSnapshot] = []
        total_bytes = 0
        for relative in portable_paths(files):
            entry = _source_file(canonical_root, relative)
            total_bytes += entry.size_bytes
            if total_bytes > _MAX_SNAPSHOT_BYTES:
                raise SourceSnapshotError("source snapshot exceeds the total byte limit")
            entries.append(entry)
        return cls(
            root=canonical_root,
            entries=tuple(entries),
            snapshot_id=_snapshot_id(tuple(entries)),
            _scope_provider=scope_provider,
        )

    @property
    def files(self) -> tuple[str, ...]:
        """Return the manifest's repository-relative file paths in order."""
        return tuple(entry.path for entry in self.entries)

    def to_dict(self) -> dict[str, object]:
        """Return the persistent source-only manifest."""
        return {
            "schema": SNAPSHOT_SCHEMA,
            "snapshot_id": self.snapshot_id,
            "files": [entry.to_dict() for entry in self.entries],
        }

    def matches(self) -> bool:
        """Validate the complete manifest and detect source scope additions or deletions."""
        if not self._matches_scope():
            return False
        try:
            return all(_source_file(self.root, entry.path) == entry for entry in self.entries)
        except SourceSnapshotError:
            return False

    def _matches_scope(self) -> bool:
        if self._scope_provider is None:
            return True
        try:
            return portable_paths(self._scope_provider()) == self.files
        except Exception:
            return False

    @contextlib.contextmanager
    def materialize(self, *, name: str) -> Iterator[Path]:
        """Write captured bytes to one private source root for deterministic consumers."""
        temporary_root = Path(tempfile.mkdtemp(prefix="review-source-snapshot-")).resolve()
        source_root = temporary_root / name
        source_root.mkdir(mode=0o700)
        try:
            for expected in self.entries:
                path = source_root / expected.path
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if expected.kind == "symlink":
                    entry = _source_file(self.root, expected.path)
                    if entry != expected:
                        raise SourceSnapshotError(f"source changed while materializing: {expected.path}")
                    path.symlink_to(entry.link_target)
                    continue
                with path.open("xb") as sink:
                    entry = _source_file(self.root, expected.path, sink)
                if entry != expected:
                    raise SourceSnapshotError(f"source changed while materializing: {expected.path}")
                path.chmod(0o755 if entry.executable else 0o644)
            require_contained_symlinks(source_root, self.files)
            if not self._matches_scope():
                raise SourceSnapshotError("source changed while its snapshot was being materialized")
            yield source_root
        finally:
            shutil.rmtree(temporary_root, ignore_errors=True)
