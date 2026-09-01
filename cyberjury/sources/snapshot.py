"""Capture and revalidate one source-only repository file manifest."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from cyberjury.sources.metadata import SOURCE_CONTROL_FILES

SNAPSHOT_SCHEMA = "cyberjury.source-snapshot/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCE_FILES = 200_000
_MAX_SOURCE_FILE_BYTES = 100_000_000
_MAX_SNAPSHOT_BYTES = 2_000_000_000
_WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)

type ScopeProvider = Callable[[], tuple[str, ...]]


class SourceSnapshotError(RuntimeError):
    """Source scope cannot be captured or no longer matches its manifest."""


def capture_source_snapshot(root: str | Path) -> SourceSnapshot:
    """Capture one complete source tree and preserve trusted acquisition controls."""
    source_root = Path(root).resolve()
    controls = tuple(sorted(name for name in SOURCE_CONTROL_FILES if (source_root / name).is_file()))
    return SourceSnapshot.capture(
        source_root,
        source_snapshot_files(source_root),
        scope_provider=lambda: source_snapshot_files(source_root),
        materialized_extras=controls,
    )


def source_snapshot_files(root: str | Path) -> tuple[str, ...]:
    """Enumerate the complete profile-independent source tree denominator."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise SourceSnapshotError(f"snapshot root is not a directory: {base}")
    files: list[str] = []
    for current, directories, names in os.walk(base, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directories):
            path = current_path / name
            if name == ".git":
                continue
            if path.is_symlink():
                relative = path.relative_to(base).as_posix()
                raise SourceSnapshotError(f"source directory symlink is unsupported: {relative}")
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(names):
            path = current_path / name
            relative = path.relative_to(base)
            if len(relative.parts) == 1 and (relative.name == ".git" or relative.name in SOURCE_CONTROL_FILES):
                continue
            try:
                resolved = path.resolve(strict=True)
            except OSError as exc:
                raise SourceSnapshotError(f"source path cannot be resolved: {relative.as_posix()}: {exc}") from exc
            if not resolved.is_relative_to(base):
                raise SourceSnapshotError(f"source path escapes the snapshot root: {relative.as_posix()}")
            if not resolved.is_file():
                raise SourceSnapshotError(f"source path is not a regular file: {relative.as_posix()}")
            files.append(relative.as_posix())
            if len(files) > _MAX_SOURCE_FILES:
                raise SourceSnapshotError("source snapshot exceeds the file count limit")
    return _normalized_files(files)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly: {', '.join(sorted(fields))}")
    return value


def _normalized_files(files: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    portable: set[str] = set()
    for value in files:
        if not isinstance(value, str) or not value or "\\" in value:
            raise SourceSnapshotError("snapshot file paths must be nonempty POSIX relative paths")
        path = PurePosixPath(value)
        try:
            encoded = value.encode("utf-8")
        except UnicodeError as exc:
            raise SourceSnapshotError(f"snapshot file path is not UTF-8: {value!r}") from exc
        if (
            not encoded
            or unicodedata.normalize("NFC", value) != value
            or path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or "." in path.parts
            or any(":" in part or part.endswith((" ", ".")) or _WINDOWS_RESERVED.fullmatch(part) for part in path.parts)
        ):
            raise SourceSnapshotError(f"snapshot file path is unsafe or noncanonical: {value!r}")
        folded = value.casefold()
        if folded in portable:
            raise SourceSnapshotError(f"snapshot file paths collide portably: {value!r}")
        normalized.append(value)
        portable.add(folded)
        if len(normalized) > _MAX_SOURCE_FILES:
            raise SourceSnapshotError("source snapshot exceeds the file count limit")
    ordered = tuple(sorted(normalized))
    if len(set(ordered)) != len(ordered):
        raise SourceSnapshotError("snapshot file paths must be unique")
    for value in ordered:
        parts = PurePosixPath(value).parts
        if any("/".join(parts[:index]).casefold() in portable for index in range(1, len(parts))):
            raise SourceSnapshotError(f"snapshot file path conflicts with a file parent: {value!r}")
    return ordered


@dataclass(frozen=True, kw_only=True)
class SourceFileSnapshot:
    """Exact type, mode, and content identity for one source path."""

    path: str
    kind: str
    executable: bool | None
    size_bytes: int
    content_sha256: str
    link_target: str | None = None

    def __post_init__(self) -> None:
        """Reject fields that cannot represent one exact source path."""
        _normalized_files((self.path,))
        if self.kind not in {"regular", "symlink"}:
            raise ValueError("source file kind is invalid")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("source file size is invalid")
        if not isinstance(self.content_sha256, str) or not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("source file sha256 is invalid")
        if self.kind == "regular":
            if not isinstance(self.executable, bool) or self.link_target is not None:
                raise ValueError("regular source file mode or link target is invalid")
        else:
            if (
                self.executable is not None
                or not isinstance(self.link_target, str)
                or not self.link_target
                or "\x00" in self.link_target
                or "\\" in self.link_target
                or Path(self.link_target).is_absolute()
                or unicodedata.normalize("NFC", self.link_target) != self.link_target
            ):
                raise ValueError("symlink source file fields are invalid")

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

    @classmethod
    def from_dict(cls, value: object) -> SourceFileSnapshot:
        """Parse one strict file manifest entry."""
        fields = {"path", "kind", "executable", "size_bytes", "content_sha256", "link_target"}
        return cls(**_exact(value, fields, "source file snapshot"))


def _source_file_with_content(root: Path, relative: str) -> tuple[SourceFileSnapshot, bytes]:
    path = root / relative
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if path.is_symlink():
            if not resolved.is_file():
                raise SourceSnapshotError(f"source symlink does not resolve to a regular file: {relative}")
            link_target = os.readlink(path)
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if before.st_size > _MAX_SOURCE_FILE_BYTES:
                    raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
                data = stream.read(_MAX_SOURCE_FILE_BYTES + 1)
                after = os.fstat(stream.fileno())
            if len(data) > _MAX_SOURCE_FILE_BYTES:
                raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
            changed = _stable_stat(before) != _stable_stat(after)
            changed = changed or _stable_stat(path.lstat()) != _stable_stat(metadata)
            changed = changed or os.readlink(path) != link_target
            if changed:
                raise SourceSnapshotError(f"source symlink changed while being read: {relative}")
            return (
                SourceFileSnapshot(
                    path=relative,
                    kind="symlink",
                    executable=None,
                    size_bytes=len(data),
                    content_sha256=hashlib.sha256(data).hexdigest(),
                    link_target=link_target,
                ),
                data,
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise SourceSnapshotError(f"source path is not a regular file: {relative}")
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > _MAX_SOURCE_FILE_BYTES:
                raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
            data = stream.read(_MAX_SOURCE_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(data) > _MAX_SOURCE_FILE_BYTES:
            raise SourceSnapshotError(f"source file exceeds the byte limit: {relative}")
        if _stable_stat(before) != _stable_stat(after) or _stable_stat(path.lstat()) != _stable_stat(metadata):
            raise SourceSnapshotError(f"source file changed while being read: {relative}")
        return (
            SourceFileSnapshot(
                path=relative,
                kind="regular",
                executable=bool(stat.S_IMODE(metadata.st_mode) & 0o111),
                size_bytes=len(data),
                content_sha256=hashlib.sha256(data).hexdigest(),
            ),
            data,
        )
    except SourceSnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SourceSnapshotError(f"cannot snapshot source file {relative!r}: {exc}") from exc


def _source_file(root: Path, relative: str) -> SourceFileSnapshot:
    return _source_file_with_content(root, relative)[0]


def _stable_stat(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Compare content identity fields while ignoring read-induced access time changes."""
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
    _extras: tuple[SourceFileSnapshot, ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        """Require canonical ordering and a content-derived snapshot id."""
        canonical_root = self.root.resolve()
        if canonical_root != self.root or not canonical_root.is_dir():
            raise ValueError("source snapshot root must be one canonical directory")
        paths = tuple(entry.path for entry in self.entries)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            raise ValueError("source snapshot entries must be unique and sorted")
        if not isinstance(self.snapshot_id, str) or not _SHA256.fullmatch(self.snapshot_id):
            raise ValueError("source snapshot id is invalid")
        if self.snapshot_id != self._identity(self.entries):
            raise ValueError("source snapshot id does not match its manifest")
        if self._extras:
            _normalized_files((*paths, *(entry.path for entry in self._extras)))

    @staticmethod
    def _identity(entries: tuple[SourceFileSnapshot, ...]) -> str:
        return _sha256({"schema": SNAPSHOT_SCHEMA, "files": [entry.to_dict() for entry in entries]})

    @classmethod
    def capture(
        cls,
        root: str | Path,
        files: Iterable[str],
        *,
        scope_provider: ScopeProvider | None = None,
        materialized_extras: Iterable[str] = (),
    ) -> SourceSnapshot:
        """Capture a canonical manifest without profile or analyzer identity."""
        raw_root = Path(root)
        if raw_root.is_symlink():
            raise SourceSnapshotError("snapshot root cannot be a symlink")
        canonical_root = raw_root.resolve()
        if not canonical_root.is_dir():
            raise SourceSnapshotError(f"snapshot root is not a directory: {canonical_root}")
        paths = _normalized_files(files)
        captured_list: list[tuple[SourceFileSnapshot, bytes]] = []
        total_bytes = 0
        for relative in paths:
            item = _source_file_with_content(canonical_root, relative)
            total_bytes += item[0].size_bytes
            if total_bytes > _MAX_SNAPSHOT_BYTES:
                raise SourceSnapshotError("source snapshot exceeds the total byte limit")
            captured_list.append(item)
        entries = tuple(entry for entry, _data in captured_list)
        extra_paths = _normalized_files(materialized_extras)
        if set(extra_paths).intersection(paths):
            raise SourceSnapshotError("snapshot materialized extras cannot duplicate source paths")
        extras = tuple(_source_file(canonical_root, relative) for relative in extra_paths)
        if total_bytes + sum(entry.size_bytes for entry in extras) > _MAX_SNAPSHOT_BYTES:
            raise SourceSnapshotError("source snapshot exceeds the total byte limit")
        return cls(
            root=canonical_root,
            entries=entries,
            snapshot_id=cls._identity(entries),
            _scope_provider=scope_provider,
            _extras=extras,
        )

    @property
    def files(self) -> tuple[str, ...]:
        """Return the canonical relative path denominator."""
        return tuple(entry.path for entry in self.entries)

    @property
    def total_bytes(self) -> int:
        """Return the total materialized bytes represented by the manifest."""
        return sum(entry.size_bytes for entry in self.entries)

    def to_dict(self) -> dict[str, object]:
        """Return the persistent source-only manifest."""
        return {
            "schema": SNAPSHOT_SCHEMA,
            "snapshot_id": self.snapshot_id,
            "files": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        root: str | Path,
        scope_provider: ScopeProvider | None = None,
    ) -> SourceSnapshot:
        """Restore a strict manifest and bind its runtime root."""
        data = _exact(value, {"schema", "snapshot_id", "files"}, "source snapshot")
        if data["schema"] != SNAPSHOT_SCHEMA or not isinstance(data["files"], list):
            raise ValueError("source snapshot schema is unsupported")
        return cls(
            root=Path(root).resolve(),
            entries=tuple(SourceFileSnapshot.from_dict(entry) for entry in data["files"]),
            snapshot_id=data["snapshot_id"],
            _scope_provider=scope_provider,
        )

    def matches(self) -> bool:
        """Validate the complete manifest and detect source scope additions or deletions."""
        if self._scope_provider is not None:
            try:
                current = _normalized_files(self._scope_provider())
            except Exception:
                return False
            if current != self.files:
                return False
        return self.matches_files(self.files) and self._matches_extras()

    def _matches_extras(self) -> bool:
        try:
            return all(_source_file(self.root, entry.path) == entry for entry in self._extras)
        except SourceSnapshotError:
            return False

    def matches_files(self, files: Iterable[str]) -> bool:
        """Validate selected files against the immutable manifest."""
        try:
            selected = _normalized_files(dict.fromkeys(files))
        except SourceSnapshotError:
            return False
        expected = {entry.path: entry for entry in self.entries}
        if any(relative not in expected for relative in selected):
            return False
        try:
            return all(_source_file(self.root, relative) == expected[relative] for relative in selected)
        except SourceSnapshotError:
            return False

    def matches_scope_and_files(self, files: Iterable[str]) -> bool:
        """Check denominator drift before validating one bounded source selection."""
        if self._scope_provider is not None:
            try:
                if _normalized_files(self._scope_provider()) != self.files:
                    return False
            except Exception:
                return False
        return self.matches_files(files)

    @contextlib.contextmanager
    def materialize(self, *, name: str | None = None) -> Iterator[Path]:
        """Write captured bytes to one private source root for deterministic consumers."""
        if not self.matches():
            raise SourceSnapshotError("source no longer matches its captured snapshot")
        temporary_root = Path(tempfile.mkdtemp(prefix="review-source-snapshot-"))
        source_root = temporary_root / (name or self.root.name or "source")
        source_root.mkdir(mode=0o700)
        try:
            for expected in (*self.entries, *self._extras):
                entry, data = _source_file_with_content(self.root, expected.path)
                if entry != expected:
                    raise SourceSnapshotError(f"source changed while materializing: {expected.path}")
                path = source_root / expected.path
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if entry.kind == "symlink":
                    assert entry.link_target is not None
                    if Path(entry.link_target).is_absolute():
                        raise SourceSnapshotError(f"source symlink target must be relative: {entry.path}")
                    path.symlink_to(entry.link_target)
                else:
                    path.write_bytes(data)
                    path.chmod(0o755 if entry.executable else 0o644)
            for entry in (*self.entries, *self._extras):
                path = source_root / entry.path
                if path.is_symlink():
                    try:
                        path.resolve(strict=True).relative_to(source_root)
                    except (OSError, ValueError) as exc:
                        raise SourceSnapshotError(f"materialized source symlink is unsafe: {entry.path}") from exc
            if not self.matches():
                raise SourceSnapshotError("source changed while its snapshot was being materialized")
            yield source_root
        finally:
            shutil.rmtree(temporary_root, ignore_errors=True)
