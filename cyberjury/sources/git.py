"""Acquire deterministic source and patch bytes from committed Git objects."""

from __future__ import annotations

import contextlib
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)
_MAX_GIT_FILES = 200_000
_MAX_GIT_BLOB_BYTES = 100_000_000
_MAX_GIT_TREE_BYTES = 2_000_000_000
_MAX_GIT_SYMLINK_BYTES = 4096
_MAX_GIT_LIST_BYTES = 100_000_000
_MAX_PATCH_BYTES = 100_000_000
_MAX_GIT_ERROR_BYTES = 1_000_000
_GIT_ENV_OVERRIDES = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
}


class GitSourceError(RuntimeError):
    """Committed Git source cannot be acquired exactly."""


def _git_environment() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key not in _GIT_ENV_OVERRIDES}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    return env


def _git(repository: str | Path, *arguments: str) -> str:
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=_git_environment(),
        ).stdout
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        raise GitSourceError(f"Git source acquisition failed: {detail}") from exc


def _git_bytes(repository: str | Path, *arguments: str) -> bytes:
    return _git_limited_bytes(repository, arguments, limit=_MAX_GIT_LIST_BYTES, label="Git output")


def _git_limited_bytes(
    repository: str | Path,
    arguments: tuple[str, ...],
    *,
    limit: int,
    label: str,
) -> bytes:
    try:
        process = subprocess.Popen(
            ["git", "--no-replace-objects", "-C", str(repository), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise GitSourceError(f"Git source acquisition failed: {exc}") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise GitSourceError("Git source acquisition has no output pipes")
    output = bytearray()
    error = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, output)
    selector.register(process.stderr, selectors.EVENT_READ, error)
    try:
        while selector.get_map():
            for key, _events in selector.select():
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = key.data
                if buffer is output:
                    output.extend(chunk)
                    if len(output) > limit:
                        raise GitSourceError(f"{label} exceeds the byte limit")
                elif len(error) < _MAX_GIT_ERROR_BYTES:
                    error.extend(chunk[: _MAX_GIT_ERROR_BYTES - len(error)])
        if process.wait() != 0:
            detail = error.decode("utf-8", errors="replace").strip() or "unknown Git failure"
            raise GitSourceError(f"Git source acquisition failed: {detail}")
        return bytes(output)
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()


def resolve_root(repository: str | Path) -> Path:
    """Resolve one operator path to the canonical Git top level."""
    requested = Path(repository).expanduser()
    if requested.is_symlink():
        raise GitSourceError("diff repository cannot be a symlink")
    root = Path(_git(requested, "rev-parse", "--show-toplevel").strip()).resolve()
    if not root.is_dir():
        raise GitSourceError("Git top level is not an accessible directory")
    return root


def object_format(repository: str | Path) -> str:
    """Return the repository object format."""
    value = _git(repository, "rev-parse", "--show-object-format").strip()
    if value not in {"sha1", "sha256"}:
        raise GitSourceError(f"unsupported Git object format: {value}")
    return value


def resolve_commit(repository: str | Path, revision: str) -> str:
    """Resolve one explicit revision to one immutable commit id."""
    value = _git(repository, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").strip()
    if not _OBJECT_ID.fullmatch(value):
        raise GitSourceError(f"Git revision did not resolve to one commit: {revision}")
    return value


def merge_bases(repository: str | Path, left: str, right: str) -> tuple[str, ...]:
    """Return every merge base for two resolved commits."""
    return tuple(line for line in _git(repository, "merge-base", "--all", left, right).splitlines() if line)


def contains_gitlink(repository: str | Path, revision: str) -> bool:
    """Report whether one committed tree depends on an unacquired submodule tree."""
    tree = _git(repository, "ls-tree", "-r", revision)
    return any(line.startswith("160000 ") for line in tree.splitlines())


def index_contains_gitlink(repository: str | Path) -> bool:
    """Report whether a live repository index contains a submodule entry."""
    return any(line.startswith("160000 ") for line in _git(repository, "ls-files", "--stage").splitlines())


def canonical_patch(repository: str | Path, base_revision: str, head_revision: str) -> str:
    """Generate one patch independent from operator Git diff configuration."""
    arguments = (
        "-c",
        "color.ui=false",
        "-c",
        "core.quotePath=true",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "diff.mnemonicPrefix=false",
        "-c",
        "diff.noprefix=false",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--find-renames=50%",
        "--abbrev=7",
        "--diff-algorithm=myers",
        "--indent-heuristic",
        "--inter-hunk-context=0",
        "--unified=3",
        f"-O{os.devnull}",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        base_revision,
        head_revision,
        "--",
    )
    try:
        return _git_limited_bytes(
            repository,
            arguments,
            limit=_MAX_PATCH_BYTES,
            label="Git patch",
        ).decode("utf-8")
    except UnicodeError as exc:
        raise GitSourceError("Git patch is not UTF-8") from exc


@dataclass(frozen=True, kw_only=True)
class _GitBlob:
    mode: str
    object_id: str
    path: str


def _git_blobs(repository: str, revision: str) -> tuple[_GitBlob, ...]:
    raw = _git_bytes(repository, "ls-tree", "-rz", "--full-tree", revision)
    blobs: list[_GitBlob] = []
    portable_paths: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise GitSourceError("Git tree contains a noncanonical entry") from exc
        candidate = PurePosixPath(path)
        portable = path.casefold()
        invalid_segment = any(
            ":" in part or part.endswith((" ", ".")) or _WINDOWS_RESERVED.fullmatch(part) for part in candidate.parts
        )
        if (
            kind != "blob"
            or mode not in {"100644", "100755", "120000"}
            or candidate.is_absolute()
            or candidate.as_posix() != path
            or ".." in candidate.parts
            or unicodedata.normalize("NFC", path) != path
            or invalid_segment
            or portable in portable_paths
        ):
            raise GitSourceError(f"Git tree entry is unsupported or nonportable: {path!r}")
        portable_paths.add(portable)
        blobs.append(_GitBlob(mode=mode, object_id=object_id, path=path))
        if len(blobs) > _MAX_GIT_FILES:
            raise GitSourceError("Git tree exceeds the file count limit")
    for blob in blobs:
        parts = PurePosixPath(blob.path).parts
        if any("/".join(parts[:index]).casefold() in portable_paths for index in range(1, len(parts))):
            raise GitSourceError(f"Git tree path conflicts with a file parent: {blob.path!r}")
    return tuple(sorted(blobs, key=lambda item: item.path))


def _write_git_blobs(repository: str, blobs: tuple[_GitBlob, ...], source_root: Path) -> None:
    command = ["git", "--no-replace-objects", "-C", repository, "cat-file", "--batch"]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
        )
    except OSError as exc:
        raise GitSourceError(f"Git blob reader could not start: {exc}") from exc
    if process.stdin is None or process.stdout is None:
        process.kill()
        raise GitSourceError("Git blob reader has no pipes")
    total_bytes = 0
    try:
        for blob in blobs:
            process.stdin.write(blob.object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii").strip().split(" ")
            if len(header) != 3 or header[0] != blob.object_id or header[1] != "blob":
                raise GitSourceError(f"Git object is not the expected blob for {blob.path!r}")
            try:
                size = int(header[2])
            except ValueError as exc:
                raise GitSourceError(f"Git blob size is invalid for {blob.path!r}") from exc
            if size < 0 or size > _MAX_GIT_BLOB_BYTES:
                raise GitSourceError(f"Git blob exceeds the byte limit: {blob.path!r}")
            total_bytes += size
            if total_bytes > _MAX_GIT_TREE_BYTES:
                raise GitSourceError("Git tree exceeds the total byte limit")
            path = source_root / blob.path
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if blob.mode == "120000":
                if size > _MAX_GIT_SYMLINK_BYTES:
                    raise GitSourceError(f"Git symlink target exceeds the byte limit: {blob.path!r}")
                content = process.stdout.read(size)
                if len(content) != size:
                    raise GitSourceError(f"Git blob is truncated for {blob.path!r}")
                try:
                    link_target = content.decode("utf-8")
                except UnicodeError as exc:
                    raise GitSourceError(f"Git symlink target is not UTF-8: {blob.path!r}") from exc
                if (
                    Path(link_target).is_absolute()
                    or "\x00" in link_target
                    or "\\" in link_target
                    or unicodedata.normalize("NFC", link_target) != link_target
                ):
                    raise GitSourceError(f"Git symlink target must be relative: {blob.path!r}")
                path.symlink_to(link_target)
            else:
                remaining = size
                with path.open("xb") as stream:
                    while remaining:
                        chunk = process.stdout.read(min(1_048_576, remaining))
                        if not chunk:
                            raise GitSourceError(f"Git blob is truncated for {blob.path!r}")
                        stream.write(chunk)
                        remaining -= len(chunk)
                path.chmod(0o755 if blob.mode == "100755" else 0o644)
            if process.stdout.read(1) != b"\n":
                raise GitSourceError(f"Git blob is truncated for {blob.path!r}")
        process.stdin.close()
        if process.wait() != 0:
            raise GitSourceError("Git blob reader failed")
    except BaseException:
        process.kill()
        process.wait()
        raise


@contextlib.contextmanager
def materialize_revision(repository: str | Path, revision: str) -> Iterator[Path]:
    """Materialize exact Git blobs without checkout filters, hooks, or line conversion."""
    temporary_root = Path(tempfile.mkdtemp(prefix="review-git-source-"))
    source_root = temporary_root / Path(repository).name
    try:
        source_root.mkdir(mode=0o700)
        blobs = _git_blobs(str(repository), revision)
        _write_git_blobs(str(repository), blobs, source_root)
        for blob in blobs:
            path = source_root / blob.path
            if path.is_symlink():
                try:
                    path.resolve(strict=True).relative_to(source_root)
                except (OSError, ValueError) as exc:
                    raise GitSourceError(f"Git symlink escapes or is broken: {blob.path!r}") from exc
        yield source_root
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
