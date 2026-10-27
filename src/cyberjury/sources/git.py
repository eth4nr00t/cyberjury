"""Deterministic source and patch bytes acquired from committed Git objects."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cyberjury.sources.paths import (
    SourceSnapshotError,
    portable_paths,
    require_contained_symlinks,
    safe_link_target,
)

_MAX_GIT_BLOB_BYTES = 100_000_000
_MAX_GIT_TREE_BYTES = 2_000_000_000
_MAX_GIT_SYMLINK_BYTES = 4096
_MAX_GIT_LIST_BYTES = 100_000_000
_MAX_PATCH_BYTES = 100_000_000
_MAX_GIT_ERROR_BYTES = 1_000_000
_GIT_ENV_OVERRIDES = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
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
    output = _git_limited_bytes(repository, arguments, limit=_MAX_GIT_LIST_BYTES, label="Git output")
    try:
        return output.decode("utf-8")
    except UnicodeError as exc:
        raise GitSourceError(f"Git source acquisition failed: {exc}") from exc


def _git_limited_bytes(
    repository: str | Path,
    arguments: tuple[str, ...],
    *,
    limit: int,
    label: str,
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
            env=_git_environment(),
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr[:_MAX_GIT_ERROR_BYTES].decode("utf-8", errors="replace").strip() or "unknown Git failure"
        raise GitSourceError(f"Git source acquisition failed: {detail}") from exc
    except OSError as exc:
        raise GitSourceError(f"Git source acquisition failed: {exc}") from exc
    if len(completed.stdout) > limit:
        raise GitSourceError(f"{label} exceeds the byte limit")
    return completed.stdout


def resolve_root(repository: str | Path) -> Path:
    """Resolve one operator path to the canonical Git top level."""
    requested = Path(repository).expanduser()
    if requested.is_symlink():
        raise GitSourceError("Git repository path cannot be a symlink")
    return Path(_git(requested, "rev-parse", "--show-toplevel").strip()).resolve()


def object_format(repository: str | Path) -> str:
    """Return the repository object format."""
    value = _git(repository, "rev-parse", "--show-object-format").strip()
    if value not in {"sha1", "sha256"}:
        raise GitSourceError(f"unsupported Git object format: {value}")
    return value


def resolve_commit(repository: str | Path, revision: str) -> str:
    """Resolve one explicit revision to one immutable commit id."""
    return _git(repository, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").strip()


def merge_bases(repository: str | Path, left: str, right: str) -> tuple[str, ...]:
    """Return every merge base for two resolved commits."""
    return tuple(line for line in _git(repository, "merge-base", "--all", left, right).splitlines() if line)


def worktree_files(repository: str | Path) -> tuple[str, ...]:
    """List the tracked and unignored untracked files present in one Git work tree."""
    raw = _git_limited_bytes(
        repository,
        ("ls-files", "-z", "--cached", "--others", "--exclude-standard"),
        limit=_MAX_GIT_LIST_BYTES,
        label="Git output",
    )
    submodules = _submodule_paths(repository)
    files: list[str] = []
    for record in raw.split(b"\0"):
        if not record or record.endswith(b"/"):
            continue
        try:
            path = record.decode("utf-8")
        except UnicodeError as exc:
            raise GitSourceError("Git work tree contains a path that is not UTF-8") from exc
        if path not in submodules and os.path.lexists(Path(repository) / path):
            files.append(path)
    return tuple(dict.fromkeys(files))


def _submodule_paths(repository: str | Path) -> set[str]:
    raw = _git_limited_bytes(repository, ("ls-files", "-z", "--stage"), limit=_MAX_GIT_LIST_BYTES, label="Git output")
    paths: set[str] = set()
    for record in raw.split(b"\0"):
        header, _, path = record.partition(b"\t")
        if header.startswith(b"160000 "):
            try:
                paths.add(path.decode("utf-8"))
            except UnicodeError as exc:
                raise GitSourceError("Git index contains a submodule path that is not UTF-8") from exc
    return paths


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
        "-c",
        "diff.suppressBlankEmpty=false",
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--submodule=short",
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
    raw = _git_limited_bytes(
        repository,
        ("ls-tree", "-rz", "--full-tree", revision),
        limit=_MAX_GIT_LIST_BYTES,
        label="Git output",
    )
    blobs: list[_GitBlob] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise GitSourceError("Git tree contains a noncanonical entry") from exc
        if kind == "commit" and mode == "160000":
            continue
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise GitSourceError(f"Git tree entry is unsupported: {path!r}")
        blobs.append(_GitBlob(mode=mode, object_id=object_id, path=path))
    try:
        portable_paths(blob.path for blob in blobs)
    except SourceSnapshotError as exc:
        raise GitSourceError(f"Git tree is nonportable: {exc}") from exc
    return tuple(sorted(blobs, key=lambda item: item.path))


def _write_git_blobs(repository: str, blobs: tuple[_GitBlob, ...], source_root: Path) -> None:
    command = ["git", "-C", repository, "cat-file", "--batch"]
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
    total_bytes = 0
    with process:
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
                if size > _MAX_GIT_BLOB_BYTES:
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
                    if not safe_link_target(link_target):
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
        try:
            require_contained_symlinks(source_root, (blob.path for blob in blobs))
        except SourceSnapshotError as exc:
            raise GitSourceError(f"Git symlink escapes or is broken: {exc}") from exc
        yield source_root
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
