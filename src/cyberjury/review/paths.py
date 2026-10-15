"""Keep model supplied source locations inside the reviewed repository."""

from __future__ import annotations

from pathlib import Path

from cyberjury.detection import Detection


class RepositoryPathError(RuntimeError):
    """Repository inventory contains a path that cannot be reviewed safely."""


def safe_repository_path(root: str | Path, rel: str) -> Path | None:
    """Resolve a relative path only when it remains inside the repository root."""
    if not rel:
        return None
    base = Path(root).resolve()
    try:
        resolved = (base / rel).resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(base) else None


def repository_files(root: str | Path, detection: Detection) -> tuple[str, ...]:
    """List boundary safe repository files while pruning configured noise directories."""
    base = Path(root).resolve()
    files: list[str] = []
    for path in base.rglob("*"):
        rel = path.relative_to(base)
        if rel.parts and rel.parts[0] == ".git":
            continue
        if detection.is_skipped_dir(rel.parts[:-1]):
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RepositoryPathError(f"repository path cannot be resolved: {rel.as_posix()}: {exc}") from exc
        if not resolved.is_relative_to(base):
            raise RepositoryPathError(f"repository path escapes the source root: {rel.as_posix()}")
        if path.is_symlink() and resolved.is_dir():
            raise RepositoryPathError(f"repository directory symlink is unsupported: {rel.as_posix()}")
        if not resolved.is_file():
            raise RepositoryPathError(f"repository path is not a regular file: {rel.as_posix()}")
        files.append(rel.as_posix())
    return tuple(sorted(files))


def source_navigation_files(root: str | Path, detection: Detection) -> tuple[str, ...]:
    """Publish readable production source plus readable documentation to navigation."""
    from cyberjury.selection import source_files

    base = Path(root)
    files = list(source_files(base, detection))
    for file in repository_files(base, detection):
        if Path(file).suffix.lower() not in detection.doc_extensions:
            continue
        try:
            (base / file).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        files.append(file)
    return tuple(dict.fromkeys(files))


def resolve_source_path(root: str | Path, rel: str) -> Path | None:
    """Resolve only an exact safe repository file path."""
    if is_unsafe_rel(rel):
        return None
    exact = safe_repository_path(root, rel)
    return exact if exact is not None and exact.is_file() else None


def is_unsafe_rel(rel: str) -> bool:
    """Reject empty, absolute, and parent traversing finding locations."""
    if not rel:
        return True
    p = Path(rel)
    return p.is_absolute() or ".." in p.parts
