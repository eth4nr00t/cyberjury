"""Repository source reads by relative path, and path resolution that never leaves the reviewed repository."""

from __future__ import annotations

from pathlib import Path

from cyberjury.review.failures import BackendUnavailableError


def read_repository_source(root: str | Path, rel: str, *, label: str) -> str | None:
    """Read one UTF-8 repository file, or None when it is absent."""
    path = Path(root) / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BackendUnavailableError(f"{label} could not read source {rel}: {exc}") from exc


def normalized_location_path(rel: str) -> str:
    """Normalize one reported location path to the repository spelling used by source spans."""
    return rel.strip().replace("\\", "/").removeprefix("./")


def resolve_source_path(root: str | Path, rel: str) -> Path | None:
    """Resolve only an exact repository file path that stays inside the root."""
    if is_unsafe_rel(rel):
        return None
    base = Path(root).resolve()
    try:
        resolved = (base / rel).resolve()
    except OSError:
        return None
    return resolved if resolved.is_relative_to(base) and resolved.is_file() else None


def is_unsafe_rel(rel: str) -> bool:
    """Report whether a finding location is empty, absolute, or traverses a parent directory."""
    if not rel:
        return True
    path = Path(rel)
    return path.is_absolute() or ".." in path.parts
