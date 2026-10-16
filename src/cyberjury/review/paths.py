"""Keep model supplied source locations inside the reviewed repository."""

from __future__ import annotations

from pathlib import Path


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


def contained_repository_path(root: str | Path, rel: str) -> Path:
    """Resolve a relative path inside the repository root or raise `ValueError`."""
    path = safe_repository_path(root, rel)
    if path is None:
        raise ValueError(f"path is outside the repository root: {rel!r}")
    return path


def normalized_location_path(rel: str) -> str:
    """Normalize one reported location path to the repository spelling used by source spans."""
    return rel.strip().replace("\\", "/").removeprefix("./")


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
