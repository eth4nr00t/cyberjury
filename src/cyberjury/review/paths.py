"""Resolve and read repository source paths without leaving the reviewed repository."""

from __future__ import annotations

from pathlib import Path

from cyberjury.review.failures import BackendUnavailable


def read_repository_source(root: str | Path, rel: str, *, label: str) -> str | None:
    """Read one UTF-8 repository file, or None when it is absent."""
    path = Path(root) / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BackendUnavailable(f"{label} could not read source {rel}: {exc}") from exc


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
    """Reject empty, absolute, and parent traversing finding locations."""
    if not rel:
        return True
    p = Path(rel)
    return p.is_absolute() or ".." in p.parts
