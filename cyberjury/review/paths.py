"""Keep model supplied source locations inside the reviewed repository."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from cyberjury.detection import Detection, load_detection


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


@lru_cache(maxsize=8)
def _basename_index(root: str) -> dict[str, tuple[str, ...]]:
    """So a name-based fallback can never land in a vendored copy or outside the tree."""
    det: Detection = load_detection()
    base = Path(root).resolve()
    out: dict[str, list[str]] = {}
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(base)
        if det.is_skipped_dir(rel.parts[:-1]):
            continue
        try:
            if not path.resolve().is_relative_to(base):
                continue
        except OSError:
            continue
        out.setdefault(rel.name, []).append(str(rel))
    return {name: tuple(sorted(paths)) for name, paths in out.items()}


def resolve_source_path(root: str | Path, rel: str) -> Path | None:
    """Resolve an exact path or one unambiguous basename inside the repository."""
    exact = safe_repository_path(root, rel)
    if exact is not None and exact.is_file():
        return exact
    if is_unsafe_rel(rel):
        return None
    hits = _basename_index(str(Path(root).resolve())).get(Path(rel).name, ())
    if len(hits) != 1:
        return None
    return safe_repository_path(root, hits[0])


def is_unsafe_rel(rel: str) -> bool:
    """Reject empty, absolute, and parent traversing finding locations."""
    if not rel:
        return True
    p = Path(rel)
    return p.is_absolute() or ".." in p.parts
