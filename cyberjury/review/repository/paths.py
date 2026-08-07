"""The one boundary for reading a reviewed repository's files from a path that may be.

untrusted. A candidate's `file` can come from model output during a run or from a
workspace `candidates/*.md` a prompt-injected agent or a manual edit wrote. Joined
naively, an absolute path discards the root and a `../` segment escapes it, so the
verifier could read and then ship a file outside the target repository to the provider.
Every workspace-to-source read goes through `safe_repository_path`, which resolves under
the root and refuses anything that escapes, mirroring the symlink containment the
repository file map already applies. `resolve_source_path` layers the name-based
fallback on top and returns only what that guard cleared.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from cyberjury.detection import Detection, load_detection


def safe_repository_path(root: str | Path, rel: str) -> Path | None:
    """Resolve `rel` under `root`, or None when it is empty, absolute, parent-traversing.

    or escapes root through a symlink. The single gate for reading a reviewed repository's
    files from a path that may come from model output or a workspace file.
    """
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
    """The file a finding's location names, or None when nothing in the repository can be it.

    A reviewer sometimes records a bare filename where the repository holds the file one or
    more directories down, and reading nothing there let a skeptic refute a real finding for
    containing no code. Two files carrying the basename would mean judging the finding
    against unrelated code, which is worse than not reading it at all.
    """
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
    """A relative path that should never name a finding's location.

    empty, absolute, or carrying a `..` segment. Used to drop a tampered or hallucinated
    location before it becomes a reportable finding, independent of whether the file exists.
    """
    if not rel:
        return True
    p = Path(rel)
    return p.is_absolute() or ".." in p.parts
