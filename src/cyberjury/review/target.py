"""Resolve operator target input into immutable repository and diff identities."""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cyberjury.canonical import canonical_sha256
from cyberjury.review.request import ReviewTargetKind
from cyberjury.sources.git import (
    GitSourceError,
    canonical_patch,
    materialize_revision,
    merge_bases,
    object_format,
    resolve_commit,
    resolve_root,
)

TARGET_SCHEMA = "cyberjury.target/v1"


class TargetResolutionError(RuntimeError):
    """Operator target input cannot identify one immutable source target."""


@dataclass(frozen=True, kw_only=True)
class PatchArtifact:
    """Exact unified diff consumed by one Diff Review."""

    text: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_text(cls, text: str) -> PatchArtifact:
        """Bind one UTF-8 patch to its content hash."""
        encoded = text.encode()
        return cls(text=text, sha256=hashlib.sha256(encoded).hexdigest(), size_bytes=len(encoded))

    def to_dict(self) -> dict[str, object]:
        """Return the strict patch wire form."""
        return {
            "media_type": "text/x-diff",
            "encoding": "utf-8",
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "text": self.text,
        }


@dataclass(frozen=True, kw_only=True)
class GitTarget:
    """Resolved Git endpoints and the exact patch base."""

    object_format: str
    requested_range: str
    range_kind: str
    left_revision: str
    right_revision: str
    patch_base_revision: str

    def to_dict(self) -> dict[str, str]:
        """Return the resolved Git comparison wire form."""
        return {
            "object_format": self.object_format,
            "requested_range": self.requested_range,
            "range_kind": self.range_kind,
            "left_revision": self.left_revision,
            "right_revision": self.right_revision,
            "patch_base_revision": self.patch_base_revision,
        }


@dataclass(frozen=True, kw_only=True)
class ResolvedTarget:
    """Canonical target identity used by source acquisition and review adapters."""

    kind: ReviewTargetKind
    repository_root: str
    git: GitTarget | None = None
    patch: PatchArtifact | None = None

    def semantic_dict(self) -> dict[str, object]:
        """Return target semantics without schema or receipt hash."""
        value: dict[str, object] = {
            "kind": self.kind,
            "repository_root": self.repository_root,
        }
        if self.kind == "diff":
            value.update(
                {
                    "git": self.git.to_dict() if self.git is not None else None,
                    "patch": self.patch.to_dict() if self.patch is not None else None,
                }
            )
        return value

    @property
    def target_sha256(self) -> str:
        """Identify this resolved target independently from capture time."""
        return canonical_sha256(self.semantic_dict())

    def to_dict(self) -> dict[str, object]:
        """Return the complete target artifact."""
        return {"schema": TARGET_SCHEMA, **self.semantic_dict(), "target_sha256": self.target_sha256}


def resolve_repository_target(repository: str | Path) -> ResolvedTarget:
    """Resolve one existing directory without claiming it is a Git revision."""
    path = Path(repository).expanduser()
    if path.is_symlink():
        raise TargetResolutionError("repository target cannot be a symlink")
    root = path.resolve()
    if not root.is_dir():
        raise TargetResolutionError(f"repository target is not a directory: {root}")
    return ResolvedTarget(
        kind="repository",
        repository_root=str(root),
    )


def _parse_git_range(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise TargetResolutionError("git range must be a nonempty trimmed string")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise TargetResolutionError("git range cannot contain whitespace or control characters")
    if value.startswith("-"):
        raise TargetResolutionError("git range cannot be a Git option")
    if "..." in value:
        if value.count("...") != 1:
            raise TargetResolutionError("git range must contain exactly two endpoints")
        left, right = value.split("...", 1)
        separator = "three-dot"
    elif ".." in value:
        if value.count("..") != 1:
            raise TargetResolutionError("git range must contain exactly two endpoints")
        left, right = value.split("..", 1)
        separator = "two-dot"
    else:
        raise TargetResolutionError("git range must use A..B or A...B")
    if not left or not right or left.startswith("-") or right.startswith("-"):
        raise TargetResolutionError("git range requires two explicit non-option endpoints")
    return left, right, separator


def resolve_diff_target(repository: str | Path, git_range: str) -> ResolvedTarget:
    """Resolve a committed two endpoint diff once and generate its canonical patch."""
    try:
        root = resolve_root(repository)
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
    left, right, range_kind = _parse_git_range(git_range)
    try:
        git_object_format = object_format(root)
        left_revision = resolve_commit(root, left)
        head_revision = resolve_commit(root, right)
        if range_kind == "three-dot":
            bases = merge_bases(root, left_revision, head_revision)
            if len(bases) != 1:
                raise TargetResolutionError("merge-base diff requires exactly one merge base")
            base_revision = bases[0]
        else:
            base_revision = left_revision
        patch_text = canonical_patch(root, base_revision, head_revision)
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
    target = ResolvedTarget(
        kind="diff",
        repository_root=str(root),
        git=GitTarget(
            object_format=git_object_format,
            requested_range=git_range,
            range_kind=range_kind,
            left_revision=left_revision,
            right_revision=head_revision,
            patch_base_revision=base_revision,
        ),
        patch=PatchArtifact.from_text(patch_text),
    )
    return target


@contextlib.contextmanager
def materialize_diff_target(target: ResolvedTarget) -> Iterator[Path]:
    """Adapt one resolved diff target to committed Git source acquisition."""
    try:
        with materialize_revision(target.repository_root, target.git.right_revision) as source_root:
            yield source_root
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
