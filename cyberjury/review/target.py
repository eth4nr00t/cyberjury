"""Resolve operator target input into immutable repository and diff identities."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path

from cyberjury.sources.git import (
    GitSourceError,
    canonical_patch,
    contains_gitlink,
    index_contains_gitlink,
    materialize_revision,
    merge_bases,
    object_format,
    resolve_commit,
    resolve_root,
)
from cyberjury.sources.metadata import SourceError, read_source_acquisition

TARGET_SCHEMA = "cyberjury.resolved-target/v1"
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TargetResolutionError(RuntimeError):
    """Operator target input cannot identify one immutable source target."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly: {', '.join(sorted(fields))}")
    return value


@dataclass(frozen=True, kw_only=True)
class PatchArtifact:
    """Exact unified diff consumed by one Diff Review."""

    text: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_text(cls, text: str) -> PatchArtifact:
        """Bind one UTF-8 patch to its content hash."""
        if not isinstance(text, str):
            raise ValueError("patch text must be a string")
        encoded = text.encode()
        return cls(text=text, sha256=hashlib.sha256(encoded).hexdigest(), size_bytes=len(encoded))

    def __post_init__(self) -> None:
        """Require the patch receipt to match the exact UTF-8 text."""
        if not isinstance(self.text, str) or not isinstance(self.sha256, str) or not _SHA256.fullmatch(self.sha256):
            raise ValueError("patch sha256 is invalid")
        encoded = self.text.encode()
        if hashlib.sha256(encoded).hexdigest() != self.sha256:
            raise ValueError("patch sha256 does not match its text")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
            or self.size_bytes != len(encoded)
        ):
            raise ValueError("patch size does not match its text")

    def to_dict(self) -> dict[str, object]:
        """Return the strict patch wire form."""
        return {
            "media_type": "text/x-diff",
            "encoding": "utf-8",
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "text": self.text,
        }

    @classmethod
    def from_dict(cls, value: object) -> PatchArtifact:
        """Parse one strict patch artifact."""
        data = _exact(value, {"media_type", "encoding", "sha256", "size_bytes", "text"}, "patch")
        if data["media_type"] != "text/x-diff" or data["encoding"] != "utf-8":
            raise ValueError("patch media type is unsupported")
        if not isinstance(data["text"], str):
            raise ValueError("patch text must be a string")
        return cls(text=data["text"], sha256=data["sha256"], size_bytes=data["size_bytes"])


@dataclass(frozen=True, kw_only=True)
class GitTarget:
    """Resolved Git endpoints and the exact patch base."""

    object_format: str
    requested_range: str
    range_kind: str
    left_revision: str
    right_revision: str
    patch_base_revision: str

    def __post_init__(self) -> None:
        """Validate every object id against the repository object format."""
        lengths = {"sha1": 40, "sha256": 64}
        length = lengths.get(self.object_format)
        if length is None or self.range_kind not in {"two-dot", "three-dot"}:
            raise ValueError("Git target format or range kind is invalid")
        if not isinstance(self.requested_range, str) or not self.requested_range:
            raise ValueError("Git target requested range is invalid")
        for revision in (self.left_revision, self.right_revision, self.patch_base_revision):
            if not isinstance(revision, str) or len(revision) != length or not _OBJECT_ID.fullmatch(revision):
                raise ValueError("Git target revision is invalid")

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

    @classmethod
    def from_dict(cls, value: object) -> GitTarget:
        """Parse one strict Git comparison."""
        fields = {
            "object_format",
            "requested_range",
            "range_kind",
            "left_revision",
            "right_revision",
            "patch_base_revision",
        }
        return cls(**_exact(value, fields, "Git target"))


@dataclass(frozen=True, kw_only=True)
class ResolvedTarget:
    """Canonical target identity used by source acquisition and review adapters."""

    kind: str
    repository_root: str
    source_acquisition_sha256: str | None = None
    git: GitTarget | None = None
    patch: PatchArtifact | None = None

    def __post_init__(self) -> None:
        """Reject fields outside the selected target variant."""
        if self.kind not in {"diff", "repository"}:
            raise ValueError("resolved target kind is invalid")
        root = Path(self.repository_root)
        if not root.is_absolute() or str(root.resolve()) != self.repository_root:
            raise ValueError("resolved repository root must be canonical and absolute")
        if self.source_acquisition_sha256 is not None and not _SHA256.fullmatch(self.source_acquisition_sha256):
            raise ValueError("resolved source acquisition sha256 is invalid")
        if self.kind == "repository":
            if self.git is not None or self.patch is not None:
                raise ValueError("repository target cannot have diff fields")
            return
        if not isinstance(self.git, GitTarget) or not isinstance(self.patch, PatchArtifact):
            raise ValueError("diff target fields are incomplete or invalid")

    def semantic_dict(self) -> dict[str, object]:
        """Return target semantics without schema or receipt hash."""
        value: dict[str, object] = {
            "kind": self.kind,
            "repository_root": self.repository_root,
            "source_acquisition_sha256": self.source_acquisition_sha256,
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
        return _sha256(self.semantic_dict())

    def to_dict(self) -> dict[str, object]:
        """Return the complete target artifact."""
        return {"schema": TARGET_SCHEMA, **self.semantic_dict(), "target_sha256": self.target_sha256}

    @classmethod
    def from_dict(cls, value: object) -> ResolvedTarget:
        """Parse and verify one complete target artifact."""
        if not isinstance(value, dict):
            raise ValueError("resolved target must be a JSON object")
        kind = value.get("kind")
        fields = {"schema", "kind", "repository_root", "source_acquisition_sha256", "target_sha256"}
        if kind == "diff":
            fields.update({"git", "patch"})
        data = _exact(value, fields, "resolved target")
        if data["schema"] != TARGET_SCHEMA:
            raise ValueError("resolved target schema is unsupported")
        target = cls(
            kind=data["kind"],
            repository_root=data["repository_root"],
            source_acquisition_sha256=data["source_acquisition_sha256"],
            git=GitTarget.from_dict(data["git"]) if "git" in data else None,
            patch=PatchArtifact.from_dict(data["patch"]) if "patch" in data else None,
        )
        if data["target_sha256"] != target.target_sha256:
            raise ValueError("resolved target hash does not match its content")
        return target


def resolve_repository_target(repository: str | Path) -> ResolvedTarget:
    """Resolve one existing directory without claiming it is a Git revision."""
    path = Path(repository).expanduser()
    if path.is_symlink():
        raise TargetResolutionError("repository target cannot be a symlink")
    root = path.resolve()
    if not root.is_dir():
        raise TargetResolutionError(f"repository target is not a directory: {root}")
    try:
        acquisition = read_source_acquisition(root)
        if (root / ".git").exists() and index_contains_gitlink(root):
            raise TargetResolutionError("Git submodules require verified recursive source acquisition")
    except SourceError as exc:
        raise TargetResolutionError(f"verified source acquisition is invalid: {exc}") from exc
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
    return ResolvedTarget(
        kind="repository",
        repository_root=str(root),
        source_acquisition_sha256=acquisition.acquisition_sha256 if acquisition is not None else None,
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
        separator = "merge-base"
    elif ".." in value:
        if value.count("..") != 1:
            raise TargetResolutionError("git range must contain exactly two endpoints")
        left, right = value.split("..", 1)
        separator = "endpoints"
    else:
        raise TargetResolutionError("git range must use A..B or A...B")
    if not left or not right or left.startswith("-") or right.startswith("-"):
        raise TargetResolutionError("git range requires two explicit non-option endpoints")
    return left, right, separator


def resolve_git_root(repository: str | Path) -> Path:
    """Resolve one operator path to the canonical Git top level."""
    try:
        return resolve_root(repository)
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc


def resolve_diff_target(repository: str | Path, git_range: str) -> ResolvedTarget:
    """Resolve a committed two endpoint diff once and generate its canonical patch."""
    root = resolve_git_root(repository)
    left, right, range_kind = _parse_git_range(git_range)
    try:
        git_object_format = object_format(root)
        left_revision = resolve_commit(root, left)
        head_revision = resolve_commit(root, right)
        if range_kind == "merge-base":
            bases = merge_bases(root, left_revision, head_revision)
            if len(bases) != 1 or not _OBJECT_ID.fullmatch(bases[0]):
                raise TargetResolutionError("merge-base diff requires exactly one merge base")
            base_revision = bases[0]
        else:
            base_revision = left_revision
        if any(contains_gitlink(root, revision) for revision in {base_revision, head_revision}):
            raise TargetResolutionError("Git submodules require verified recursive source acquisition")
        patch_text = canonical_patch(root, base_revision, head_revision)
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
    target = ResolvedTarget(
        kind="diff",
        repository_root=str(root),
        git=GitTarget(
            object_format=git_object_format,
            requested_range=git_range,
            range_kind="three-dot" if range_kind == "merge-base" else "two-dot",
            left_revision=left_revision,
            right_revision=head_revision,
            patch_base_revision=base_revision,
        ),
        patch=PatchArtifact.from_text(patch_text),
    )
    try:
        with materialize_diff_target(target) as source_root:
            acquisition = read_source_acquisition(source_root)
    except SourceError as exc:
        raise TargetResolutionError(f"verified source acquisition is invalid: {exc}") from exc
    if acquisition is not None:
        target = replace(target, source_acquisition_sha256=acquisition.acquisition_sha256)
    return target


@contextlib.contextmanager
def materialize_diff_target(target: ResolvedTarget) -> Iterator[Path]:
    """Adapt one resolved diff target to committed Git source acquisition."""
    if target.kind != "diff" or target.git is None:
        raise ValueError("only a resolved diff target can be materialized")
    try:
        with materialize_revision(target.repository_root, target.git.right_revision) as source_root:
            yield source_root
    except GitSourceError as exc:
        raise TargetResolutionError(str(exc)) from exc
