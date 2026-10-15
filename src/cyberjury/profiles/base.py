"""Bind one general review contract to optional facts and proof backends."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cyberjury.canonical import canonical_sha256
from cyberjury.sources.snapshot import SourceFileSnapshot, snapshot_id_for_entries

if TYPE_CHECKING:
    from cyberjury.providers.base import Provider
    from cyberjury.review.facts import FactsBackend
    from cyberjury.sources.snapshot import SourceSnapshot

__all__ = [
    "ContentPaths",
    "PoCArtifact",
    "PoCBackend",
    "PoCBackendFactory",
    "ProfileBinding",
    "ReviewProfile",
    "bind_profile_content",
    "content_paths",
    "profile_binding",
    "profile_content_snapshot",
    "validate_profile",
]

PROFILE_BINDING_SCHEMA = "cyberjury.profile-binding/v4"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """Resolve the kernel, role assets, and file classification data."""

    root: Path
    security_kernel_file: Path
    severity_rubric_file: Path
    detection_file: Path


def content_paths(content_root: str | Path) -> ContentPaths:
    """Resolve the shared content layout under a backend root."""
    root = Path(content_root)
    knowledge = root / "knowledge"
    playbook = root / "playbook"
    return ContentPaths(
        root=root,
        security_kernel_file=knowledge / "security-kernel.md",
        severity_rubric_file=playbook / "severity-rubric.md",
        detection_file=root / "detection.yaml",
    )


@dataclass(frozen=True, kw_only=True)
class PoCArtifact:
    """Optional proof of concept evidence returned after successful generation.

    `source` is the runnable text and `run_hint` states how a human runs it. The backend owns
    the persisted file suffix. An absent artifact or a generation failure never refutes the finding.
    """

    source: str
    run_hint: str = ""


@runtime_checkable
class PoCBackend(Protocol):
    """Generate a script for manual reproduction in a sandbox."""

    ext: str

    def generate(
        self,
        *,
        title: str,
        analysis: str,
        symbol: str,
        file: str,
        line: int | None,
        source: str,
        endpoint: str = "",
    ) -> PoCArtifact:
        """Produce one artifact from the reviewed `source` text of `file` without executing it."""


class PoCBackendFactory(Protocol):
    """Keep provider imports lazy until the selected profile needs PoC generation."""

    def __call__(
        self,
        *,
        provider: Provider,
        model: str,
    ) -> PoCBackend:
        """Use the selected model without widening the profile import boundary."""


@dataclass(frozen=True, kw_only=True)
class ReviewProfile:
    """Bind generic review behavior to replaceable facts and proof backends."""

    name: str
    content_root: Path
    facts_backend: FactsBackend | None = None
    poc_backend: PoCBackendFactory | None = None

    @property
    def paths(self) -> ContentPaths:
        """Return the resolved content paths for this profile."""
        return content_paths(self.content_root)


@dataclass(frozen=True, kw_only=True)
class ProfileBinding:
    """Persist the complete review behavior selected from one profile."""

    name: str
    content_snapshot_id: str
    content_files: tuple[SourceFileSnapshot, ...]
    facts_backend_id: str
    poc_backend_id: str | None
    profile_sha256: str

    def __post_init__(self) -> None:
        """Reject profile receipts that cannot identify one complete binding."""
        if not isinstance(self.name, str) or not _PROFILE_NAME.fullmatch(self.name):
            raise ValueError("profile binding name is invalid")
        for value in (self.content_snapshot_id, self.profile_sha256):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError("profile binding hash is invalid")
        paths = tuple(entry.path for entry in self.content_files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("profile content files must be unique and sorted")
        if snapshot_id_for_entries(self.content_files) != self.content_snapshot_id:
            raise ValueError("profile content files do not match the content snapshot id")
        if not isinstance(self.facts_backend_id, str) or not self.facts_backend_id:
            raise ValueError("profile facts backend identity is invalid")
        if self.poc_backend_id is not None and (not isinstance(self.poc_backend_id, str) or not self.poc_backend_id):
            raise ValueError("profile PoC backend identity is invalid")
        if self.profile_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("profile binding hash does not match its content")

    def semantic_dict(self) -> dict[str, object]:
        """Return every behavior field covered by the profile receipt."""
        return {
            "name": self.name,
            "content_snapshot_id": self.content_snapshot_id,
            "facts_backend_id": self.facts_backend_id,
            "poc_backend_id": self.poc_backend_id,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict persistent profile binding."""
        return {
            "schema": PROFILE_BINDING_SCHEMA,
            **self.semantic_dict(),
            "content_files": [entry.to_dict() for entry in self.content_files],
            "profile_sha256": self.profile_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProfileBinding:
        """Parse and verify one persistent profile binding."""
        fields = {
            "schema",
            "name",
            "content_snapshot_id",
            "content_files",
            "facts_backend_id",
            "poc_backend_id",
            "profile_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("profile binding must contain the exact supported fields")
        if value["schema"] != PROFILE_BINDING_SCHEMA:
            raise ValueError("profile binding schema is unsupported")
        data = {key: item for key, item in value.items() if key not in {"schema", "content_files"}}
        content_files = value["content_files"]
        if not isinstance(content_files, list):
            raise ValueError("profile content files must be a list")
        return cls(
            **data,
            content_files=tuple(SourceFileSnapshot.from_dict(item) for item in content_files),
        )


def _implementation_identity(value: object) -> str:
    module = getattr(value, "__module__", type(value).__module__)
    qualname = getattr(value, "__qualname__", type(value).__qualname__)
    identity = f"{module}.{qualname}"
    if not module or not qualname:
        raise ValueError("profile backend identity is unavailable")
    return identity


def _profile_content_files(root: Path) -> tuple[str, ...]:
    from cyberjury.sources.snapshot import source_snapshot_files

    return tuple(
        path
        for path in source_snapshot_files(root)
        if "__pycache__" not in Path(path).parts and Path(path).suffix not in {".pyc", ".pyo"}
    )


def validate_profile(profile: ReviewProfile) -> None:
    """Fail before review when a registered profile is behaviorally incomplete."""
    from cyberjury.detection import load_detection

    if profile.facts_backend is None:
        raise ValueError(f"review profile {profile.name!r} has no facts backend")
    paths = profile.paths
    for path in (
        paths.security_kernel_file,
        paths.severity_rubric_file,
        paths.detection_file,
    ):
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            relative = path.relative_to(profile.content_root)
            raise ValueError(f"review profile {profile.name!r} content file is missing or empty: {relative}")
    load_detection(paths.detection_file)
    try:
        profile.facts_backend.validate_content(paths)
    except Exception as exc:
        raise ValueError(
            f"review profile {profile.name!r} facts backend content is invalid: {type(exc).__name__}: {exc}"
        ) from exc


def profile_content_snapshot(profile: ReviewProfile) -> SourceSnapshot:
    """Capture the exact profile package content consumed by one command."""
    from cyberjury.sources.snapshot import SourceSnapshot

    if profile.content_root.is_symlink() or profile.content_root.resolve() != profile.content_root:
        raise ValueError(f"review profile {profile.name!r} content root must be canonical and absolute")
    root = profile.content_root
    files = _profile_content_files(root)
    snapshot = SourceSnapshot.capture(root, files, scope_provider=lambda: _profile_content_files(root))
    if not snapshot.matches():
        raise ValueError(f"review profile {profile.name!r} content changed while it was being bound")
    return snapshot


def profile_binding(
    profile: ReviewProfile,
    *,
    content_snapshot: SourceSnapshot | None = None,
) -> ProfileBinding:
    """Validate and bind every profile behavior input to one receipt."""
    snapshot = content_snapshot or profile_content_snapshot(profile)
    validate_profile(profile)
    if snapshot.root != profile.content_root.resolve() or not snapshot.matches():
        raise ValueError(f"review profile {profile.name!r} content snapshot does not match its root")
    semantic = {
        "name": profile.name,
        "content_snapshot_id": snapshot.snapshot_id,
        "facts_backend_id": profile.facts_backend.cache_identity(),
        "poc_backend_id": _implementation_identity(profile.poc_backend) if profile.poc_backend is not None else None,
    }
    return ProfileBinding(
        **semantic,
        content_files=snapshot.entries,
        profile_sha256=canonical_sha256(semantic),
    )


def bind_profile_content(profile: ReviewProfile) -> ReviewProfile:
    """Bind a profile backend to the same content root used by generic consumers."""
    if profile.facts_backend is None:
        raise ValueError(f"review profile {profile.name!r} has no facts backend")
    return replace(profile, facts_backend=profile.facts_backend.bind_content(profile.paths))
