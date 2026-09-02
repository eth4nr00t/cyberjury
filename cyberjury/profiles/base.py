"""A review profile: a self-contained body of security knowledge plus where it lives.

The tool reviews more than one kind of code, web code and smart contracts. The engine
itself names no language, all the language and vulnerability knowledge is data under a
content root: `knowledge/`, `playbook/`, and `detection.yaml`. A `ReviewProfile` ties a name to
one such content root, and `ContentPaths` resolves the fixed file layout under it.
Selecting a profile swaps the knowledge set without touching the engine. Facts
extraction and its failure semantics live in `cyberjury.review.facts`. This module keeps
the profile configuration and PoC contracts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

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
    "PoCExecResult",
    "PoCReproduction",
    "ProfileBinding",
    "ReproducingPoCBackend",
    "ReviewProfile",
    "bind_profile_content",
    "content_paths",
    "profile_binding",
    "profile_content_fingerprint",
    "profile_content_snapshot",
    "validate_profile",
]

PROFILE_BINDING_SCHEMA = "cyberjury.profile-binding/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one profile's root, resolved to absolute paths.

    Every profile uses the same fixed layout, so a caller given a `ContentPaths` reads the
    same files whether the profile is web or another.
    """

    root: Path
    knowledge: Path
    vulnerabilities_dir: Path
    languages_dir: Path
    frameworks_dir: Path
    protocols_dir: Path
    knowledge_index: Path
    methodology_file: Path
    unit_review_file: Path
    severity_rubric_file: Path
    false_positive_traps_file: Path
    detection_file: Path


def content_paths(content_root: str | Path) -> ContentPaths:
    """Resolve the content layout under a profile root.

    The relative structure is the contract every profile follows, so a new profile is a
    directory in the same shape.
    """
    root = Path(content_root)
    knowledge = root / "knowledge"
    guides = knowledge / "guides"
    playbook = root / "playbook"
    return ContentPaths(
        root=root,
        knowledge=knowledge,
        vulnerabilities_dir=knowledge / "vulnerabilities",
        languages_dir=guides / "languages",
        frameworks_dir=guides / "frameworks",
        protocols_dir=guides / "protocols",
        knowledge_index=knowledge / "index.md",
        methodology_file=playbook / "methodology.md",
        unit_review_file=playbook / "unit-review.md",
        severity_rubric_file=playbook / "severity-rubric.md",
        false_positive_traps_file=playbook / "false-positive-traps.md",
        detection_file=root / "detection.yaml",
    )


@dataclass(frozen=True, kw_only=True)
class PoCArtifact:
    """Optional proof of concept evidence returned after successful generation.

    `source` is the runnable text and `run_hint` states how a human runs it. The backend owns
    the persisted file suffix because both generated and reproduced proofs use the same format.
    `note` carries an optional writer side check, such as a syntax warning, that the engine folds
    into the evidence. An absent artifact or a generation failure never refutes the finding,
    invariant 2.
    """

    source: str
    run_hint: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class PoCExecResult:
    """The outcome of running one written PoC.

    `ran` is False when execution is out of scope, such as a web PoC that a human runs
    against a sandbox, or when the toolchain is absent. `ok` is True only when the PoC ran
    and proved the exploit. A PoC that did not run or did not pass is never a safe verdict,
    it only fails to add positive evidence, so a finding is kept regardless, invariant 2.
    """

    ran: bool
    ok: bool
    detail: str


class PoCReproduction(Protocol):
    """Keep automatic execution evidence separate from the written artifact."""

    reproduced: bool
    test_source: str
    detail: str


@runtime_checkable
class PoCBackend(Protocol):
    """Expose explicit capabilities so orchestration never infers profile behavior."""

    executes: bool
    install_hint: str
    ext: str

    def available(self) -> bool:
        """False leaves an automatic backend in write only mode."""

    def generate(
        self,
        *,
        title: str,
        analysis: str,
        symbol: str,
        file: str,
        line: int | None,
        root: str,
        endpoint: str = "",
    ) -> PoCArtifact:
        """Produce an artifact even when automatic execution is unavailable."""

    def execute(self, *, source: str, root: str) -> PoCExecResult:
        """Never use a failed or skipped run to refute the finding."""


@runtime_checkable
class ReproducingPoCBackend(Protocol):
    """Keep repair attempts inside backends that can execute locally."""

    def reproduce(
        self,
        *,
        title: str,
        analysis: str,
        symbol: str,
        file: str,
        line: int | None,
        root: str,
    ) -> PoCReproduction:
        """Return positive evidence only after local execution proves the exploit."""


class PoCBackendFactory(Protocol):
    """Keep provider imports lazy until the selected profile needs PoC generation."""

    def __call__(
        self,
        *,
        provider: Provider | None = None,
        model: str | None = None,
    ) -> PoCBackend:
        """Use the selected model without widening the profile import boundary."""


@dataclass(frozen=True, kw_only=True)
class ReviewProfile:
    """Bind a profile name to its content, prompt blocks, and optional backends.

    The engine reads these from the selected profile rather than naming any of them itself.
    A new profile is the data here plus a content root. Severity is the model's, graded
    against the profile's rubric markdown, so it lives in that rubric and the verifier,
    not in a field here.
    The field list is limited to profile seams that the generic engine can consume.
    """

    name: str
    content_root: Path
    diff_focus: str
    diff_do_not_report: str
    facts_backend: FactsBackend | None = None
    poc_backend: PoCBackendFactory | None = None
    dedup_by_file: bool = False

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
    diff_policy_sha256: str
    facts_backend_id: str
    poc_backend_id: str | None
    dedup_by_file: bool
    profile_sha256: str

    def __post_init__(self) -> None:
        """Reject profile receipts that cannot identify one complete binding."""
        if not isinstance(self.name, str) or not _PROFILE_NAME.fullmatch(self.name):
            raise ValueError("profile binding name is invalid")
        for value in (self.content_snapshot_id, self.diff_policy_sha256, self.profile_sha256):
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
        if not isinstance(self.dedup_by_file, bool):
            raise ValueError("profile deduplication policy is invalid")
        if self.profile_sha256 != _profile_sha256(self.semantic_dict()):
            raise ValueError("profile binding hash does not match its content")

    def semantic_dict(self) -> dict[str, object]:
        """Return every behavior field covered by the profile receipt."""
        return {
            "name": self.name,
            "content_snapshot_id": self.content_snapshot_id,
            "diff_policy_sha256": self.diff_policy_sha256,
            "facts_backend_id": self.facts_backend_id,
            "poc_backend_id": self.poc_backend_id,
            "dedup_by_file": self.dedup_by_file,
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
            "diff_policy_sha256",
            "facts_backend_id",
            "poc_backend_id",
            "dedup_by_file",
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


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _profile_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


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
    from cyberjury.detection import load_detection, load_patch_syntax
    from cyberjury.guides import load_guides
    from cyberjury.review.facts import FactsBackend
    from cyberjury.review.vulnerabilities import VulnerabilityCatalog

    if not isinstance(profile.name, str) or not _PROFILE_NAME.fullmatch(profile.name):
        raise ValueError("review profile name is invalid")
    if not isinstance(profile.content_root, Path) or profile.content_root.is_symlink():
        raise ValueError(f"review profile {profile.name!r} content root is invalid")
    root = profile.content_root.resolve()
    if root != profile.content_root or not root.is_dir():
        raise ValueError(f"review profile {profile.name!r} content root must be canonical and absolute")
    if not isinstance(profile.diff_focus, str) or not profile.diff_focus.strip():
        raise ValueError(f"review profile {profile.name!r} has no diff focus policy")
    if not isinstance(profile.diff_do_not_report, str) or not profile.diff_do_not_report.strip():
        raise ValueError(f"review profile {profile.name!r} has no diff exclusion policy")
    if not isinstance(profile.dedup_by_file, bool):
        raise ValueError(f"review profile {profile.name!r} has an invalid deduplication policy")
    if not isinstance(profile.facts_backend, FactsBackend):
        raise ValueError(f"review profile {profile.name!r} has no facts backend")
    if profile.poc_backend is not None and not callable(profile.poc_backend):
        raise ValueError(f"review profile {profile.name!r} has an invalid PoC backend factory")

    paths = profile.paths
    required_directories = (paths.knowledge, paths.vulnerabilities_dir, paths.languages_dir, paths.protocols_dir)
    missing_directories = [str(path.relative_to(root)) for path in required_directories if not path.is_dir()]
    if missing_directories:
        raise ValueError(
            f"review profile {profile.name!r} is missing content directories: {', '.join(missing_directories)}"
        )
    required_files = (
        paths.knowledge_index,
        paths.methodology_file,
        paths.unit_review_file,
        paths.severity_rubric_file,
        paths.false_positive_traps_file,
        paths.detection_file,
    )
    for path in required_files:
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            relative = path.relative_to(root)
            raise ValueError(f"review profile {profile.name!r} content file is missing or empty: {relative}")

    detection = load_detection(paths.detection_file)
    if not detection.source_extensions or not detection.auto_select_extensions:
        raise ValueError(f"review profile {profile.name!r} has no source or automatic selection extensions")
    load_patch_syntax(paths.detection_file)
    catalog = VulnerabilityCatalog.load(paths.vulnerabilities_dir)
    if not catalog.items:
        raise ValueError(f"review profile {profile.name!r} has no vulnerability knowledge")
    guides = load_guides(paths.languages_dir, paths.frameworks_dir, paths.protocols_dir)
    language_ids = {guide.id for guide in guides if guide.kind == "language"}
    if not language_ids:
        raise ValueError(f"review profile {profile.name!r} has no language guide")
    identities = [(guide.kind, guide.id) for guide in guides]
    if any(
        not guide.id
        or guide.kind not in {"language", "framework", "protocol"}
        or not guide.title.strip()
        or not guide.body.strip()
        for guide in guides
    ) or len(identities) != len(set(identities)):
        raise ValueError(f"review profile {profile.name!r} has invalid or duplicate guides")
    missing_languages = sorted(
        {guide.language for guide in guides if guide.kind == "framework" and guide.language not in language_ids}
    )
    if missing_languages:
        raise ValueError(
            f"review profile {profile.name!r} framework guides reference missing languages: "
            f"{', '.join(missing_languages)}"
        )
    try:
        profile.facts_backend.validate_content(paths)
        backend_id = profile.facts_backend.cache_identity()
    except Exception as exc:
        raise ValueError(
            f"review profile {profile.name!r} facts backend content is invalid: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(backend_id, str) or not backend_id:
        raise ValueError(f"review profile {profile.name!r} facts backend identity is invalid")


def profile_content_fingerprint(profile: ReviewProfile) -> str:
    """Return the pure content snapshot id for one validated profile root."""
    return profile_content_snapshot(profile).snapshot_id


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
    if snapshot.root != profile.content_root.resolve() or not snapshot.matches():
        raise ValueError(f"review profile {profile.name!r} content snapshot does not match its root")
    with snapshot.materialize(name=profile.content_root.name) as content_root:
        validate_profile(replace(profile, content_root=content_root))
    if profile.facts_backend is None:
        raise ValueError(f"review profile {profile.name!r} has no facts backend")
    semantic = {
        "name": profile.name,
        "content_snapshot_id": snapshot.snapshot_id,
        "diff_policy_sha256": _profile_sha256(
            {"focus": profile.diff_focus, "do_not_report": profile.diff_do_not_report}
        ),
        "facts_backend_id": profile.facts_backend.cache_identity(),
        "poc_backend_id": _implementation_identity(profile.poc_backend) if profile.poc_backend is not None else None,
        "dedup_by_file": profile.dedup_by_file,
    }
    return ProfileBinding(
        **semantic,
        content_files=snapshot.entries,
        profile_sha256=_profile_sha256(semantic),
    )


def bind_profile_content(profile: ReviewProfile) -> ReviewProfile:
    """Bind a profile backend to the same content root used by generic consumers."""
    if profile.facts_backend is None:
        raise ValueError(f"review profile {profile.name!r} has no facts backend")
    return replace(profile, facts_backend=profile.facts_backend.bind_content(profile.paths))
