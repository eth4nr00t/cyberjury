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

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cyberjury.providers.base import Provider
    from cyberjury.review.facts import FactsBackend

__all__ = [
    "ContentPaths",
    "PoCArtifact",
    "PoCBackend",
    "PoCBackendFactory",
    "PoCExecResult",
    "PoCReproduction",
    "ReproducingPoCBackend",
    "ReviewProfile",
    "content_paths",
]


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one profile's root, resolved to absolute paths.

    Every profile uses the same fixed layout, so a caller given a `ContentPaths` reads the
    same files whether the profile is web or another.
    """

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
