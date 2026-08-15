"""A review profile: a self-contained body of security knowledge plus where it lives.

The tool reviews more than one kind of code, web code and smart contracts. The engine
itself names no language, all the language and vulnerability knowledge is data under a
content root: `knowledge/`, `playbook/`, and `detection.yaml`. A `ReviewProfile` ties a name to
one such content root, and `ContentPaths` resolves the fixed file layout under it.
Selecting a profile swaps the whole knowledge set without touching the engine. Facts
extraction and its failure semantics live in `cyberjury.review.facts`; this module keeps
the profile configuration and the source and PoC seams.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyberjury.review.facts import FactsBackend

__all__ = [
    "ContentPaths",
    "PoCArtifact",
    "PoCExecResult",
    "ReviewProfile",
    "SourceLoader",
    "content_paths",
]


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one profile's root, resolved to absolute paths.

    The same fixed layout for every profile, so a caller given a `ContentPaths` reads the
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
    poc_backend: Callable[..., object] | None = None
    dedup_by_file: bool = False

    @property
    def paths(self) -> ContentPaths:
        """Return the resolved content paths for this profile."""
        return content_paths(self.content_root)


@dataclass(frozen=True, kw_only=True)
class PoCArtifact:
    """One written proof of concept before it runs.

    Every profile writes one, so a finding always carries a concrete reproduction recipe, not
    only a prose scenario. `source` is the runnable text, `ext` is its file suffix so it
    lands as `pocs/<name>.<ext>`, and `run_hint` states how a human runs it. Writing is
    separate from running: a profile writes for every finding, and only a profile that runs
    safely and locally, such as evm under Foundry, also executes. `note` is an optional
    writer-side check result, such as a syntax warning, that the engine folds into the
    evidence. It never refutes the finding, invariant 2.
    """

    source: str
    ext: str
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


class SourceLoader(ABC):
    """Materializes review source into a local tree.

    The web profile reviews a checkout in place, another profile may fetch from a host or a
    block explorer. A profile may bind one, the CLI passes a local path directly when none is
    set.
    """

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool or client is installed."""

    @abstractmethod
    def fetch(self, ref: str, dest: str | Path) -> Path:
        """Materialize the source named by ref under dest and return the review root.

        Raise BackendUnavailable when the backing tool or client is absent.
        """
