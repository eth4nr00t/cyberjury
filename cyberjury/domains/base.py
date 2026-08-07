"""A review domain: a self-contained body of security knowledge plus where it lives.

The tool reviews more than one kind of code, web code and smart contracts. The engine
itself names no language, all the language and vulnerability knowledge is data under a
content root: `knowledge/`, `playbook/`, and `detection.yaml`. A `Domain` ties a name to
one such content root, and `ContentPaths` resolves the fixed file layout under it.
Selecting a domain swaps the whole knowledge set without touching the engine. It also
declares the tool-backed seams a domain may bind, `FactsBackend` and `SourceLoader`, as
abstract interfaces. The interfaces name no tool, so a concrete backend such as a
Slither facts extractor or a block-explorer loader lives in its own domain package, and
a domain without one falls back to the engine's own heuristics. This module holds no
path of its own and imports nothing from `cyberjury`, so the leaf modules that only need
resolved paths or these interfaces can depend on it with no import cycle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, kw_only=True)
class ContentPaths:
    """The fixed content layout under one domain's root, resolved to absolute paths.

    The same fixed layout for every domain, so a caller given a `ContentPaths` reads the
    same files whether the domain is web or another.
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
    """Resolve the content layout under a domain root.

    The relative structure is the contract every domain follows, so a new domain is a
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
class Domain:
    """A named review domain.

    where its content lives plus the review strategy that is data, not engine logic.
    `lenses` rotate the repository-review passes, and the diff focus and do-not-report
    blocks lead the diff prompt. The engine reads these from the selected domain rather than
    naming any of them itself, so a new domain is the data here plus a content root.
    Severity is the model's, graded against the domain's rubric markdown, so it lives in
    that rubric and the verifier, not in a field here.
    """

    name: str
    content_root: Path
    lenses: tuple[str, ...]
    diff_focus: str
    diff_do_not_report: str
    facts_backend: FactsBackend | None = None
    poc_backend: Callable[..., object] | None = None
    dedup_by_file: bool = False

    @property
    def paths(self) -> ContentPaths:
        """Return the resolved content paths for this domain."""
        return content_paths(self.content_root)


class BackendUnavailable(RuntimeError):
    """A tool-backed seam was asked to work but its external tool is not installed.

    Raised, never swallowed into an empty result, so a missing toolchain is a loud failure
    and not a silently clean review, invariant 4.
    """


@dataclass(frozen=True, kw_only=True)
class PoCArtifact:
    """One written proof of concept before it runs.

    Every domain writes one, so a finding always carries a concrete reproduction recipe, not
    only a prose scenario. `source` is the runnable text, `ext` is its file suffix so it
    lands as `pocs/<name>.<ext>`, and `run_hint` states how a human runs it. Writing is
    separate from running: a domain writes for every finding, and only a domain that runs
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


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic, tool-extracted facts about a source tree, used to ground model review.

    `summary` is prompt-ready text the engine threads into shared context, `data` is the
    structured payload, such as a call graph a backend uses for unit packing. Empty facts
    mean no backend ran, the engine falls back to its own heuristics. A backend may also
    fill three generic keys the engine reads, each optional: - `data["by_file"]`, a map from
    a source path relative to the repository to a prompt-ready facts block for that file.
    The engine grounds each unit with only the facts for the files it owns, so a large file
    split into slices still carries its whole call graph, the cross-slice signal a flat,
    truncated global dump loses. - `data["units"]`, focused unit specs the backend packed
    itself, each `{name, files, fragments}` where a fragment is `[file, start, end]` char
    offsets. - `data["graph"]`, a `{callgraph, imports}` pair for a backend that cannot pack
    units because it runs before the candidate entrypoints are known. The engine expands
    each candidate along those edges instead. All three are data the domain fills, the
    engine names no contract or function.
    """

    summary: str = ""
    data: dict = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        """Return whether the backend produced no usable facts."""
        return not self.summary and not self.data


class FactsBackend(ABC):
    """Extracts deterministic facts from a source tree to ground model review.

    A domain may bind one, the engine falls back to its heuristics when none is available.
    On the grounded path the facts decide which code a unit packs, so a backend is a recall
    lever, not only a precision aid.
    """

    install_hint: str = "install the backend's toolchain to enable it"

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool is installed.

        so a caller can fall back rather than fail when facts are optional.
        """

    @abstractmethod
    def extract(self, root: str | Path) -> Facts:
        """Extract facts from the source tree at root.

        Raise BackendUnavailable when the tool is absent rather than returning empty facts that
        would mask a missing toolchain.
        """


class SourceLoader(ABC):
    """Materializes review source into a local tree.

    The web domain reviews a checkout in place, another domain may fetch from a host or a
    block explorer. A domain may bind one, the CLI passes a local path directly when none is
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
