"""Shared facts contracts and extraction semantics for review workflows."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cyberjury.canonical import canonical_sha256
from cyberjury.review.definitions import definition_fragments
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.profiles.base import ContentPaths

__all__ = [
    "BackendUnavailable",
    "FactLimitation",
    "Facts",
    "FactsBackend",
    "FactsByFile",
    "FactsPayload",
    "FactsRecord",
    "FactsResolutionReceipt",
    "NativeAnalysisReceipt",
    "extract_facts",
    "normalize_fact_limitations",
    "render_fact_limitations",
]

type FactsRecord = dict[str, object]
type FactsByFile = Mapping[str, str]
type FactsPayload = Mapping[str, object]

NATIVE_ANALYSIS_SCHEMA = "cyberjury.native-analysis/v1"
FACTS_RESOLUTION_SCHEMA = "cyberjury.facts-resolution/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class NativeAnalysisReceipt:
    """Observable identity and counts for one exact native analyzer result."""

    producer: str
    producer_version: str
    source_count: int
    definition_count: int
    callsite_count: int
    limitation_count: int
    evidence_sha256: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        """Reject incomplete or self-inconsistent analyzer receipts."""
        if not isinstance(self.producer, str) or not self.producer:
            raise ValueError("native analysis producer is invalid")
        if not isinstance(self.producer_version, str) or not self.producer_version:
            raise ValueError("native analysis producer version is invalid")
        for value in (self.source_count, self.definition_count, self.callsite_count, self.limitation_count):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("native analysis count is invalid")
        if not isinstance(self.evidence_sha256, str) or not _SHA256.fullmatch(self.evidence_sha256):
            raise ValueError("native analysis evidence hash is invalid")
        if self.receipt_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("native analysis receipt hash does not match its content")

    @classmethod
    def create(
        cls,
        *,
        producer: str,
        producer_version: str,
        source_count: int,
        definition_count: int,
        callsite_count: int,
        limitation_count: int,
        evidence: object,
    ) -> NativeAnalysisReceipt:
        """Bind stable normalized evidence and its observable counts."""
        semantic = {
            "producer": producer,
            "producer_version": producer_version,
            "source_count": source_count,
            "definition_count": definition_count,
            "callsite_count": callsite_count,
            "limitation_count": limitation_count,
            "evidence_sha256": canonical_sha256(evidence),
        }
        return cls(**semantic, receipt_sha256=canonical_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return every analyzer result field covered by the receipt hash."""
        return {
            "producer": self.producer,
            "producer_version": self.producer_version,
            "source_count": self.source_count,
            "definition_count": self.definition_count,
            "callsite_count": self.callsite_count,
            "limitation_count": self.limitation_count,
            "evidence_sha256": self.evidence_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict native analysis artifact."""
        return {"schema": NATIVE_ANALYSIS_SCHEMA, **self.semantic_dict(), "receipt_sha256": self.receipt_sha256}

    @classmethod
    def from_dict(cls, value: object) -> NativeAnalysisReceipt:
        """Parse and verify one strict native analysis artifact."""
        fields = {
            "schema",
            "producer",
            "producer_version",
            "source_count",
            "definition_count",
            "callsite_count",
            "limitation_count",
            "evidence_sha256",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("schema") != NATIVE_ANALYSIS_SCHEMA:
            raise ValueError("native analysis artifact has an unsupported or nonexact schema")
        return cls(**{key: item for key, item in value.items() if key != "schema"})


@dataclass(frozen=True, kw_only=True)
class FactsResolutionReceipt:
    """Observable identity and coverage for one shared relationship evidence graph."""

    native_analysis_receipt_sha256: str
    relationship_source_count: int
    definition_count: int
    callsite_count: int
    excluded_native_callsite_count: int
    candidate_callsite_count: int
    unresolved_callsite_count: int
    candidate_structural_relationship_count: int
    unresolved_structural_relationship_count: int
    limitation_count: int
    evidence_sha256: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        """Reject incomplete or self-inconsistent facts resolution receipts."""
        if not isinstance(self.native_analysis_receipt_sha256, str) or not _SHA256.fullmatch(
            self.native_analysis_receipt_sha256
        ):
            raise ValueError("facts resolution native analysis hash is invalid")
        counts = (
            self.relationship_source_count,
            self.definition_count,
            self.callsite_count,
            self.excluded_native_callsite_count,
            self.candidate_callsite_count,
            self.unresolved_callsite_count,
            self.candidate_structural_relationship_count,
            self.unresolved_structural_relationship_count,
            self.limitation_count,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("facts resolution count is invalid")
        if self.candidate_callsite_count + self.unresolved_callsite_count != self.callsite_count:
            raise ValueError("facts resolution callsite target counts do not cover every callsite")
        if not isinstance(self.evidence_sha256, str) or not _SHA256.fullmatch(self.evidence_sha256):
            raise ValueError("facts resolution evidence hash is invalid")
        if self.receipt_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("facts resolution receipt hash does not match its content")

    @classmethod
    def create(
        cls,
        *,
        native_analysis: NativeAnalysisReceipt,
        relationship_evidence: object,
        limitations: tuple[FactLimitation, ...],
    ) -> FactsResolutionReceipt:
        """Bind normalized relationship evidence and source limitations to Stage 04."""
        from cyberjury.review.relationships import relationship_evidence_from_data

        bundle = relationship_evidence_from_data(relationship_evidence)
        if len(bundle.callsites) > native_analysis.callsite_count:
            raise ValueError("facts resolution contains more callsites than native analysis")
        paths = {
            *(source.path for source in bundle.sources),
            *(definition.source.path for definition in bundle.definitions),
            *(callsite.source.path for callsite in bundle.callsites),
            *(relationship.source.path for relationship in bundle.structural_relationships),
        }
        semantic = {
            "native_analysis_receipt_sha256": native_analysis.receipt_sha256,
            "relationship_source_count": len(paths),
            "definition_count": len(bundle.definitions),
            "callsite_count": len(bundle.callsites),
            "excluded_native_callsite_count": native_analysis.callsite_count - len(bundle.callsites),
            "candidate_callsite_count": sum(
                relationship.target_status == "candidate" for relationship in bundle.call_relationships
            ),
            "unresolved_callsite_count": sum(
                relationship.target_status == "unresolved" for relationship in bundle.call_relationships
            ),
            "candidate_structural_relationship_count": sum(
                relationship.target_status == "candidate" for relationship in bundle.structural_relationships
            ),
            "unresolved_structural_relationship_count": sum(
                relationship.target_status == "unresolved" for relationship in bundle.structural_relationships
            ),
            "limitation_count": len(limitations),
            "evidence_sha256": canonical_sha256(
                {
                    "relationship_evidence": bundle.to_data(),
                    "limitations": [limitation.to_data() for limitation in limitations],
                }
            ),
        }
        return cls(**semantic, receipt_sha256=canonical_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return every facts result field covered by the receipt hash."""
        return {
            "native_analysis_receipt_sha256": self.native_analysis_receipt_sha256,
            "relationship_source_count": self.relationship_source_count,
            "definition_count": self.definition_count,
            "callsite_count": self.callsite_count,
            "excluded_native_callsite_count": self.excluded_native_callsite_count,
            "candidate_callsite_count": self.candidate_callsite_count,
            "unresolved_callsite_count": self.unresolved_callsite_count,
            "candidate_structural_relationship_count": self.candidate_structural_relationship_count,
            "unresolved_structural_relationship_count": self.unresolved_structural_relationship_count,
            "limitation_count": self.limitation_count,
            "evidence_sha256": self.evidence_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict facts resolution artifact."""
        return {"schema": FACTS_RESOLUTION_SCHEMA, **self.semantic_dict(), "receipt_sha256": self.receipt_sha256}

    @classmethod
    def from_dict(cls, value: object) -> FactsResolutionReceipt:
        """Parse and verify one strict facts resolution artifact."""
        fields = {
            "schema",
            "native_analysis_receipt_sha256",
            "relationship_source_count",
            "definition_count",
            "callsite_count",
            "excluded_native_callsite_count",
            "candidate_callsite_count",
            "unresolved_callsite_count",
            "candidate_structural_relationship_count",
            "unresolved_structural_relationship_count",
            "limitation_count",
            "evidence_sha256",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("schema") != FACTS_RESOLUTION_SCHEMA:
            raise ValueError("facts resolution artifact has an unsupported or nonexact schema")
        return cls(**{key: item for key, item in value.items() if key != "schema"})


@dataclass(frozen=True, kw_only=True)
class FactLimitation:
    """One source that could not produce complete structured facts."""

    source: str
    analyzer: str
    reason: str
    line: int | None = None
    column: int | None = None

    @property
    def identity(self) -> str:
        """Identify the missing structured evidence without source content."""
        location = f":{self.line}:{self.column}" if self.line is not None and self.column is not None else ""
        return f"facts:{self.source}{location}"

    @property
    def message(self) -> str:
        """Render the limitation for prompts and operator diagnostics."""
        location = f" at {self.line}:{self.column}" if self.line is not None and self.column is not None else ""
        return f"{self.source}{location}: {self.analyzer} {self.reason}"

    def to_data(self) -> dict[str, object]:
        """Return the stable JSON record persisted with facts artifacts."""
        data: dict[str, object] = {
            "source": self.source,
            "analyzer": self.analyzer,
            "reason": self.reason,
        }
        if self.line is not None:
            data["line"] = self.line
        if self.column is not None:
            data["column"] = self.column
        return data


class FrozenDict(dict):
    """A JSON-compatible dictionary snapshot that rejects mutation."""

    def _readonly(self, *_args, **_kwargs) -> None:
        raise TypeError("facts snapshots are immutable")

    __setitem__ = _readonly
    __delitem__ = _readonly
    __ior__ = _readonly
    clear = _readonly
    pop = _readonly
    popitem = _readonly
    setdefault = _readonly
    update = _readonly


class FrozenList(list):
    """A JSON-compatible list snapshot that rejects mutation."""

    def _readonly(self, *_args, **_kwargs) -> None:
        raise TypeError("facts snapshots are immutable")

    __setitem__ = _readonly
    __delitem__ = _readonly
    __iadd__ = _readonly
    __imul__ = _readonly
    append = _readonly
    clear = _readonly
    extend = _readonly
    insert = _readonly
    pop = _readonly
    remove = _readonly
    reverse = _readonly
    sort = _readonly


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        frozen = FrozenDict()
        for key, item in value.items():
            dict.__setitem__(frozen, key, _freeze(item))
        return frozen
    if isinstance(value, list):
        frozen_list = FrozenList()
        for item in value:
            list.append(frozen_list, _freeze(item))
        return frozen_list
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _mutable_copy(value: object) -> object:
    if isinstance(value, dict):
        return {key: _mutable_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mutable_copy(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_mutable_copy(item) for item in value)
    return value


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic facts that ground one or more review contexts.

    ``summary`` is prompt-ready text. ``data`` is a structured payload with shared keys
    such as ``by_file``, ``graph``, and ``relationship_evidence``. Domain backends may add
    fields, but extraction, persistence, and consumption remain review-owned.
    """

    summary: str = ""
    data: FactsPayload = field(default_factory=dict)
    limitations: tuple[FactLimitation, ...] = ()
    native_analysis: NativeAnalysisReceipt | None = None
    facts_resolution: FactsResolutionReceipt | None = None

    @property
    def empty(self) -> bool:
        """Report whether the backend produced no usable facts."""
        return not self.summary and not self.data and not self.limitations

    @property
    def complete(self) -> bool:
        """Report whether every source produced complete structured facts."""
        return not self.limitations


class FactsBackend(ABC):
    """Extract deterministic facts from a source tree for grounded review."""

    def bind_content(self, content: ContentPaths) -> FactsBackend:
        """Bind profile-owned analyzer data to the selected content snapshot."""
        return self

    def validate_content(self, content: ContentPaths) -> None:
        """Validate backend-owned profile data before review work starts."""
        return None

    def cache_identity(self) -> str:
        """Identify the effective backend implementation for persisted facts."""
        backend = type(self)
        return f"{backend.__module__}.{backend.__qualname__}"

    @abstractmethod
    def extract(self, root: str | Path) -> Facts:
        """Extract facts from ``root`` and disclose any source limitations."""


def extract_facts(
    backend: FactsBackend | None,
    root: str | Path,
    *,
    purpose: str = "review",
) -> Facts:
    """Run one facts backend with shared loud-failure behavior.

    A missing backend means that the caller did not bind grounding. A bound backend that
    cannot run or returns an invalid value is an error, never an empty clean review.
    """
    if backend is None:
        return Facts()
    try:
        facts = backend.extract(root)
    except BackendUnavailable:
        raise
    except Exception as exc:
        raise BackendUnavailable(
            f"facts extraction failed for {purpose}, so this review has no grounding: {exc}"
        ) from exc
    if not isinstance(facts, Facts):
        raise BackendUnavailable(f"facts backend returned an invalid result for {purpose}")
    if not isinstance(facts.summary, str) or not isinstance(facts.data, Mapping):
        raise BackendUnavailable(f"facts backend returned an invalid payload for {purpose}")
    if facts.native_analysis is not None and not isinstance(facts.native_analysis, NativeAnalysisReceipt):
        raise BackendUnavailable(f"facts backend returned an invalid native analysis receipt for {purpose}")
    if facts.facts_resolution is not None and not isinstance(facts.facts_resolution, FactsResolutionReceipt):
        raise BackendUnavailable(f"facts backend returned an invalid facts resolution receipt for {purpose}")
    if (facts.native_analysis is None) != (facts.facts_resolution is None):
        raise BackendUnavailable(f"facts backend returned an incomplete analysis receipt chain for {purpose}")
    data = cast("dict[str, object]", _mutable_copy(facts.data))
    by_file = data.get("by_file")
    if by_file is not None and (
        not isinstance(by_file, dict)
        or not all(isinstance(key, str) and key and isinstance(value, str) for key, value in by_file.items())
    ):
        raise BackendUnavailable(f"facts backend returned invalid per-file facts for {purpose}")
    graph = data.get("graph")
    if graph is not None:
        if not isinstance(graph, dict):
            raise BackendUnavailable(f"facts backend returned an invalid definition graph for {purpose}")
        definition_fragments(graph)
    limitations = normalize_fact_limitations(facts.limitations)
    if facts.facts_resolution is not None and facts.native_analysis is not None:
        relationships = data.get("relationship_evidence")
        if relationships is None:
            from cyberjury.review.relationships import RelationshipEvidenceBundle

            relationships = RelationshipEvidenceBundle().to_data()
        if not isinstance(relationships, dict):
            raise BackendUnavailable(f"facts backend returned invalid relationship evidence for {purpose}")
        expected_resolution = FactsResolutionReceipt.create(
            native_analysis=facts.native_analysis,
            relationship_evidence=relationships,
            limitations=limitations,
        )
        if facts.facts_resolution != expected_resolution:
            raise BackendUnavailable(f"facts backend returned a mismatched facts resolution receipt for {purpose}")
    return replace(
        facts,
        data=cast("FactsPayload", _freeze(data)),
        limitations=limitations,
    )


def normalize_fact_limitations(values: object) -> tuple[FactLimitation, ...]:
    """Validate persisted source limitations at the shared facts boundary."""
    if not isinstance(values, list | tuple):
        raise BackendUnavailable("facts backend returned invalid source limitations")
    limitations: list[FactLimitation] = []
    for index, value in enumerate(values):
        if isinstance(value, FactLimitation):
            value = value.to_data()
        if not isinstance(value, dict):
            raise BackendUnavailable(f"facts source limitation {index} must be an object")
        source = value.get("source")
        analyzer = value.get("analyzer")
        reason = value.get("reason")
        line = value.get("line")
        column = value.get("column")
        if not all(isinstance(item, str) and item for item in (source, analyzer, reason)):
            raise BackendUnavailable(f"facts source limitation {index} has invalid text fields")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            raise BackendUnavailable(f"facts source limitation {index} has an invalid line")
        if column is not None and (isinstance(column, bool) or not isinstance(column, int) or column < 1):
            raise BackendUnavailable(f"facts source limitation {index} has an invalid column")
        if (line is None) != (column is None):
            raise BackendUnavailable(f"facts source limitation {index} must provide line and column together")
        limitations.append(
            FactLimitation(
                source=source,
                analyzer=analyzer,
                reason=reason,
                line=line,
                column=column,
            )
        )
    identities = [limitation.identity for limitation in limitations]
    if len(identities) != len(set(identities)):
        raise BackendUnavailable("facts source limitations must have unique locations")
    return tuple(limitations)


def render_fact_limitations(limitations: tuple[FactLimitation, ...]) -> str:
    """Render incomplete structured coverage without hiding raw source review."""
    if not limitations:
        return ""
    lines = [
        "Structured facts are unavailable for these sources. Review their raw source, and do not "
        "treat missing graph edges as evidence that no relationship exists:",
    ]
    lines.extend(f"- {limitation.message}" for limitation in limitations)
    return "\n".join(lines)
