"""Shared facts contracts and extraction semantics for review workflows."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NamedTuple, TypedDict, cast

from cyberjury.review.definitions import (
    CallCandidate,
    DefinitionDependency,
    DefinitionFragment,
    DefinitionUnitPlan,
    FactsGraph,
    StructuralCandidate,
    StructuralGap,
    UnresolvedDependency,
    call_candidates_data,
    definition_call_candidates,
    definition_dependencies,
    definition_fragments,
    definition_references,
    definition_structural_candidates,
    definition_structural_gaps,
    definition_union_size,
    dependencies_data,
    dependency_closure,
    dependency_paths,
    merge_definition_unit_plans,
    plan_definition_units,
    structural_candidates_data,
    structural_gaps_data,
    unresolved_dependencies,
    unresolved_dependencies_data,
)
from cyberjury.review.failures import BackendUnavailable
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot

if TYPE_CHECKING:
    from cyberjury.profiles.base import ContentPaths

__all__ = [
    "BackendUnavailable",
    "CallCandidate",
    "DefinitionDependency",
    "DefinitionFragment",
    "DefinitionUnitPlan",
    "FactFragment",
    "FactLimitation",
    "FactUnitSpec",
    "Facts",
    "FactsBackend",
    "FactsByFile",
    "FactsGraph",
    "FactsPayload",
    "FactsRecord",
    "FactsResolutionReceipt",
    "NativeAnalysisReceipt",
    "StructuralCandidate",
    "StructuralGap",
    "UnresolvedDependency",
    "call_candidates_data",
    "definition_call_candidates",
    "definition_dependencies",
    "definition_fragments",
    "definition_references",
    "definition_structural_candidates",
    "definition_structural_gaps",
    "definition_union_size",
    "dependencies_data",
    "dependency_closure",
    "dependency_paths",
    "extract_facts",
    "fact_unit_specs",
    "merge_definition_unit_plans",
    "normalize_fact_limitations",
    "normalize_fact_unit_specs",
    "plan_definition_units",
    "render_fact_limitations",
    "structural_candidates_data",
    "structural_gaps_data",
    "unresolved_dependencies",
    "unresolved_dependencies_data",
]

type FactsRecord = dict[str, object]
type FactsByFile = Mapping[str, str]
type FactsPayload = Mapping[str, object]

NATIVE_ANALYSIS_SCHEMA = "cyberjury.native-analysis/v1"
FACTS_RESOLUTION_SCHEMA = "cyberjury.facts-resolution/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


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
        if self.receipt_sha256 != _sha256(self.semantic_dict()):
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
            "evidence_sha256": _sha256(evidence),
        }
        return cls(**semantic, receipt_sha256=_sha256(semantic))

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
        if self.receipt_sha256 != _sha256(self.semantic_dict()):
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
            "evidence_sha256": _sha256(
                {
                    "relationship_evidence": bundle.to_data(),
                    "limitations": [limitation.to_data() for limitation in limitations],
                }
            ),
        }
        return cls(**semantic, receipt_sha256=_sha256(semantic))

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


class FactFragment(NamedTuple):
    """One source range selected by a facts backend."""

    file: str
    start: int
    end: int


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
    if isinstance(value, FactFragment):
        return value
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
    if isinstance(value, FactFragment):
        return value
    if isinstance(value, dict):
        return {key: _mutable_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mutable_copy(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_mutable_copy(item) for item in value)
    return value


class FactUnitSpec(TypedDict, total=False):
    """Focused source fragments emitted by a facts backend."""

    name: str
    files: list[str]
    fragments: list[FactFragment]


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic facts that ground one or more review contexts.

    ``summary`` is prompt-ready text. ``data`` is a structured payload with shared keys
    such as ``by_file``, ``graph``, and optional focused unit specifications. Domain
    backends may add fields, but extraction, persistence, and consumption remain review-owned.
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

    install_hint: str = "install the backend's toolchain to enable it"
    writes_analysis_artifacts: bool = False

    def bind_content(self, content: ContentPaths) -> FactsBackend:
        """Bind profile-owned analyzer data to the selected content snapshot."""
        return self

    def validate_content(self, content: ContentPaths) -> None:
        """Validate backend-owned profile data before review work starts."""
        return None

    def analysis_output_dirs(self) -> frozenset[str]:
        """Name generated directories omitted from an isolated writable analyzer copy."""
        return frozenset()

    def cache_identity(self) -> str:
        """Identify the effective backend implementation for persisted facts."""
        backend = type(self)
        return f"{backend.__module__}.{backend.__qualname__}"

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool is installed and can support grounded review."""

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
        backend_available = backend.available()
    except Exception as exc:
        raise BackendUnavailable(f"the facts backend capability probe failed for {purpose}: {exc}") from exc
    if not backend_available:
        raise BackendUnavailable(
            f"the facts backend cannot run for {purpose}, so this review has no grounding. {backend.install_hint}"
        )
    try:
        if backend.writes_analysis_artifacts:
            source_snapshot = capture_source_snapshot(root)
            output_dirs = backend.analysis_output_dirs()
            analysis_files = tuple(
                path
                for path in source_snapshot.files
                if not any(part in output_dirs for part in PurePosixPath(path).parts[:-1])
            )
            protected_snapshot = SourceSnapshot.capture(root, analysis_files)
            with protected_snapshot.materialize(name=Path(root).resolve().name) as analysis_root:
                materialized_snapshot = capture_source_snapshot(analysis_root)
                facts = backend.extract(analysis_root)
                if not materialized_snapshot.matches_files(analysis_files):
                    raise BackendUnavailable("facts backend modified an input source while extracting facts")
            if not source_snapshot.matches():
                raise BackendUnavailable("source changed while isolated facts extraction was running")
        else:
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
        definition_dependencies(graph)
        unresolved_dependencies(graph)
    if "unit_specs" in data:
        data["unit_specs"] = normalize_fact_unit_specs(data["unit_specs"])
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


def fact_unit_specs(facts: Facts) -> list[FactUnitSpec]:
    """Return backend-provided focused unit specifications in one shared shape."""
    data = facts.data if isinstance(facts.data, dict) else {}
    return normalize_fact_unit_specs(data.get("unit_specs", []))


def normalize_fact_unit_specs(specs: object) -> list[FactUnitSpec]:
    """Validate and name the focused unit records at a facts boundary."""
    if not isinstance(specs, list | tuple):
        raise BackendUnavailable("facts backend returned invalid focused unit specifications")
    normalized: list[FactUnitSpec] = []
    for index, spec in enumerate(specs):
        if not isinstance(spec, dict):
            raise BackendUnavailable(f"facts backend returned malformed focused unit specification {index}")
        item: FactUnitSpec = {}
        if "name" in spec:
            name = spec["name"]
            if not isinstance(name, str):
                raise BackendUnavailable(f"focused unit specification {index} name must be a string")
            item["name"] = name
        if "files" in spec:
            files = spec["files"]
            if not isinstance(files, list | tuple) or not all(isinstance(file, str) for file in files):
                raise BackendUnavailable(f"focused unit specification {index} files must be a list of strings")
            item["files"] = list(files)
        if "fragments" in spec:
            fragments = spec["fragments"]
            if not isinstance(fragments, list | tuple):
                raise BackendUnavailable(f"focused unit specification {index} fragments must be a list")
            item["fragments"] = [
                _fact_fragment(fragment, unit_index=index, fragment_index=fragment_index)
                for fragment_index, fragment in enumerate(fragments)
            ]
        fragments = item.get("fragments", [])
        if not fragments:
            raise BackendUnavailable(f"focused unit specification {index} must contain source fragments")
        projected_files = list(dict.fromkeys(fragment.file for fragment in fragments))
        declared_files = item.get("files")
        if declared_files is not None and declared_files != projected_files:
            raise BackendUnavailable(
                f"focused unit specification {index} files must equal its fragment file projection"
            )
        item["files"] = projected_files
        normalized.append(item)
    names = [item.get("name", "") for item in normalized if item.get("name")]
    if len(names) != len(set(names)):
        raise BackendUnavailable("focused unit specification names must be unique")
    return normalized


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


def _fact_fragment(value: object, *, unit_index: int, fragment_index: int) -> FactFragment:
    if isinstance(value, FactFragment) or (isinstance(value, (list, tuple)) and len(value) == 3):
        file, start, end = value
    else:
        raise BackendUnavailable(
            f"focused unit specification {unit_index} fragment {fragment_index} has an invalid shape"
        )
    if (
        not isinstance(file, str)
        or not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise BackendUnavailable(
            f"focused unit specification {unit_index} fragment {fragment_index} has an invalid shape"
        )
    return FactFragment(file, start, end)
