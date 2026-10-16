"""Shared facts contracts for review workflows."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from cyberjury.canonical import canonical_sha256
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import RelationshipEvidenceBundle

__all__ = [
    "BackendUnavailable",
    "FactLimitation",
    "Facts",
    "FactsReceipt",
    "render_fact_limitations",
]

FACTS_SCHEMA = "cyberjury.facts/v1"


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
        """Return the stable JSON record bound by the facts receipt."""
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


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic syntax facts that ground every review unit.

    ``by_file`` holds prompt-ready syntax hints per analyzed file, ``relationships`` the
    exact definitions and callsites, and ``import_files`` the files with import declarations.
    """

    by_file: Mapping[str, str] = field(default_factory=dict)
    relationships: RelationshipEvidenceBundle = field(default_factory=RelationshipEvidenceBundle)
    import_files: tuple[str, ...] = ()
    limitations: tuple[FactLimitation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class FactsReceipt:
    """Identify one exact facts extraction by its backend and its extracted evidence."""

    backend_id: str
    evidence_sha256: str
    receipt_sha256: str

    @classmethod
    def create(cls, *, backend_id: str, facts: Facts) -> FactsReceipt:
        """Bind extracted facts and their source limitations to the backend that produced them."""
        evidence = {
            "by_file": dict(facts.by_file),
            "relationship_evidence": facts.relationships.to_data(),
            "import_files": list(facts.import_files),
            "limitations": [limitation.to_data() for limitation in facts.limitations],
        }
        semantic = {"backend_id": backend_id, "evidence_sha256": canonical_sha256(evidence)}
        return cls(**semantic, receipt_sha256=canonical_sha256(semantic))

    def to_dict(self) -> dict[str, object]:
        """Return the strict facts artifact."""
        return {
            "schema": FACTS_SCHEMA,
            "backend_id": self.backend_id,
            "evidence_sha256": self.evidence_sha256,
            "receipt_sha256": self.receipt_sha256,
        }


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
