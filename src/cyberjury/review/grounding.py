"""Persist strict receipts for initial grounding envelopes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from cyberjury.review.context import (
    EvidenceItem,
    EvidenceRevision,
    GroundingContext,
    GroundingCoverage,
    SourceSpan,
)
from cyberjury.review.unit_plans import UnitPlanReceipt

GROUNDING_SCHEMA = "cyberjury.grounding/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION_ID = re.compile(r"^revision-[0-9a-f]{24}$")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _source_path(path: str) -> str:
    if not isinstance(path, str):
        raise ValueError("grounding source path must be a normalized repository path")
    normalized = PurePosixPath(path)
    if (
        not path
        or path == "."
        or path.startswith("/")
        or "\\" in path
        or normalized.as_posix() != path
        or ".." in normalized.parts
    ):
        raise ValueError("grounding source path must be a normalized repository path")
    return path


def _unique_strings(values: tuple[str, ...], label: str) -> None:
    if not isinstance(values, tuple) or not all(isinstance(value, str) and value for value in values):
        raise ValueError(f"grounding {label} must be a tuple of nonempty strings")
    if len(values) != len(set(values)):
        raise ValueError(f"grounding {label} must not contain duplicates")


@dataclass(frozen=True, kw_only=True)
class GroundingEvidenceRecord:
    """Describe one exact source item published for bounded retrieval."""

    id: str
    identity: str
    label: str
    preview: str
    content_chars: int
    content_sha256: str
    source_span: SourceSpan | None

    def __post_init__(self) -> None:
        """Reject evidence metadata that cannot identify exact content."""
        if not isinstance(self.id, str) or not self.id.startswith("ev-"):
            raise ValueError("grounding evidence record id is invalid")
        if not all(isinstance(value, str) and value for value in (self.identity, self.label)):
            raise ValueError("grounding evidence record identity and label are invalid")
        if not isinstance(self.preview, str):
            raise ValueError("grounding evidence record preview is invalid")
        if isinstance(self.content_chars, bool) or not isinstance(self.content_chars, int) or self.content_chars < 1:
            raise ValueError("grounding evidence record character count is invalid")
        if not isinstance(self.content_sha256, str) or not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("grounding evidence record content hash is invalid")
        expected_id = f"ev-{hashlib.sha256(f'{self.identity}\0{self.content_sha256}'.encode()).hexdigest()[:12]}"
        if self.id != expected_id:
            raise ValueError("grounding evidence record id does not match its content")
        if self.source_span is not None and not isinstance(self.source_span, SourceSpan):
            raise ValueError("grounding evidence record source span is invalid")

    @classmethod
    def from_item(cls, item: EvidenceItem) -> GroundingEvidenceRecord:
        """Bind one published evidence item without persisting its source text twice."""
        return cls(
            id=item.id,
            identity=item.identity,
            label=item.label,
            preview=item.preview,
            content_chars=len(item.text),
            content_sha256=_text_sha256(item.text),
            source_span=item.source_span,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict evidence metadata record."""
        return {
            "id": self.id,
            "identity": self.identity,
            "label": self.label,
            "preview": self.preview,
            "content_chars": self.content_chars,
            "content_sha256": self.content_sha256,
            "source_span": self.source_span.to_dict() if self.source_span is not None else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> GroundingEvidenceRecord:
        """Load one strict evidence metadata record."""
        fields = {"id", "identity", "label", "preview", "content_chars", "content_sha256", "source_span"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("grounding evidence record has an unsupported shape")
        span = value["source_span"]
        return cls(
            id=value["id"],
            identity=value["identity"],
            label=value["label"],
            preview=value["preview"],
            content_chars=value["content_chars"],
            content_sha256=value["content_sha256"],
            source_span=SourceSpan.from_dict(span) if span is not None else None,
        )


@dataclass(frozen=True, kw_only=True)
class GroundingContextRecord:
    """Bind one planned unit to its initial source and evidence envelope."""

    unit_id: str
    source: Literal["diff", "repository"]
    source_snapshot_id: str
    files: tuple[str, ...]
    snapshot_files: tuple[str, ...]
    source_spans: tuple[SourceSpan, ...]
    coverage: GroundingCoverage
    context_chars: int
    context_sha256: str
    facts_chars: int
    facts_sha256: str
    controls_chars: int
    controls_sha256: str
    evidence: tuple[GroundingEvidenceRecord, ...]
    seed_sha256: str
    revision_id: str
    record_sha256: str

    def __post_init__(self) -> None:
        """Require complete hashes, ranges, coverage, and derived identity."""
        if not isinstance(self.unit_id, str) or not self.unit_id.startswith("unit-"):
            raise ValueError("grounding context unit id is invalid")
        if self.source not in {"diff", "repository"}:
            raise ValueError("grounding context source is invalid")
        if not isinstance(self.source_snapshot_id, str) or not _SHA256.fullmatch(self.source_snapshot_id):
            raise ValueError("grounding context source snapshot id is invalid")
        for label, paths in (("files", self.files), ("snapshot files", self.snapshot_files)):
            _unique_strings(paths, label)
            for path in paths:
                _source_path(path)
        if not isinstance(self.source_spans, tuple) or not all(
            isinstance(span, SourceSpan) for span in self.source_spans
        ):
            raise ValueError("grounding context source spans are invalid")
        if not isinstance(self.coverage, GroundingCoverage):
            raise ValueError("grounding context coverage is invalid")
        for value in (self.context_chars, self.facts_chars, self.controls_chars):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("grounding context character count is invalid")
        for value in (self.context_sha256, self.facts_sha256, self.controls_sha256, self.seed_sha256):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError("grounding context content hash is invalid")
        if not isinstance(self.evidence, tuple) or not all(
            isinstance(item, GroundingEvidenceRecord) for item in self.evidence
        ):
            raise ValueError("grounding context evidence metadata is invalid")
        if len({item.id for item in self.evidence}) != len(self.evidence):
            raise ValueError("grounding context evidence ids must be unique")
        revision = EvidenceRevision(
            source_snapshot_key=self.source_snapshot_id,
            seed_sha256=self.seed_sha256,
            evidence=tuple(sorted((f"{item.id}\0{item.identity}", item.content_sha256) for item in self.evidence)),
            source_evidence=(),
            controls_sha256=self.controls_sha256,
        )
        if not _REVISION_ID.fullmatch(self.revision_id) or self.revision_id != revision.id:
            raise ValueError("grounding context revision id is invalid")
        if not isinstance(self.record_sha256, str) or not _SHA256.fullmatch(self.record_sha256):
            raise ValueError("grounding context record hash is invalid")
        if self.record_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("grounding context record hash does not match its content")

    @classmethod
    def create(cls, *, unit_id: str, context: GroundingContext) -> GroundingContextRecord:
        """Create one initial context receipt from exact in-memory evidence."""
        if context.source_snapshot is None:
            raise ValueError("grounding context needs a bound source snapshot")
        if context.source_evidence:
            raise ValueError("initial grounding cannot contain later navigation evidence")
        prompt = context.prompt
        evidence = tuple(GroundingEvidenceRecord.from_item(item) for item in context.evidence)
        semantic = {
            "unit_id": unit_id,
            "source": context.source,
            "source_snapshot_id": context.source_snapshot.snapshot_id,
            "files": context.files,
            "snapshot_files": context.snapshot_files,
            "source_spans": context.source_spans,
            "coverage": context.coverage,
            "context_chars": len(context.text),
            "context_sha256": _text_sha256(context.text),
            "facts_chars": len(context.facts),
            "facts_sha256": _text_sha256(context.facts),
            "controls_chars": len(prompt.controls),
            "controls_sha256": _text_sha256(prompt.controls),
            "evidence": evidence,
            "seed_sha256": context.revision.seed_sha256,
            "revision_id": context.revision.id,
        }
        return cls(**semantic, record_sha256=_sha256(_grounding_json(semantic)))

    def semantic_dict(self) -> dict[str, object]:
        """Return every context field covered by its record hash."""
        return _grounding_json(
            {
                "unit_id": self.unit_id,
                "source": self.source,
                "source_snapshot_id": self.source_snapshot_id,
                "files": self.files,
                "snapshot_files": self.snapshot_files,
                "source_spans": self.source_spans,
                "coverage": self.coverage,
                "context_chars": self.context_chars,
                "context_sha256": self.context_sha256,
                "facts_chars": self.facts_chars,
                "facts_sha256": self.facts_sha256,
                "controls_chars": self.controls_chars,
                "controls_sha256": self.controls_sha256,
                "evidence": self.evidence,
                "seed_sha256": self.seed_sha256,
                "revision_id": self.revision_id,
            }
        )

    def to_dict(self) -> dict[str, object]:
        """Return one strict grounding context receipt."""
        return {**self.semantic_dict(), "record_sha256": self.record_sha256}

    @classmethod
    def from_dict(cls, value: object) -> GroundingContextRecord:
        """Load one strict grounding context receipt."""
        fields = {
            "unit_id",
            "source",
            "source_snapshot_id",
            "files",
            "snapshot_files",
            "source_spans",
            "coverage",
            "context_chars",
            "context_sha256",
            "facts_chars",
            "facts_sha256",
            "controls_chars",
            "controls_sha256",
            "evidence",
            "seed_sha256",
            "revision_id",
            "record_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("grounding context record has an unsupported shape")
        for name in ("files", "snapshot_files", "source_spans", "evidence"):
            if not isinstance(value[name], list):
                raise ValueError(f"grounding context {name} must be a list")
        return cls(
            unit_id=value["unit_id"],
            source=value["source"],
            source_snapshot_id=value["source_snapshot_id"],
            files=tuple(value["files"]),
            snapshot_files=tuple(value["snapshot_files"]),
            source_spans=tuple(SourceSpan.from_dict(item) for item in value["source_spans"]),
            coverage=GroundingCoverage.from_dict(value["coverage"]),
            context_chars=value["context_chars"],
            context_sha256=value["context_sha256"],
            facts_chars=value["facts_chars"],
            facts_sha256=value["facts_sha256"],
            controls_chars=value["controls_chars"],
            controls_sha256=value["controls_sha256"],
            evidence=tuple(GroundingEvidenceRecord.from_dict(item) for item in value["evidence"]),
            seed_sha256=value["seed_sha256"],
            revision_id=value["revision_id"],
            record_sha256=value["record_sha256"],
        )


@dataclass(frozen=True, kw_only=True)
class GroundingReceipt:
    """Bind every Stage 06 unit to one initial evidence envelope."""

    unit_plan_receipt_sha256: str
    context_count: int
    total_context_chars: int
    total_facts_chars: int
    total_controls_chars: int
    total_catalog_chars: int
    unreviewable_unit_ids: tuple[str, ...]
    limited_unit_ids: tuple[str, ...]
    contexts: tuple[GroundingContextRecord, ...]
    receipt_sha256: str

    def __post_init__(self) -> None:
        """Reject a receipt that does not match its complete context list."""
        if not isinstance(self.unit_plan_receipt_sha256, str) or not _SHA256.fullmatch(self.unit_plan_receipt_sha256):
            raise ValueError("grounding unit plan receipt hash is invalid")
        counts = (
            self.context_count,
            self.total_context_chars,
            self.total_facts_chars,
            self.total_controls_chars,
            self.total_catalog_chars,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("grounding receipt count is invalid")
        for label, values in (
            ("unreviewable unit ids", self.unreviewable_unit_ids),
            ("limited unit ids", self.limited_unit_ids),
        ):
            _unique_strings(values, label)
        if not isinstance(self.contexts, tuple) or not all(
            isinstance(context, GroundingContextRecord) for context in self.contexts
        ):
            raise ValueError("grounding receipt contexts are invalid")
        if self.context_count != len(self.contexts):
            raise ValueError("grounding receipt context count does not match its contexts")
        ids = tuple(context.unit_id for context in self.contexts)
        if len(ids) != len(set(ids)):
            raise ValueError("grounding receipt unit ids must be unique")
        expected_unreviewable = tuple(context.unit_id for context in self.contexts if not context.coverage.reviewable)
        expected_limited = tuple(context.unit_id for context in self.contexts if context.coverage.limitations)
        if self.unreviewable_unit_ids != expected_unreviewable or self.limited_unit_ids != expected_limited:
            raise ValueError("grounding receipt incomplete unit summaries do not match its contexts")
        if self.total_context_chars != sum(context.context_chars for context in self.contexts):
            raise ValueError("grounding receipt context characters do not match its contexts")
        if self.total_facts_chars != sum(context.facts_chars for context in self.contexts):
            raise ValueError("grounding receipt facts characters do not match its contexts")
        if self.total_controls_chars != sum(context.controls_chars for context in self.contexts):
            raise ValueError("grounding receipt control characters do not match its contexts")
        if self.total_catalog_chars != sum(
            item.content_chars for context in self.contexts for item in context.evidence
        ):
            raise ValueError("grounding receipt catalog characters do not match its contexts")
        if not isinstance(self.receipt_sha256, str) or not _SHA256.fullmatch(self.receipt_sha256):
            raise ValueError("grounding receipt hash is invalid")
        if self.receipt_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("grounding receipt hash does not match its content")

    @classmethod
    def create(
        cls,
        *,
        unit_plan: UnitPlanReceipt,
        contexts: tuple[GroundingContext, ...],
    ) -> GroundingReceipt:
        """Create the complete initial grounding receipt in unit plan order."""
        if len(contexts) != len(unit_plan.units):
            raise ValueError("grounding needs exactly one context for every planned unit")
        for unit, context in zip(unit_plan.units, contexts, strict=True):
            expected_source = "diff" if unit.kind == "diff" else "repository"
            if context.source != expected_source:
                raise ValueError(f"grounding context source does not match unit {unit.id}")
        records = tuple(
            GroundingContextRecord.create(unit_id=unit.id, context=context)
            for unit, context in zip(unit_plan.units, contexts, strict=True)
        )
        semantic = {
            "unit_plan_receipt_sha256": unit_plan.receipt_sha256,
            "context_count": len(records),
            "total_context_chars": sum(context.context_chars for context in records),
            "total_facts_chars": sum(context.facts_chars for context in records),
            "total_controls_chars": sum(context.controls_chars for context in records),
            "total_catalog_chars": sum(item.content_chars for context in records for item in context.evidence),
            "unreviewable_unit_ids": tuple(context.unit_id for context in records if not context.coverage.reviewable),
            "limited_unit_ids": tuple(context.unit_id for context in records if context.coverage.limitations),
            "contexts": records,
        }
        return cls(**semantic, receipt_sha256=_sha256(_grounding_json(semantic)))

    def semantic_dict(self) -> dict[str, object]:
        """Return every receipt field covered by its hash."""
        return _grounding_json(
            {
                "unit_plan_receipt_sha256": self.unit_plan_receipt_sha256,
                "context_count": self.context_count,
                "total_context_chars": self.total_context_chars,
                "total_facts_chars": self.total_facts_chars,
                "total_controls_chars": self.total_controls_chars,
                "total_catalog_chars": self.total_catalog_chars,
                "unreviewable_unit_ids": self.unreviewable_unit_ids,
                "limited_unit_ids": self.limited_unit_ids,
                "contexts": self.contexts,
            }
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict Stage 07 artifact."""
        return {"schema": GROUNDING_SCHEMA, **self.semantic_dict(), "receipt_sha256": self.receipt_sha256}

    @classmethod
    def from_dict(cls, value: object) -> GroundingReceipt:
        """Load and verify one strict Stage 07 artifact."""
        fields = {
            "schema",
            "unit_plan_receipt_sha256",
            "context_count",
            "total_context_chars",
            "total_facts_chars",
            "total_controls_chars",
            "total_catalog_chars",
            "unreviewable_unit_ids",
            "limited_unit_ids",
            "contexts",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or value["schema"] != GROUNDING_SCHEMA:
            raise ValueError("grounding artifact has an unsupported or nonexact schema")
        for name in ("unreviewable_unit_ids", "limited_unit_ids", "contexts"):
            if not isinstance(value[name], list):
                raise ValueError(f"grounding {name} must be a list")
        return cls(
            unit_plan_receipt_sha256=value["unit_plan_receipt_sha256"],
            context_count=value["context_count"],
            total_context_chars=value["total_context_chars"],
            total_facts_chars=value["total_facts_chars"],
            total_controls_chars=value["total_controls_chars"],
            total_catalog_chars=value["total_catalog_chars"],
            unreviewable_unit_ids=tuple(value["unreviewable_unit_ids"]),
            limited_unit_ids=tuple(value["limited_unit_ids"]),
            contexts=tuple(GroundingContextRecord.from_dict(item) for item in value["contexts"]),
            receipt_sha256=value["receipt_sha256"],
        )


def _grounding_json(values: dict[str, object]) -> dict[str, object]:
    def json_value(value: object) -> object:
        if isinstance(value, tuple):
            return [json_value(item) for item in value]
        if isinstance(value, GroundingContextRecord | GroundingEvidenceRecord | SourceSpan | GroundingCoverage):
            return value.to_dict()
        return value

    return {key: json_value(value) for key, value in values.items()}
