"""Persist strict receipts for initial grounding envelopes."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.canonical import canonical_sha256, text_sha256
from cyberjury.review.context import EvidenceItem, GroundingContext, SourceEvidence
from cyberjury.review.unit_plans import UnitPlanReceipt

GROUNDING_SCHEMA = "cyberjury.grounding/v5"


@dataclass(frozen=True, kw_only=True)
class GroundingContextRecord:
    """Bind one planned unit to its initial source and evidence envelope."""

    unit_id: str
    record: dict[str, object]

    @classmethod
    def create(cls, *, unit_id: str, context: GroundingContext) -> GroundingContextRecord:
        """Create one initial context receipt from exact in-memory evidence."""
        if context.source_snapshot is None:
            raise ValueError("grounding context needs a bound source snapshot")
        controls = context.prompt.controls
        semantic = {
            "unit_id": unit_id,
            "source_snapshot_id": context.source_snapshot.snapshot_id,
            "files": list(context.files),
            "snapshot_files": list(context.snapshot_files),
            "source_spans": [span.to_dict() for span in context.source_spans],
            "coverage": context.coverage.to_dict(),
            "seed_chars": len(context.seed),
            "seed_sha256": text_sha256(context.seed),
            "context_chars": len(context.text),
            "context_sha256": text_sha256(context.text),
            "syntax_hints_chars": len(context.syntax_hints),
            "syntax_hints_sha256": text_sha256(context.syntax_hints),
            "controls_chars": len(controls),
            "controls_sha256": text_sha256(controls),
            "evidence": [_content_record(item) for item in context.evidence],
            "source_evidence": [_content_record(item) for item in context.source_evidence],
        }
        return cls(
            unit_id=unit_id,
            record={**semantic, "record_sha256": canonical_sha256(semantic)},
        )

    def to_dict(self) -> dict[str, object]:
        """Return one strict grounding context receipt."""
        return dict(self.record)


@dataclass(frozen=True, kw_only=True)
class GroundingReceipt:
    """Bind every Stage 06 unit to one initial evidence envelope."""

    unit_plan_receipt_sha256: str
    contexts: tuple[GroundingContextRecord, ...]
    receipt_sha256: str

    @classmethod
    def create(
        cls,
        *,
        unit_plan: UnitPlanReceipt,
        contexts: tuple[GroundingContext, ...],
    ) -> GroundingReceipt:
        """Create the complete initial grounding receipt in unit plan order."""
        records = tuple(
            GroundingContextRecord.create(unit_id=unit.id, context=context)
            for unit, context in zip(unit_plan.units, contexts, strict=True)
        )
        return cls(
            unit_plan_receipt_sha256=unit_plan.receipt_sha256,
            contexts=records,
            receipt_sha256=canonical_sha256(_receipt_semantic(unit_plan.receipt_sha256, records)),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict Stage 07 artifact."""
        return {
            "schema": GROUNDING_SCHEMA,
            **_receipt_semantic(self.unit_plan_receipt_sha256, self.contexts),
            "receipt_sha256": self.receipt_sha256,
        }


def _receipt_semantic(unit_plan_receipt_sha256: str, contexts: tuple[GroundingContextRecord, ...]) -> dict[str, object]:
    return {
        "unit_plan_receipt_sha256": unit_plan_receipt_sha256,
        "context_count": len(contexts),
        "contexts": [context.to_dict() for context in contexts],
    }


def _content_record(item: EvidenceItem | SourceEvidence) -> dict[str, object]:
    catalog = {"label": item.label, "preview": item.preview} if isinstance(item, EvidenceItem) else {}
    return {
        "id": item.id,
        "identity": item.identity,
        **catalog,
        "content_chars": len(item.text),
        "content_sha256": text_sha256(item.text),
        "source_span": item.source_span.to_dict() if item.source_span is not None else None,
    }
