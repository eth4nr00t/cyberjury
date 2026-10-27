"""Shared observable schema for deterministic review unit plans."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from cyberjury.canonical import canonical_sha256, text_sha256
from cyberjury.review.facts import FactsReceipt

PLAN_SCHEMA = "cyberjury.plan/v1"

type UnitKind = Literal["diff", "source"]


@dataclass(frozen=True, order=True, kw_only=True)
class UnitSourceSlice:
    """Identify one normalized source range owned or requested by a unit."""

    path: str
    start: int
    end: int

    def to_dict(self) -> dict[str, object]:
        """Return the strict source slice record."""
        return {"path": self.path, "range": [self.start, self.end]}


@dataclass(frozen=True, kw_only=True)
class UnitPlanRecord:
    """Describe one deterministic model work item."""

    id: str
    kind: UnitKind
    name: str
    owned_paths: tuple[str, ...]
    source_slices: tuple[UnitSourceSlice, ...]
    patch_sha256: str | None

    @classmethod
    def create(
        cls,
        *,
        kind: UnitKind,
        name: str,
        owned_paths: tuple[str, ...],
        source_slices: tuple[UnitSourceSlice, ...] = (),
        patch_text: str | None = None,
    ) -> UnitPlanRecord:
        """Build one record whose id covers every planned field."""
        record = cls(
            id="",
            kind=kind,
            name=name,
            owned_paths=tuple(dict.fromkeys(owned_paths)),
            source_slices=tuple(dict.fromkeys(source_slices)),
            patch_sha256=text_sha256(patch_text) if patch_text is not None else None,
        )
        return replace(record, id=f"unit-{canonical_sha256(record.semantic_dict())[:16]}")

    def semantic_dict(self) -> dict[str, object]:
        """Return every unit field covered by its stable id."""
        return {
            "kind": self.kind,
            "name": self.name,
            "owned_paths": list(self.owned_paths),
            "source_slices": [source.to_dict() for source in self.source_slices],
            "patch_sha256": self.patch_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict unit plan record."""
        return {"id": self.id, **self.semantic_dict()}


@dataclass(frozen=True, kw_only=True)
class UnitPlanReceipt:
    """Bind one complete deterministic unit worklist to its extracted facts."""

    facts_receipt_sha256: str
    units: tuple[UnitPlanRecord, ...]
    receipt_sha256: str

    @classmethod
    def create(cls, *, facts: FactsReceipt, units: tuple[UnitPlanRecord, ...]) -> UnitPlanReceipt:
        """Build one unit plan bound to its facts receipt."""
        receipt = cls(facts_receipt_sha256=facts.receipt_sha256, units=units, receipt_sha256="")
        return replace(receipt, receipt_sha256=canonical_sha256(receipt.semantic_dict()))

    def semantic_dict(self) -> dict[str, object]:
        """Return every receipt field covered by the receipt hash."""
        return {
            "facts_receipt_sha256": self.facts_receipt_sha256,
            "units": [unit.to_dict() for unit in self.units],
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict unit plan artifact."""
        return {"schema": PLAN_SCHEMA, **self.semantic_dict(), "receipt_sha256": self.receipt_sha256}
