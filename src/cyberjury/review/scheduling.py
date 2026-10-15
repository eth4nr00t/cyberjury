"""Strict execution receipts for shared review scheduling."""

from __future__ import annotations

import math
from dataclasses import dataclass

from cyberjury.canonical import canonical_sha256

SCHEDULING_SCHEMA = "cyberjury.scheduling/v3"
_EXECUTED_STOP_REASONS = {"complete", "incomplete"}
_EMPTY_STOP_REASONS = {"no_reviewable_units", "no_open_units"}


def _string_ids(value: object, label: str, *, prefix: str = "") -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or not all(
        isinstance(item, str) and item and item.startswith(prefix) for item in value
    ):
        raise ValueError(f"scheduling {label} must be a string list")
    if len(value) != len(set(value)):
        raise ValueError(f"scheduling {label} must not contain duplicates")
    return tuple(value)


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedulingReceipt:
    """One attempt's exact unit fan-out and its completion state."""

    unit_ids: tuple[str, ...]
    new_finding_ids: tuple[str, ...]
    union_finding_ids: tuple[str, ...]
    errors: int
    failures: int
    incomplete: int
    clean: bool
    duration_seconds: float
    stop_reason: str
    content_sha256: str
    schema: str = SCHEDULING_SCHEMA

    def __post_init__(self) -> None:
        """Reject scheduling state that cannot explain one execution."""
        if self.schema != SCHEDULING_SCHEMA:
            raise ValueError("scheduling receipt schema is unsupported")
        _string_ids(self.unit_ids, "unit_ids")
        _string_ids(self.new_finding_ids, "new_finding_ids", prefix="union-")
        _string_ids(self.union_finding_ids, "union_finding_ids", prefix="union-")
        if not set(self.new_finding_ids).issubset(self.union_finding_ids):
            raise ValueError("scheduling new finding ids are outside the union")
        for name in ("errors", "failures", "incomplete"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"scheduling {name} must be a nonnegative integer")
        if not isinstance(self.clean, bool):
            raise ValueError("scheduling clean state must be boolean")
        if self.clean and any((self.errors, self.failures, self.incomplete)):
            raise ValueError("a clean scheduling receipt cannot contain incomplete work")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, int | float)
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ValueError("scheduling duration_seconds must be finite and nonnegative")
        if not isinstance(self.stop_reason, str):
            raise ValueError("scheduling stop_reason is invalid")
        if self.stop_reason in _EMPTY_STOP_REASONS:
            if self.unit_ids or self.union_finding_ids or not self.clean or self.duration_seconds:
                raise ValueError("nonexecuting scheduling receipts cannot contain executed work")
        elif self.stop_reason in _EXECUTED_STOP_REASONS:
            if not self.unit_ids:
                raise ValueError("executed scheduling receipts require units")
            if self.clean != (self.stop_reason == "complete"):
                raise ValueError("scheduling stop_reason contradicts its clean state")
        else:
            raise ValueError("scheduling stop_reason is invalid")
        if self.content_sha256 != canonical_sha256(self.semantic_dict()):
            raise ValueError("scheduling content hash does not match its receipt")

    @classmethod
    def create(
        cls,
        *,
        unit_ids: tuple[str, ...],
        new_finding_ids: tuple[str, ...],
        union_finding_ids: tuple[str, ...],
        errors: int,
        failures: int,
        incomplete: int,
        clean: bool,
        duration_seconds: float,
    ) -> SchedulingReceipt:
        """Create one content addressed receipt for an executed unit fan-out."""
        return cls._sealed(
            unit_ids=unit_ids,
            new_finding_ids=new_finding_ids,
            union_finding_ids=union_finding_ids,
            errors=errors,
            failures=failures,
            incomplete=incomplete,
            clean=clean,
            duration_seconds=duration_seconds,
            stop_reason="complete" if clean else "incomplete",
        )

    @classmethod
    def empty(cls, *, stop_reason: str) -> SchedulingReceipt:
        """Record a run action that correctly scheduled no unit execution."""
        return cls._sealed(
            unit_ids=(),
            new_finding_ids=(),
            union_finding_ids=(),
            errors=0,
            failures=0,
            incomplete=0,
            clean=True,
            duration_seconds=0,
            stop_reason=stop_reason,
        )

    @classmethod
    def _sealed(cls, **semantic: object) -> SchedulingReceipt:
        return cls(**semantic, content_sha256=canonical_sha256(semantic))

    def semantic_dict(self) -> dict[str, object]:
        """Return the fields covered by the content hash."""
        return {
            "unit_ids": list(self.unit_ids),
            "new_finding_ids": list(self.new_finding_ids),
            "union_finding_ids": list(self.union_finding_ids),
            "errors": self.errors,
            "failures": self.failures,
            "incomplete": self.incomplete,
            "clean": self.clean,
            "duration_seconds": self.duration_seconds,
            "stop_reason": self.stop_reason,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict persisted artifact."""
        return {"schema": self.schema, **self.semantic_dict(), "content_sha256": self.content_sha256}

    @classmethod
    def from_dict(cls, value: object) -> SchedulingReceipt:
        """Load and verify one persisted scheduling artifact."""
        fields = {
            "schema",
            "unit_ids",
            "new_finding_ids",
            "union_finding_ids",
            "errors",
            "failures",
            "incomplete",
            "clean",
            "duration_seconds",
            "stop_reason",
            "content_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("scheduling receipt has an invalid shape")
        id_fields = {"unit_ids", "new_finding_ids", "union_finding_ids"}
        return cls(
            **{key: item for key, item in value.items() if key not in id_fields},
            unit_ids=_string_ids(value["unit_ids"], "unit_ids"),
            new_finding_ids=_string_ids(value["new_finding_ids"], "new_finding_ids", prefix="union-"),
            union_finding_ids=_string_ids(value["union_finding_ids"], "union_finding_ids", prefix="union-"),
        )
