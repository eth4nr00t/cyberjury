"""Strict execution receipts for shared review scheduling."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass

SCHEDULING_SCHEMA = "cyberjury.scheduling/v2"
_V1_SCHEDULING_SCHEMA = "cyberjury.scheduling/v1"
_STOP_REASONS = {
    "checkpoint_failure",
    "converged",
    "failure",
    "incomplete",
    "no_reviewable_units",
    "no_open_units",
    "round_limit",
    "single_complete",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def schedule_sha256(schedule: dict[str, object]) -> str:
    """Identify the exact validated schedule stored in an attempt request."""
    return _sha256(schedule)


def _nonnegative(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"scheduling {label} must be a nonnegative integer")
    return value


def _unit_ids(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"scheduling {label} must be a string list")
    if len(value) != len(set(value)):
        raise ValueError(f"scheduling {label} must not contain duplicates")
    return tuple(value)


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedulingRound:
    """One completed scheduler round in planned unit order."""

    round: int
    unit_ids: tuple[str, ...]
    new_findings: int
    union_size: int
    errors: int
    failures: int
    recovered_failures: int
    incomplete: int
    pending: int
    convergence_streak: int
    clean: bool
    converged: bool
    duration_seconds: float
    new_finding_ids: tuple[str, ...] = ()
    union_finding_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject a round that cannot be reconciled to scheduler state."""
        if isinstance(self.round, bool) or not isinstance(self.round, int) or self.round < 1:
            raise ValueError("scheduling round must be a positive integer")
        if (
            not isinstance(self.unit_ids, tuple)
            or not self.unit_ids
            or any(not isinstance(item, str) or not item for item in self.unit_ids)
        ):
            raise ValueError("scheduling round unit_ids must be a nonempty string tuple")
        if len(self.unit_ids) != len(set(self.unit_ids)):
            raise ValueError("scheduling round unit_ids must not contain duplicates")
        for field in (
            "new_findings",
            "union_size",
            "errors",
            "failures",
            "recovered_failures",
            "incomplete",
            "pending",
            "convergence_streak",
        ):
            _nonnegative(getattr(self, field), f"round {field}")
        if self.new_findings > self.union_size:
            raise ValueError("scheduling round new_findings cannot exceed union_size")
        for field, expected in (
            ("new_finding_ids", self.new_findings),
            ("union_finding_ids", self.union_size),
        ):
            values = getattr(self, field)
            if not isinstance(values, tuple) or any(
                not isinstance(item, str) or not item.startswith("union-") for item in values
            ):
                raise ValueError(f"scheduling round {field} must contain union ids")
            if values and (len(values) != expected or len(values) != len(set(values))):
                raise ValueError(f"scheduling round {field} does not match its count")
        if self.new_finding_ids and not set(self.new_finding_ids).issubset(self.union_finding_ids):
            raise ValueError("scheduling round new finding ids are outside the union")
        if not isinstance(self.clean, bool) or not isinstance(self.converged, bool):
            raise ValueError("scheduling round state must be boolean")
        if self.clean and any((self.errors, self.failures, self.incomplete)):
            raise ValueError("a clean scheduling round cannot contain incomplete work")
        if self.converged and (not self.clean or self.convergence_streak < 1):
            raise ValueError("a converged scheduling round must end a clean streak")
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, int | float)
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ValueError("scheduling round duration_seconds must be finite and nonnegative")

    def to_dict(self, *, include_finding_ids: bool = True) -> dict[str, object]:
        """Return the strict persisted round form."""
        value = {
            "round": self.round,
            "unit_ids": list(self.unit_ids),
            "new_findings": self.new_findings,
            "union_size": self.union_size,
            "errors": self.errors,
            "failures": self.failures,
            "recovered_failures": self.recovered_failures,
            "incomplete": self.incomplete,
            "pending": self.pending,
            "convergence_streak": self.convergence_streak,
            "clean": self.clean,
            "converged": self.converged,
            "duration_seconds": self.duration_seconds,
        }
        if include_finding_ids:
            value["new_finding_ids"] = list(self.new_finding_ids)
            value["union_finding_ids"] = list(self.union_finding_ids)
        return value

    @classmethod
    def from_dict(cls, value: object, *, include_finding_ids: bool = True) -> SchedulingRound:
        """Load one strict scheduler round."""
        fields = {
            "round",
            "unit_ids",
            "new_findings",
            "union_size",
            "errors",
            "failures",
            "recovered_failures",
            "incomplete",
            "pending",
            "convergence_streak",
            "clean",
            "converged",
            "duration_seconds",
        }
        if include_finding_ids:
            fields.update({"new_finding_ids", "union_finding_ids"})
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("scheduling round has an invalid shape")
        list_fields = {"unit_ids", "new_finding_ids", "union_finding_ids"}
        return cls(
            **{key: item for key, item in value.items() if key not in list_fields},
            unit_ids=_unit_ids(value["unit_ids"], "round unit_ids"),
            new_finding_ids=(
                _unit_ids(value["new_finding_ids"], "round new_finding_ids") if include_finding_ids else ()
            ),
            union_finding_ids=(
                _unit_ids(value["union_finding_ids"], "round union_finding_ids") if include_finding_ids else ()
            ),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class SchedulingReceipt:
    """One attempt's exact unit, round, and stopping record."""

    schedule_sha256: str
    unit_ids: tuple[str, ...]
    rounds: tuple[SchedulingRound, ...]
    stop_reason: str
    content_sha256: str
    schema: str = SCHEDULING_SCHEMA

    def __post_init__(self) -> None:
        """Reject scheduling state that cannot explain one execution."""
        if not isinstance(self.schedule_sha256, str) or len(self.schedule_sha256) != 64:
            raise ValueError("scheduling schedule_sha256 must be a SHA-256 digest")
        if any(character not in "0123456789abcdef" for character in self.schedule_sha256):
            raise ValueError("scheduling schedule_sha256 must be a SHA-256 digest")
        if not isinstance(self.unit_ids, tuple) or any(not isinstance(item, str) or not item for item in self.unit_ids):
            raise ValueError("scheduling unit_ids must be a string tuple")
        if len(self.unit_ids) != len(set(self.unit_ids)):
            raise ValueError("scheduling unit_ids must not contain duplicates")
        if not isinstance(self.rounds, tuple) or not all(isinstance(item, SchedulingRound) for item in self.rounds):
            raise ValueError("scheduling rounds must be a round tuple")
        if tuple(item.round for item in self.rounds) != tuple(range(1, len(self.rounds) + 1)):
            raise ValueError("scheduling rounds must be consecutive")
        if any(item.unit_ids != self.unit_ids for item in self.rounds):
            raise ValueError("scheduling round units do not match the planned units")
        if any(item.converged for item in self.rounds[:-1]):
            raise ValueError("scheduling continued after convergence")
        if self.schema not in {SCHEDULING_SCHEMA, _V1_SCHEDULING_SCHEMA}:
            raise ValueError("scheduling receipt schema is unsupported")
        if self.schema == SCHEDULING_SCHEMA and any(
            len(item.new_finding_ids) != item.new_findings or len(item.union_finding_ids) != item.union_size
            for item in self.rounds
        ):
            raise ValueError("scheduling receipt finding identities do not match round counts")
        if self.schema == _V1_SCHEDULING_SCHEMA and any(
            item.new_finding_ids or item.union_finding_ids for item in self.rounds
        ):
            raise ValueError("legacy scheduling receipt cannot contain finding identities")
        for previous, current in zip(self.rounds, self.rounds[1:], strict=False):
            if current.union_size != previous.union_size + current.new_findings:
                raise ValueError("scheduling round union growth is inconsistent")
            if self.schema == SCHEDULING_SCHEMA and set(current.union_finding_ids) != {
                *previous.union_finding_ids,
                *current.new_finding_ids,
            }:
                raise ValueError("scheduling round union identities are inconsistent")
        if not isinstance(self.stop_reason, str) or self.stop_reason not in _STOP_REASONS:
            raise ValueError("scheduling stop_reason is invalid")
        if self.stop_reason in {"no_open_units", "no_reviewable_units"}:
            if self.unit_ids or self.rounds:
                raise ValueError("nonexecuting scheduling receipts cannot contain units or rounds")
        elif not self.unit_ids or not self.rounds:
            raise ValueError("executed scheduling receipts require units and rounds")
        elif self.stop_reason == "converged" and not self.rounds[-1].converged:
            raise ValueError("converged scheduling receipt has no converged final round")
        elif self.stop_reason != "converged" and self.rounds[-1].converged:
            raise ValueError("nonconverged scheduling receipt has a converged final round")
        elif self.stop_reason == "single_complete" and (len(self.rounds) != 1 or not self.rounds[-1].clean):
            raise ValueError("single scheduling receipt must contain one clean round")
        elif self.stop_reason in {"failure", "checkpoint_failure"} and self.rounds[-1].clean:
            raise ValueError("failed scheduling receipt has a clean final round")
        elif self.stop_reason == "incomplete" and self.rounds[-1].clean and not self.rounds[-1].pending:
            raise ValueError("incomplete scheduling receipt has no incomplete final state")
        if self.content_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("scheduling content hash does not match its receipt")

    @classmethod
    def create(
        cls,
        *,
        schedule: dict[str, object],
        unit_ids: tuple[str, ...],
        rounds: tuple[SchedulingRound, ...],
        stop_reason: str,
    ) -> SchedulingReceipt:
        """Create one content addressed scheduling receipt."""
        schedule_digest = schedule_sha256(schedule)
        semantic: dict[str, object] = {
            "schedule_sha256": schedule_digest,
            "unit_ids": unit_ids,
            "rounds": tuple(item.to_dict() for item in rounds),
            "stop_reason": stop_reason,
        }
        return cls(
            schedule_sha256=schedule_digest,
            unit_ids=unit_ids,
            rounds=rounds,
            stop_reason=stop_reason,
            content_sha256=_sha256(semantic),
            schema=SCHEDULING_SCHEMA,
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return the fields covered by the content hash."""
        return {
            "schedule_sha256": self.schedule_sha256,
            "unit_ids": self.unit_ids,
            "rounds": tuple(item.to_dict(include_finding_ids=self.schema == SCHEDULING_SCHEMA) for item in self.rounds),
            "stop_reason": self.stop_reason,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict persisted artifact."""
        return {
            "schema": self.schema,
            "schedule_sha256": self.schedule_sha256,
            "unit_ids": list(self.unit_ids),
            "rounds": [item.to_dict(include_finding_ids=self.schema == SCHEDULING_SCHEMA) for item in self.rounds],
            "stop_reason": self.stop_reason,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> SchedulingReceipt:
        """Load and verify one persisted scheduling artifact."""
        fields = {"schema", "schedule_sha256", "unit_ids", "rounds", "stop_reason", "content_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("scheduling receipt has an invalid shape")
        if value["schema"] not in {SCHEDULING_SCHEMA, _V1_SCHEDULING_SCHEMA}:
            raise ValueError("scheduling receipt schema is unsupported")
        if not isinstance(value["rounds"], list):
            raise ValueError("scheduling receipt rounds must be a list")
        return cls(
            schedule_sha256=value["schedule_sha256"],
            unit_ids=_unit_ids(value["unit_ids"], "unit_ids"),
            rounds=tuple(
                SchedulingRound.from_dict(item, include_finding_ids=value["schema"] == SCHEDULING_SCHEMA)
                for item in value["rounds"]
            ),
            stop_reason=value["stop_reason"],
            content_sha256=value["content_sha256"],
            schema=value["schema"],
        )
