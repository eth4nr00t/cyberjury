"""Shared observable schema for deterministic review unit plans."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from cyberjury.review.facts import FactsResolutionReceipt

UNIT_PLAN_SCHEMA = "cyberjury.unit-plan/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

type UnitKind = Literal["diff", "source", "relationship", "focused"]


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _stable_id(prefix: str, value: object) -> str:
    return f"{prefix}-{_sha256(value)[:16]}"


def _source_path(path: str) -> str:
    if not isinstance(path, str):
        raise ValueError("unit plan source path must be a normalized repository path")
    normalized = PurePosixPath(path)
    if (
        not path
        or path == "."
        or path.startswith("/")
        or "\\" in path
        or normalized.as_posix() != path
        or ".." in normalized.parts
    ):
        raise ValueError("unit plan source path must be a normalized repository path")
    return path


@dataclass(frozen=True, order=True, kw_only=True)
class UnitSourceSlice:
    """Identify one normalized source range owned or requested by a unit."""

    path: str
    start: int
    end: int

    def __post_init__(self) -> None:
        """Reject unsafe paths and invalid character ranges."""
        _source_path(self.path)
        if (
            isinstance(self.start, bool)
            or not isinstance(self.start, int)
            or isinstance(self.end, bool)
            or not isinstance(self.end, int)
            or self.start < 0
            or self.end <= self.start
        ):
            raise ValueError("unit plan source slice must have a valid character range")

    def to_dict(self) -> dict[str, object]:
        """Return the strict source slice record."""
        return {"path": self.path, "range": [self.start, self.end]}

    @classmethod
    def from_dict(cls, value: object) -> UnitSourceSlice:
        """Load one strict source slice record."""
        if not isinstance(value, dict) or set(value) != {"path", "range"}:
            raise ValueError("unit plan source slice has an unsupported shape")
        span = value["range"]
        if not isinstance(span, list) or len(span) != 2:
            raise ValueError("unit plan source slice range must contain start and end")
        return cls(path=value["path"], start=span[0], end=span[1])


def _source_union_size(slices: tuple[UnitSourceSlice, ...]) -> int:
    by_path: dict[str, list[tuple[int, int]]] = {}
    for source in slices:
        by_path.setdefault(source.path, []).append((source.start, source.end))
    total = 0
    for ranges in by_path.values():
        current_start = current_end = -1
        for start, end in sorted(ranges):
            if start > current_end:
                if current_end >= 0:
                    total += current_end - current_start
                current_start, current_end = start, end
            else:
                current_end = max(current_end, end)
        if current_end >= 0:
            total += current_end - current_start
    return total


def _overlapping_source_chars(units: tuple[UnitPlanRecord, ...]) -> int:
    by_path: dict[str, list[tuple[int, int]]] = {}
    for unit in units:
        if unit.kind not in {"source", "focused"}:
            continue
        for source in unit.source_slices:
            by_path.setdefault(source.path, []).append((source.start, source.end))
    overlap = 0
    for ranges in by_path.values():
        covered_end = -1
        for start, end in sorted(ranges):
            if start < covered_end:
                overlap += min(end, covered_end) - start
            covered_end = max(covered_end, end)
    return overlap


@dataclass(frozen=True, kw_only=True)
class UnitPlanRecord:
    """Describe one deterministic model work item and its planned code budget."""

    id: str
    kind: UnitKind
    name: str
    labels: tuple[str, ...]
    owned_paths: tuple[str, ...]
    source_slices: tuple[UnitSourceSlice, ...]
    seed_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    unresolved_ids: tuple[str, ...]
    patch_chars: int
    patch_sha256: str | None
    source_chars: int
    relationship_chars: int
    estimated_code_tokens: int
    over_target_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject incomplete or internally inconsistent unit records."""
        if (
            not isinstance(self.kind, str)
            or self.kind not in {"diff", "source", "relationship", "focused"}
            or not isinstance(self.name, str)
            or not self.name
        ):
            raise ValueError("unit plan record needs a supported kind and name")
        if not isinstance(self.id, str):
            raise ValueError("unit plan record id is invalid")
        if not self.owned_paths or any(_source_path(path) != path for path in self.owned_paths):
            raise ValueError("unit plan record needs owned repository paths")
        if not all(isinstance(source, UnitSourceSlice) for source in self.source_slices):
            raise ValueError("unit plan source slices must be source slice records")
        for label, values in (
            ("label", self.labels),
            ("seed", self.seed_ids),
            ("relationship", self.relationship_ids),
            ("unresolved relationship", self.unresolved_ids),
            ("over target reason", self.over_target_reasons),
        ):
            if not all(isinstance(value, str) and value for value in values):
                raise ValueError(f"unit plan record {label} values must be nonempty strings")
        for label, values in (
            ("owned path", self.owned_paths),
            (
                "source slice",
                tuple(source.to_dict()["path"] + str(source.to_dict()["range"]) for source in self.source_slices),
            ),
            ("seed", self.seed_ids),
            ("relationship", self.relationship_ids),
            ("unresolved relationship", self.unresolved_ids),
            ("over target reason", self.over_target_reasons),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"unit plan record contains duplicate {label} values")
        counts = (self.patch_chars, self.source_chars, self.relationship_chars, self.estimated_code_tokens)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("unit plan record contains an invalid size")
        if self.kind == "diff":
            if not isinstance(self.patch_sha256, str) or not _SHA256.fullmatch(self.patch_sha256):
                raise ValueError("diff unit plan needs an exact patch hash")
        elif self.patch_chars != 0 or self.patch_sha256 is not None:
            raise ValueError("non-diff unit plans cannot contain patch evidence")
        if self.source_chars != _source_union_size(self.source_slices):
            raise ValueError("unit plan source character count does not match its slices")
        if self.relationship_chars != sum(len(value) for value in (*self.relationship_ids, *self.unresolved_ids)):
            raise ValueError("unit plan relationship character count does not match its identities")
        expected_tokens = (self.patch_chars + self.source_chars + self.relationship_chars + 3) // 4
        if self.estimated_code_tokens != expected_tokens:
            raise ValueError("unit plan token estimate does not match its planned code")
        if self.id != _stable_id("unit", self.semantic_dict()):
            raise ValueError("unit plan record id does not match its content")

    @classmethod
    def create(
        cls,
        *,
        kind: UnitKind,
        name: str,
        labels: tuple[str, ...] = (),
        owned_paths: tuple[str, ...],
        source_slices: tuple[UnitSourceSlice, ...] = (),
        seed_ids: tuple[str, ...] = (),
        relationship_ids: tuple[str, ...] = (),
        unresolved_ids: tuple[str, ...] = (),
        patch_text: str | None = None,
        over_target_reasons: tuple[str, ...] = (),
    ) -> UnitPlanRecord:
        """Build one record with derived size and identity fields."""
        semantic = {
            "kind": kind,
            "name": name,
            "labels": tuple(dict.fromkeys(labels)),
            "owned_paths": tuple(dict.fromkeys(owned_paths)),
            "source_slices": tuple(dict.fromkeys(source_slices)),
            "seed_ids": tuple(dict.fromkeys(seed_ids)),
            "relationship_ids": tuple(dict.fromkeys(relationship_ids)),
            "unresolved_ids": tuple(dict.fromkeys(unresolved_ids)),
            "patch_chars": len(patch_text) if patch_text is not None else 0,
            "patch_sha256": hashlib.sha256(patch_text.encode()).hexdigest() if patch_text is not None else None,
            "source_chars": _source_union_size(tuple(dict.fromkeys(source_slices))),
            "relationship_chars": sum(
                len(value)
                for value in (
                    *tuple(dict.fromkeys(relationship_ids)),
                    *tuple(dict.fromkeys(unresolved_ids)),
                )
            ),
            "over_target_reasons": tuple(dict.fromkeys(over_target_reasons)),
        }
        semantic["estimated_code_tokens"] = (
            semantic["patch_chars"] + semantic["source_chars"] + semantic["relationship_chars"] + 3
        ) // 4
        return cls(id=_stable_id("unit", _semantic_data(semantic)), **semantic)

    def semantic_dict(self) -> dict[str, object]:
        """Return every unit field covered by its stable id."""
        return {
            "kind": self.kind,
            "name": self.name,
            "labels": list(self.labels),
            "owned_paths": list(self.owned_paths),
            "source_slices": [source.to_dict() for source in self.source_slices],
            "seed_ids": list(self.seed_ids),
            "relationship_ids": list(self.relationship_ids),
            "unresolved_ids": list(self.unresolved_ids),
            "patch_chars": self.patch_chars,
            "patch_sha256": self.patch_sha256,
            "source_chars": self.source_chars,
            "relationship_chars": self.relationship_chars,
            "estimated_code_tokens": self.estimated_code_tokens,
            "over_target_reasons": list(self.over_target_reasons),
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict unit plan record."""
        return {"id": self.id, **self.semantic_dict()}

    @classmethod
    def from_dict(cls, value: object) -> UnitPlanRecord:
        """Load one strict unit plan record."""
        fields = {
            "id",
            "kind",
            "name",
            "labels",
            "owned_paths",
            "source_slices",
            "seed_ids",
            "relationship_ids",
            "unresolved_ids",
            "patch_chars",
            "patch_sha256",
            "source_chars",
            "relationship_chars",
            "estimated_code_tokens",
            "over_target_reasons",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("unit plan record has an unsupported shape")
        lists = (
            "labels",
            "owned_paths",
            "source_slices",
            "seed_ids",
            "relationship_ids",
            "unresolved_ids",
            "over_target_reasons",
        )
        if any(not isinstance(value[field], list) for field in lists):
            raise ValueError("unit plan record list fields must be lists")
        return cls(
            id=value["id"],
            kind=value["kind"],
            name=value["name"],
            labels=tuple(value["labels"]),
            owned_paths=tuple(value["owned_paths"]),
            source_slices=tuple(UnitSourceSlice.from_dict(item) for item in value["source_slices"]),
            seed_ids=tuple(value["seed_ids"]),
            relationship_ids=tuple(value["relationship_ids"]),
            unresolved_ids=tuple(value["unresolved_ids"]),
            patch_chars=value["patch_chars"],
            patch_sha256=value["patch_sha256"],
            source_chars=value["source_chars"],
            relationship_chars=value["relationship_chars"],
            estimated_code_tokens=value["estimated_code_tokens"],
            over_target_reasons=tuple(value["over_target_reasons"]),
        )


@dataclass(frozen=True, kw_only=True)
class UnitPlanReceipt:
    """Bind one complete deterministic unit worklist to Stage 05 facts."""

    facts_resolution_receipt_sha256: str
    unit_count: int
    owned_path_count: int
    expected_owned_paths: tuple[str, ...]
    unowned_paths: tuple[str, ...]
    excluded_empty_paths: tuple[str, ...]
    expected_seed_ids: tuple[str, ...]
    unowned_seed_ids: tuple[str, ...]
    multi_unit_seed_ids: tuple[str, ...]
    overlapping_source_chars: int
    over_target_unit_count: int
    units: tuple[UnitPlanRecord, ...]
    plan_sha256: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        """Reject a unit plan that does not match its ownership summary."""
        if not isinstance(self.facts_resolution_receipt_sha256, str) or not _SHA256.fullmatch(
            self.facts_resolution_receipt_sha256
        ):
            raise ValueError("unit plan facts resolution hash is invalid")
        counts = (
            self.unit_count,
            self.owned_path_count,
            self.overlapping_source_chars,
            self.over_target_unit_count,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
            raise ValueError("unit plan receipt count is invalid")
        if not all(isinstance(unit, UnitPlanRecord) for unit in self.units):
            raise ValueError("unit plan receipt units must be unit records")
        for label, values in (
            ("expected owned path", self.expected_owned_paths),
            ("unowned path", self.unowned_paths),
            ("excluded empty path", self.excluded_empty_paths),
            ("expected", self.expected_seed_ids),
            ("unowned", self.unowned_seed_ids),
            ("multi unit", self.multi_unit_seed_ids),
        ):
            if not all(isinstance(value, str) and value for value in values):
                raise ValueError(f"unit plan {label} values must be nonempty strings")
        for path in (*self.expected_owned_paths, *self.unowned_paths, *self.excluded_empty_paths):
            _source_path(path)
        if self.unit_count != len(self.units):
            raise ValueError("unit plan receipt needs every planned unit")
        if len({unit.id for unit in self.units}) != len(self.units):
            raise ValueError("unit plan receipt contains duplicate unit ids")
        if len({unit.name for unit in self.units}) != len(self.units):
            raise ValueError("unit plan receipt contains duplicate unit names")
        expected = tuple(dict.fromkeys(self.expected_seed_ids))
        owners = Counter(seed for unit in self.units for seed in unit.seed_ids if seed in expected)
        if self.expected_seed_ids != expected:
            raise ValueError("unit plan expected seeds must be unique")
        if self.unowned_seed_ids != tuple(seed for seed in expected if owners[seed] == 0):
            raise ValueError("unit plan unowned seeds do not match unit ownership")
        if self.multi_unit_seed_ids != tuple(seed for seed in expected if owners[seed] > 1):
            raise ValueError("unit plan multi unit seeds do not match unit ownership")
        if self.owned_path_count != len({path for unit in self.units for path in unit.owned_paths}):
            raise ValueError("unit plan owned path count does not match its units")
        expected_paths = tuple(dict.fromkeys(self.expected_owned_paths))
        owned_paths = {path for unit in self.units for path in unit.owned_paths}
        excluded_paths = tuple(dict.fromkeys(self.excluded_empty_paths))
        if self.expected_owned_paths != expected_paths:
            raise ValueError("unit plan expected owned paths must be unique")
        if self.excluded_empty_paths != excluded_paths or any(path not in expected_paths for path in excluded_paths):
            raise ValueError("unit plan excluded empty paths must be unique expected paths")
        if any(path in owned_paths for path in excluded_paths):
            raise ValueError("unit plan excluded empty paths cannot own review work")
        if self.unowned_paths != tuple(
            path for path in expected_paths if path not in owned_paths and path not in excluded_paths
        ):
            raise ValueError("unit plan unowned paths do not match unit ownership")
        if self.overlapping_source_chars != _overlapping_source_chars(self.units):
            raise ValueError("unit plan overlapping source character count does not match its units")
        if self.over_target_unit_count != sum(bool(unit.over_target_reasons) for unit in self.units):
            raise ValueError("unit plan over target count does not match its units")
        if not isinstance(self.plan_sha256, str) or not _SHA256.fullmatch(self.plan_sha256):
            raise ValueError("unit plan hash is invalid")
        if self.plan_sha256 != _sha256(self.plan_dict()):
            raise ValueError("unit plan hash does not match its worklist")
        if not isinstance(self.receipt_sha256, str) or not _SHA256.fullmatch(self.receipt_sha256):
            raise ValueError("unit plan receipt hash is invalid")
        if self.receipt_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("unit plan receipt hash does not match its content")

    @classmethod
    def create(
        cls,
        *,
        facts_resolution: FactsResolutionReceipt,
        units: tuple[UnitPlanRecord, ...],
        expected_owned_paths: tuple[str, ...] = (),
        excluded_empty_paths: tuple[str, ...] = (),
        expected_seed_ids: tuple[str, ...] = (),
    ) -> UnitPlanReceipt:
        """Build one complete unit plan receipt bound to Stage 05 facts."""
        expected = tuple(dict.fromkeys(expected_seed_ids))
        owned_paths = {path for unit in units for path in unit.owned_paths}
        expected_paths = tuple(dict.fromkeys(expected_owned_paths)) or tuple(sorted(owned_paths))
        excluded_paths = tuple(dict.fromkeys(excluded_empty_paths))
        owners = Counter(seed for unit in units for seed in unit.seed_ids if seed in expected)
        plan = {
            "facts_resolution_receipt_sha256": facts_resolution.receipt_sha256,
            "units": [unit.to_dict() for unit in units],
            "expected_owned_paths": list(expected_paths),
            "excluded_empty_paths": list(excluded_paths),
            "expected_seed_ids": list(expected),
        }
        semantic = {
            "facts_resolution_receipt_sha256": facts_resolution.receipt_sha256,
            "unit_count": len(units),
            "owned_path_count": len({path for unit in units for path in unit.owned_paths}),
            "expected_owned_paths": expected_paths,
            "unowned_paths": tuple(
                path for path in expected_paths if path not in owned_paths and path not in excluded_paths
            ),
            "excluded_empty_paths": excluded_paths,
            "expected_seed_ids": expected,
            "unowned_seed_ids": tuple(seed for seed in expected if owners[seed] == 0),
            "multi_unit_seed_ids": tuple(seed for seed in expected if owners[seed] > 1),
            "overlapping_source_chars": _overlapping_source_chars(units),
            "over_target_unit_count": sum(bool(unit.over_target_reasons) for unit in units),
            "units": units,
            "plan_sha256": _sha256(plan),
        }
        return cls(**semantic, receipt_sha256=_sha256(_semantic_data(semantic)))

    def plan_dict(self) -> dict[str, object]:
        """Return the worklist fields covered by the plan hash."""
        return {
            "facts_resolution_receipt_sha256": self.facts_resolution_receipt_sha256,
            "units": [unit.to_dict() for unit in self.units],
            "expected_owned_paths": list(self.expected_owned_paths),
            "excluded_empty_paths": list(self.excluded_empty_paths),
            "expected_seed_ids": list(self.expected_seed_ids),
        }

    def semantic_dict(self) -> dict[str, object]:
        """Return every receipt field covered by the receipt hash."""
        return _semantic_data(
            {
                "facts_resolution_receipt_sha256": self.facts_resolution_receipt_sha256,
                "unit_count": self.unit_count,
                "owned_path_count": self.owned_path_count,
                "expected_owned_paths": self.expected_owned_paths,
                "unowned_paths": self.unowned_paths,
                "excluded_empty_paths": self.excluded_empty_paths,
                "expected_seed_ids": self.expected_seed_ids,
                "unowned_seed_ids": self.unowned_seed_ids,
                "multi_unit_seed_ids": self.multi_unit_seed_ids,
                "overlapping_source_chars": self.overlapping_source_chars,
                "over_target_unit_count": self.over_target_unit_count,
                "units": self.units,
                "plan_sha256": self.plan_sha256,
            }
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict unit plan artifact."""
        return {"schema": UNIT_PLAN_SCHEMA, **self.semantic_dict(), "receipt_sha256": self.receipt_sha256}

    @classmethod
    def from_dict(cls, value: object) -> UnitPlanReceipt:
        """Load and verify one strict unit plan artifact."""
        fields = {
            "schema",
            "facts_resolution_receipt_sha256",
            "unit_count",
            "owned_path_count",
            "expected_owned_paths",
            "unowned_paths",
            "excluded_empty_paths",
            "expected_seed_ids",
            "unowned_seed_ids",
            "multi_unit_seed_ids",
            "overlapping_source_chars",
            "over_target_unit_count",
            "units",
            "plan_sha256",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields or value["schema"] != UNIT_PLAN_SCHEMA:
            raise ValueError("unit plan artifact has an unsupported or nonexact schema")
        for field in (
            "expected_owned_paths",
            "unowned_paths",
            "excluded_empty_paths",
            "expected_seed_ids",
            "unowned_seed_ids",
            "multi_unit_seed_ids",
            "units",
        ):
            if not isinstance(value[field], list):
                raise ValueError(f"unit plan {field} must be a list")
        return cls(
            facts_resolution_receipt_sha256=value["facts_resolution_receipt_sha256"],
            unit_count=value["unit_count"],
            owned_path_count=value["owned_path_count"],
            expected_owned_paths=tuple(value["expected_owned_paths"]),
            unowned_paths=tuple(value["unowned_paths"]),
            excluded_empty_paths=tuple(value["excluded_empty_paths"]),
            expected_seed_ids=tuple(value["expected_seed_ids"]),
            unowned_seed_ids=tuple(value["unowned_seed_ids"]),
            multi_unit_seed_ids=tuple(value["multi_unit_seed_ids"]),
            overlapping_source_chars=value["overlapping_source_chars"],
            over_target_unit_count=value["over_target_unit_count"],
            units=tuple(UnitPlanRecord.from_dict(item) for item in value["units"]),
            plan_sha256=value["plan_sha256"],
            receipt_sha256=value["receipt_sha256"],
        )


def _semantic_data(values: dict[str, object]) -> dict[str, object]:
    def json_value(value: object) -> object:
        if isinstance(value, tuple):
            return [json_value(item) for item in value]
        if isinstance(value, UnitPlanRecord | UnitSourceSlice):
            return value.to_dict()
        return value

    return {key: json_value(value) for key, value in values.items()}


__all__ = ["UnitPlanReceipt", "UnitPlanRecord", "UnitSourceSlice"]
