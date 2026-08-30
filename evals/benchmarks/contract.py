"""Versioned benchmark and answer key contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

TASK_REVIEW_MODES = frozenset({"standard", "adversarial"})


@dataclass(frozen=True, kw_only=True)
class RepositoryCase:
    """One repository benchmark case materialized from a project task."""

    id: str
    kind: str
    answer_key: Path
    provenance: str
    manifest: Path | None = None
    target: dict[str, object] = field(default_factory=dict)
    stack: dict[str, list[str]] = field(default_factory=dict)
    knowledge: dict[str, list[str]] = field(default_factory=dict)
    project_id: str = ""
    task_id: str = ""
    profile: str = "web"


@dataclass(frozen=True, kw_only=True)
class BenchmarkProject:
    """One validated project manifest discovered from a benchmark source."""

    id: str
    manifest: Path
    provenance: str


def knowledge_refs(block: Mapping[str, object] | None) -> tuple[str, ...]:
    """Flatten a versioned knowledge block into coverage references."""
    block = block or {}
    refs = [f"vuln:{value}" for value in block.get("vulnerabilities") or []]
    refs += [f"guide:{value}" for value in block.get("guides") or []]
    return tuple(refs)


@dataclass(frozen=True, kw_only=True)
class ExpectedLocation:
    """One accepted source location for a benchmark report."""

    file: str
    line: int | None = None
    symbol: str = ""

    def __post_init__(self) -> None:
        """Keep the Python contract as strict as the answer key schema."""
        has_line = self.line is not None
        has_symbol = bool(self.symbol)
        if has_line == has_symbol:
            raise ValueError("expected location requires exactly one line or symbol")
        if self.line is not None and (isinstance(self.line, bool) or self.line < 1):
            raise ValueError("expected location line must be a positive integer")
        if has_symbol:
            object.__setattr__(self, "symbol", self.symbol.casefold())


@dataclass(frozen=True, kw_only=True)
class ExpectedChange:
    """One exact changed line that establishes a diff check identity."""

    file: str
    line: int
    side: Literal["old", "new"]


@dataclass(frozen=True, kw_only=True)
class KeyCheck:
    """One expected finding or clean check from an answer key."""

    id: str
    expectation: str
    applies_to: tuple[str, ...] = ()
    severity: str = ""
    locations: tuple[ExpectedLocation, ...] = ()
    changes: tuple[ExpectedChange, ...] = ()
    # Existing object form checks populate these grouped fields.
    files: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    knowledge: tuple[str, ...] = ()
    change_anchors: tuple[ExpectedChange, ...] = ()

    @property
    def category(self) -> str:
        """Return the vulnerability class declared by the answer key."""
        return next((ref.removeprefix("vuln:") for ref in self.knowledge if ref.startswith("vuln:")), "")

    @property
    def accepted_files(self) -> tuple[str, ...]:
        """Return every accepted file once across either input format."""
        if self.locations:
            return tuple(dict.fromkeys(location.file for location in self.locations))
        return self.files

    @property
    def expected_changes(self) -> tuple[ExpectedChange, ...]:
        """Return the task changes across either input format."""
        return self.changes or self.change_anchors


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    """All ground truth checks for one benchmark."""

    benchmark_id: str
    checks: tuple[KeyCheck, ...]

    @property
    def findings(self) -> tuple[KeyCheck, ...]:
        """Return checks that expect findings."""
        return tuple(check for check in self.checks if check.expectation == "findings")

    @property
    def clean(self) -> tuple[KeyCheck, ...]:
        """Return checks that expect a clean result."""
        return tuple(check for check in self.checks if check.expectation == "clean")


def _string_tuple(block: Mapping[str, object], key: str) -> tuple[str, ...]:
    return tuple(str(value) for value in cast(Sequence[object], block.get(key, ())))


def _changes(row: Mapping[str, object], key: str) -> tuple[ExpectedChange, ...]:
    changes = cast(Sequence[Mapping[str, object]], row.get(key, ()))
    return tuple(
        ExpectedChange(
            file=str(change["file"]),
            line=int(change["line"]),
            side=cast(Literal["old", "new"], change["side"]),
        )
        for change in changes
    )


def _locations(row: Mapping[str, object]) -> tuple[ExpectedLocation, ...]:
    locations = cast(Sequence[Mapping[str, object]], row["locations"])
    return tuple(
        ExpectedLocation(
            file=str(location["file"]),
            line=cast(int | None, location.get("line")),
            symbol=str(location.get("symbol") or ""),
        )
        for location in locations
    )


def _key_checks(rows: Sequence[object]) -> tuple[KeyCheck, ...]:
    """Construct checks after the JSON Schema has established their shape."""
    checks: list[KeyCheck] = []
    for raw_row in rows:
        row = cast(Mapping[str, object], raw_row)
        raw_locations = row["locations"]
        structured = isinstance(raw_locations, Sequence) and not isinstance(raw_locations, (str, bytes))
        grouped = cast(Mapping[str, object], raw_locations) if not structured else {}
        checks.append(
            KeyCheck(
                id=str(row["id"]),
                expectation=str(row["expectation"]),
                applies_to=_string_tuple(row, "applies_to"),
                severity=str(row.get("severity") or ""),
                locations=_locations(row) if structured else (),
                changes=_changes(row, "changes"),
                files=_string_tuple(grouped, "files"),
                endpoints=_string_tuple(grouped, "endpoints"),
                symbols=tuple(symbol.lower() for symbol in _string_tuple(grouped, "symbols")),
                knowledge=knowledge_refs(cast(Mapping[str, object], row["knowledge"])),
                change_anchors=_changes(row, "change_anchors"),
            )
        )
    return tuple(checks)


def load_answer_key(path: str | Path, *, task_id: str | None = None) -> AnswerKey:
    """Load the versioned answer key and fail loud on malformed data."""
    from evals.benchmarks.validate import load_validated_document

    answer_key_path = Path(path)
    data = load_validated_document(answer_key_path)
    checks = cast(Sequence[object], data["checks"])
    key = AnswerKey(benchmark_id=str(data["benchmark_id"]), checks=_key_checks(checks))
    _validate_disjoint_check_scopes(key.checks)
    if task_id is None:
        return key
    return filter_answer_key(key, task_id)


def filter_answer_key(key: AnswerKey, task_id: str) -> AnswerKey:
    """Keep checks explicitly scoped to one task."""
    filtered = AnswerKey(
        benchmark_id=key.benchmark_id,
        checks=tuple(check for check in key.checks if task_id in check.applies_to),
    )
    _validate_unique_check_ids(filtered.checks, task_id)
    return filtered


def _validate_disjoint_check_scopes(checks: tuple[KeyCheck, ...]) -> None:
    """Allow a check id to move only across disjoint task scopes."""
    checks_by_id: dict[str, list[KeyCheck]] = {}
    for check in checks:
        for prior in checks_by_id.setdefault(check.id, []):
            if set(prior.applies_to).intersection(check.applies_to):
                raise ValueError(f"duplicate check id {check.id!r} has overlapping task scopes")
        checks_by_id[check.id].append(check)


def _validate_unique_check_ids(checks: tuple[KeyCheck, ...], task_id: str) -> None:
    seen: set[str] = set()
    for check in checks:
        if check.id in seen:
            raise ValueError(f"duplicate check id {check.id!r} applies to task {task_id!r}")
        seen.add(check.id)
