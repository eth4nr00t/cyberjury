"""Runtime models for reports and the versioned benchmark contracts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.scorers.match import category_of, normalize_endpoint

SCHEMA_VERSION = 1


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it."""

    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()
    text: str = ""
    lines: tuple[int, ...] = ()

    @classmethod
    def make(
        cls,
        name: str,
        endpoint: str,
        category: str,
        files: Sequence[str],
        text: str = "",
        lines: Sequence[int] = (),
    ) -> Report:
        """Build a normalized report."""
        return cls(
            name=name,
            endpoint=normalize_endpoint(endpoint),
            category=category_of(category),
            files=tuple(files),
            text=text.lower(),
            lines=tuple(sorted({int(n) for n in lines})),
        )


def knowledge_refs(block: Mapping[str, object] | None) -> tuple[str, ...]:
    """Flatten a versioned knowledge block into coverage references."""
    block = block or {}
    refs = [f"vuln:{v}" for v in block.get("vulnerabilities") or []]
    refs += [f"guide:{g}" for g in block.get("guides") or []]
    return tuple(refs)


def require_schema_version(data: Mapping[str, object], path: str | Path, kind: str) -> None:
    """Require an explicit schema version before reading benchmark data."""
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{kind} {path} has schema_version {data.get('schema_version')!r}, expected {SCHEMA_VERSION}")


@dataclass(frozen=True, kw_only=True)
class KeyCheck:
    """One expected finding or clean check from an answer key."""

    id: str
    expectation: str
    applies_to: tuple[str, ...] = ()
    severity: str = ""
    files: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    knowledge: tuple[str, ...] = ()

    @property
    def category(self) -> str:
        """Return the normalized vulnerability class used by the scorer."""
        value = next((ref.removeprefix("vuln:") for ref in self.knowledge if ref.startswith("vuln:")), "")
        return category_of(value)

    @property
    def endpoint(self) -> str:
        """Return the first endpoint as the scorer's strong anchor."""
        return self.endpoints[0] if self.endpoints else ""


@dataclass(frozen=True, kw_only=True)
class AnswerKey:
    """All ground-truth checks for one benchmark."""

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


def _list_field(row: Mapping[str, object], key: str, where: str) -> tuple[str, ...]:
    raw = row.get(key)
    if raw is None:
        return ()
    if isinstance(raw, str) or not isinstance(raw, list):
        raise ValueError(f"{where}.{key} is not a list")
    return tuple(str(value) for value in raw)


def _locations(row: Mapping[str, object], where: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    locations = row.get("locations")
    if not isinstance(locations, dict):
        raise ValueError(f"{where}.locations is not a mapping")
    values = (
        _list_field(locations, "files", f"{where}.locations"),
        _list_field(locations, "endpoints", f"{where}.locations"),
        tuple(symbol.lower() for symbol in _list_field(locations, "symbols", f"{where}.locations")),
    )
    if not values[0]:
        raise ValueError(f"{where}.locations has no matching anchor files")
    return values


def _key_checks(rows: Sequence[object], *, where: str) -> tuple[KeyCheck, ...]:
    out: list[KeyCheck] = []
    for i, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"{where}[{i}] is not a mapping")
        check_where = f"{where}[{i}]"
        check_id = row.get("id")
        if not isinstance(check_id, str) or not check_id:
            raise ValueError(f"{check_where}.id is required")
        expectation = row.get("expectation")
        if expectation not in {"findings", "clean"}:
            raise ValueError(f"{check_where}.expectation must be findings or clean")
        severity = row.get("severity")
        if expectation == "findings" and severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise ValueError(f"{check_where}.severity is required for findings checks")
        if expectation == "clean" and "severity" in row:
            raise ValueError(f"{check_where}.severity is forbidden for clean checks")
        files, endpoints, symbols = _locations(row, check_where)
        applies_to = _list_field(row, "applies_to", check_where)
        knowledge = knowledge_refs(row.get("knowledge"))
        out.append(
            KeyCheck(
                id=check_id,
                expectation=expectation,
                applies_to=applies_to,
                severity=severity or "",
                files=files,
                endpoints=tuple(normalize_endpoint(value) for value in endpoints),
                symbols=symbols,
                knowledge=knowledge,
            )
        )
    return tuple(out)


def load_answer_key(path: str | Path, *, task_id: str | None = None) -> AnswerKey:
    """Load the versioned answer key and fail loud on malformed data."""
    answer_key_path = Path(path)
    data = yaml.safe_load(answer_key_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key {path} is not a mapping")
    require_schema_version(data, path, "answer key")
    if any(field in data for field in ("target", "planted", "safe", "issues", "entries")):
        raise ValueError(f"answer key {path} uses the pre-version-1 answer-key fields")
    if not isinstance(data.get("benchmark_id"), str) or not data["benchmark_id"]:
        raise ValueError(f"answer key {path} has no benchmark_id")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError(f"answer key {path} has no checks list")
    key = AnswerKey(benchmark_id=data["benchmark_id"], checks=_key_checks(checks, where="checks"))
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
    by_id: dict[str, list[KeyCheck]] = {}
    for check in checks:
        for prior in by_id.setdefault(check.id, []):
            if set(prior.applies_to).intersection(check.applies_to):
                raise ValueError(f"duplicate check id {check.id!r} has overlapping task scopes")
        by_id[check.id].append(check)


def _validate_unique_check_ids(checks: tuple[KeyCheck, ...], task_id: str) -> None:
    seen: set[str] = set()
    for check in checks:
        if check.id in seen:
            raise ValueError(f"duplicate check id {check.id!r} applies to task {task_id!r}")
        seen.add(check.id)
