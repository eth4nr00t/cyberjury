"""Shared facts contracts and extraction semantics for review workflows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple, TypedDict, cast

from cyberjury.review.definitions import (
    DefinitionDependency,
    DefinitionFragment,
    DefinitionUnitPlan,
    FactsGraph,
    UnresolvedDependency,
    definition_dependencies,
    definition_fragments,
    definition_references,
    definition_union_size,
    dependencies_data,
    dependency_closure,
    dependency_paths,
    merge_definition_unit_plans,
    plan_definition_units,
    unresolved_dependencies,
    unresolved_dependencies_data,
)
from cyberjury.review.failures import BackendUnavailable

__all__ = [
    "BackendUnavailable",
    "DefinitionDependency",
    "DefinitionFragment",
    "DefinitionUnitPlan",
    "FactFragment",
    "FactUnitSpec",
    "Facts",
    "FactsBackend",
    "FactsByFile",
    "FactsGraph",
    "FactsPayload",
    "FactsRecord",
    "UnresolvedDependency",
    "definition_dependencies",
    "definition_fragments",
    "definition_references",
    "definition_union_size",
    "dependencies_data",
    "dependency_closure",
    "dependency_paths",
    "extract_facts",
    "fact_unit_specs",
    "merge_definition_unit_plans",
    "normalize_fact_unit_specs",
    "pack_unit_specs",
    "plan_definition_units",
    "unresolved_dependencies",
    "unresolved_dependencies_data",
]

type FactsRecord = dict[str, object]
type FactsByFile = dict[str, str]


class FactFragment(NamedTuple):
    """One source range selected by a facts backend."""

    file: str
    start: int
    end: int


class FactUnitSpec(TypedDict, total=False):
    """Focused source fragments emitted by a facts backend."""

    name: str
    files: list[str]
    fragments: list[FactFragment]


class FactsPayload(TypedDict, total=False):
    """Shared structured facts persisted beside prompt text."""

    by_file: FactsByFile
    graph: FactsGraph
    unit_specs: list[FactUnitSpec]


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic facts that ground one or more review contexts.

    ``summary`` is prompt-ready text. ``data`` is a structured payload with shared keys
    such as ``by_file``, ``graph``, and optional focused unit specifications. Domain
    backends may add fields, but extraction, persistence, and consumption remain review-owned.
    """

    summary: str = ""
    data: FactsPayload = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        """Report whether the backend produced no usable facts."""
        return not self.summary and not self.data


class FactsBackend(ABC):
    """Extract deterministic facts from a source tree for grounded review."""

    install_hint: str = "install the backend's toolchain to enable it"

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool is installed and can support grounded review."""

    @abstractmethod
    def extract(self, root: str | Path) -> Facts:
        """Extract facts from ``root`` or raise ``BackendUnavailable``."""


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
    if not backend.available():
        raise BackendUnavailable(
            f"the facts backend cannot run for {purpose}, so this review has no grounding. {backend.install_hint}"
        )
    try:
        facts = backend.extract(root)
    except BackendUnavailable:
        raise
    except Exception as exc:
        raise BackendUnavailable(
            f"facts extraction failed for {purpose}, so this review has no grounding: {exc}"
        ) from exc
    if not isinstance(facts, Facts):
        raise BackendUnavailable(f"facts backend returned an invalid result for {purpose}")
    return facts


def fact_unit_specs(facts: Facts) -> list[FactUnitSpec]:
    """Return backend-provided focused unit specifications in one shared shape."""
    data = facts.data if isinstance(facts.data, dict) else {}
    return normalize_fact_unit_specs(data.get("unit_specs", []))


def normalize_fact_unit_specs(specs: object) -> list[FactUnitSpec]:
    """Validate and name the focused unit records at a facts boundary."""
    if not isinstance(specs, list):
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
            if not isinstance(files, list) or not all(isinstance(file, str) for file in files):
                raise BackendUnavailable(f"focused unit specification {index} files must be a list of strings")
            item["files"] = files
        if "fragments" in spec:
            fragments = spec["fragments"]
            if not isinstance(fragments, list):
                raise BackendUnavailable(f"focused unit specification {index} fragments must be a list")
            item["fragments"] = [
                _fact_fragment(fragment, unit_index=index, fragment_index=fragment_index)
                for fragment_index, fragment in enumerate(fragments)
            ]
        normalized.append(item)
    return normalized


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


def pack_unit_specs(
    records: dict[str, FactsRecord],
    *,
    focus_flags: tuple[str, ...],
    max_source_chars: int,
) -> list[FactUnitSpec]:
    """Pack flagged function records into bounded, generic unit specifications."""
    raw: list[tuple[frozenset[str], FactUnitSpec]] = []
    for owner, record in records.items():
        file = record.get("file") or ""
        if not file:
            continue
        functions = cast("dict[str, FactsRecord]", record.get("functions") or {})
        callers = _fact_callers(functions)
        for function, info in functions.items():
            if not any(info.get(flag) for flag in focus_flags):
                continue
            picked = _pick_fact_neighbors(function, info, functions, callers, max_source_chars)
            if not picked:
                continue
            fragments = sorted(
                (
                    FactFragment(str(file), span[0], span[1])
                    for name in picked
                    if (span := _fact_range(functions[name])) is not None
                ),
                key=lambda fragment: fragment.start,
            )
            spec: FactUnitSpec = {
                "name": f"{file}#{owner}.{_fact_short(function)}",
                "files": [file],
                "fragments": fragments,
            }
            raw.append((frozenset(picked), spec))
    raw.sort(key=lambda item: len(item[0]), reverse=True)
    kept: list[FactUnitSpec] = []
    kept_sets: list[frozenset[str]] = []
    for names, spec in raw:
        if any(names <= prior for prior in kept_sets):
            continue
        kept_sets.append(names)
        kept.append(spec)
    return kept


def _fact_callers(functions: dict[str, FactsRecord]) -> dict[str, list[str]]:
    callers: dict[str, list[str]] = {}
    for function, info in functions.items():
        for callee in info.get("calls") or ():
            callers.setdefault(str(callee), []).append(function)
    return callers


def _pick_fact_neighbors(
    function: str,
    info: FactsRecord,
    functions: dict[str, FactsRecord],
    callers: dict[str, list[str]],
    max_source_chars: int,
) -> list[str]:
    if _fact_range(info) is None:
        return []
    ordered = [function]
    ordered.extend(str(callee) for callee in info.get("calls") or () if callee in functions and callee not in ordered)
    ordered.extend(caller for caller in callers.get(function, ()) if caller in functions and caller not in ordered)
    picked: list[str] = []
    total = 0
    for name in ordered:
        span = _fact_range(functions[name])
        if span is None:
            continue
        size = span[1] - span[0]
        if picked and total + size > max_source_chars:
            continue
        picked.append(name)
        total += size
    return picked


def _fact_range(info: FactsRecord) -> list[int] | None:
    value = info.get("range")
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise BackendUnavailable("facts backend returned a malformed function range")
    start, end = value
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
        or start < 0
        or end <= start
    ):
        raise BackendUnavailable("facts backend returned a malformed function range")
    return [start, end]


def _fact_short(name: str) -> str:
    return name.split("(", 1)[0]
