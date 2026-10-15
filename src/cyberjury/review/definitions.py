"""Validate definition graphs and plan seed definition review units."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.canonical import normalized_repository_path
from cyberjury.review.failures import BackendUnavailable

type FactsGraph = dict[str, object]


@dataclass(frozen=True, order=True)
class DefinitionFragment:
    """One complete source definition exposed through the shared facts graph."""

    file: str
    name: str
    start: int
    end: int

    def __post_init__(self) -> None:
        """Reject unsafe paths, empty names, and invalid character ranges."""
        normalized_repository_path(self.file, "definition source path")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("definition fragment name must not be empty")
        if (
            isinstance(self.start, bool)
            or not isinstance(self.start, int)
            or isinstance(self.end, bool)
            or not isinstance(self.end, int)
            or self.start < 0
            or self.end <= self.start
        ):
            raise ValueError("definition fragment must have a valid character range")

    @property
    def identity(self) -> str:
        """Identify the exact source range required by a grounded judgment."""
        return f"{self.file}:{self.name}:{self.start}:{self.end}"


@dataclass(frozen=True, kw_only=True)
class DefinitionUnitPlan:
    """One review surface with its seed definitions and bounded source evidence."""

    seeds: tuple[DefinitionFragment, ...] = ()
    seed_files: tuple[str, ...] = ()
    evidence: tuple[DefinitionFragment, ...] = ()

    def __post_init__(self) -> None:
        """Reject duplicate or noncanonical worklist inputs."""
        for file in self.seed_files:
            normalized_repository_path(file, "definition source path")
        for label, values in (
            ("seed", self.seeds),
            ("seed file", self.seed_files),
            ("evidence", self.evidence),
        ):
            if not isinstance(values, tuple) or len(values) != len(set(values)):
                raise ValueError(f"definition unit plan {label} values must be a unique tuple")

    @property
    def fragments(self) -> tuple[DefinitionFragment, ...]:
        """Return the bounded source evidence selected for this surface."""
        return self.evidence


def definition_fragments(graph: FactsGraph) -> dict[str, tuple[DefinitionFragment, ...]]:
    """Index every definition range or reject an incomplete nonempty graph."""
    callgraph = graph.get("callgraph")
    if callgraph is None:
        return {}
    if not isinstance(callgraph, dict):
        raise BackendUnavailable("the facts graph callgraph must be an object")
    index: dict[str, list[DefinitionFragment]] = {}
    for raw_file, raw_definitions in callgraph.items():
        if not isinstance(raw_file, str) or not raw_file:
            raise BackendUnavailable("the facts graph contains a definition with an invalid file")
        for fragment in _validated_definition_entries(raw_file, raw_definitions):
            index.setdefault(fragment.name, []).append(fragment)
    return {name: tuple(dict.fromkeys(fragments)) for name, fragments in index.items()}


def _validated_definition_entries(file: str, raw_definitions: object) -> tuple[DefinitionFragment, ...]:
    if not isinstance(raw_definitions, dict):
        raise BackendUnavailable(f"the facts graph definitions for {file} must be an object")
    fragments: list[DefinitionFragment] = []
    for raw_name, raw_entries in raw_definitions.items():
        if not isinstance(raw_name, str) or not raw_name:
            raise BackendUnavailable(f"the facts graph contains a definition with an invalid name in {file}")
        location = f"{file}:{raw_name}"
        if not isinstance(raw_entries, list | tuple) or not raw_entries:
            raise BackendUnavailable(f"the facts graph definition entries for {location} must be a nonempty list")
        for position, raw_entry in enumerate(raw_entries):
            entry_location = f"{location} entry {position + 1}"
            fragment = _validated_definition_fragment(file, raw_name, raw_entry, entry_location)
            raw_calls = raw_entry.get("calls")
            if raw_calls is not None and (
                not isinstance(raw_calls, list | tuple) or not all(isinstance(call, str) and call for call in raw_calls)
            ):
                raise BackendUnavailable(f"the facts graph definition {entry_location} has invalid calls")
            fragments.append(fragment)
    return tuple(fragments)


def _validated_definition_fragment(file: str, name: str, raw_entry: object, location: str) -> DefinitionFragment:
    if not isinstance(raw_entry, dict):
        raise BackendUnavailable(f"the facts graph definition {location} must be an object")
    span = raw_entry.get("range")
    if not isinstance(span, list | tuple) or len(span) != 2:
        raise BackendUnavailable(f"the facts graph definition {location} has an invalid range")
    start, end = span
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end <= start
    ):
        raise BackendUnavailable(f"the facts graph definition {location} has an invalid range")
    try:
        return DefinitionFragment(file, name, start, end)
    except ValueError as exc:
        raise BackendUnavailable(f"the facts graph definition {location} is invalid: {exc}") from exc


def plan_definition_units(
    seeds: tuple[DefinitionFragment, ...],
    *,
    seed_files: tuple[str, ...] = (),
) -> tuple[DefinitionUnitPlan, ...]:
    """Build one plan per seed file, in seed order, holding that file's seed definitions."""
    plans = []
    for anchor in dict.fromkeys(seed.file for seed in seeds):
        anchor_seeds = tuple(seed for seed in seeds if seed.file == anchor)
        plans.append(
            DefinitionUnitPlan(
                seeds=anchor_seeds,
                seed_files=(anchor,) if anchor in seed_files else (),
                evidence=anchor_seeds,
            )
        )
    return tuple(plans)


def merge_definition_unit_plans(
    left: DefinitionUnitPlan,
    right: DefinitionUnitPlan,
) -> DefinitionUnitPlan:
    """Merge independent review surfaces without losing seed or receipt identity."""
    return DefinitionUnitPlan(
        seeds=tuple(dict.fromkeys((*left.seeds, *right.seeds))),
        seed_files=tuple(dict.fromkeys((*left.seed_files, *right.seed_files))),
        evidence=tuple(dict.fromkeys((*left.evidence, *right.evidence))),
    )


def definition_union_size(fragments: tuple[DefinitionFragment, ...]) -> int:
    """Count overlapping source definitions once when enforcing a unit budget."""
    total = 0
    by_file: dict[str, list[tuple[int, int]]] = {}
    for fragment in fragments:
        by_file.setdefault(fragment.file, []).append((fragment.start, fragment.end))
    for ranges in by_file.values():
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
