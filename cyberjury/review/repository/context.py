"""Assemble source and facts context for repository review units.

`Unit` is the worklist item the reviewer processes. Context assembly preserves source
locations, excludes untouched workspace templates, and fails on corrupt facts artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from cyberjury.numbering import numbered_source
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    RelationshipEvidence,
    SourceSpan,
    definition_evidence,
    render_relationships,
)
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import (
    BackendUnavailable,
    FactFragment,
    FactLimitation,
    FactUnitSpec,
    normalize_fact_limitations,
    normalize_fact_unit_specs,
)
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository

AUTH_MODEL_TEMPLATE = """\
# Authorization Model, Trust Boundaries, Sensitive Data

Built once in Phase 1, every unit refers to this instead of re-deriving it. See
"Phase 1: Map the Attack Surface" in methodology.md.

## Access control mechanism

## Actors and trust boundaries

## Sensitive data map

## Value map
"""


@dataclass(frozen=True, kw_only=True)
class Unit:
    """One unit of the worklist: the files it owns plus the files it traces into.

    `span`, when set, is the char window of the first owned file this unit reviews, so a
    file too large for one call is split across sibling units instead of being silently
    truncated. `fragments`, when set, are source slices this unit reviews instead of complete
    files, so a facts unit can co-locate a function and its extracted neighborhood rather
    than a char window. `files` still names the source files for facts grounding and
    coverage bookkeeping.
    """

    name: str
    root: str
    files: tuple[str, ...]
    span: tuple[int, int] | None = None
    fragments: tuple[FactFragment, ...] = ()
    fragment_identities: tuple[str, ...] = ()
    relationships: tuple[RelationshipEvidence, ...] = ()
    unresolved_identities: tuple[str, ...] = ()
    definition_plan: DefinitionUnitPlan | None = None
    grounding: GroundingContext | None = None


class UnitSourceError(RuntimeError):
    """A unit source file could not be read, so the unit review must fail loud."""


def _read_unit_text(unit: Unit, rel: str) -> str:
    path = safe_repository_path(unit.root, rel)
    if path is None:
        raise UnitSourceError(f"unit {unit.name} references unsafe source path {rel!r}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UnitSourceError(f"unit {unit.name} could not read source file {rel}: {exc}") from exc


def _source_span(rel: str, text: str, first_line: int) -> SourceSpan:
    return SourceSpan(
        file=rel,
        start_line=first_line,
        end_line=first_line + max(1, len(text.splitlines())) - 1,
    )


def _fragment_identity(fragment: FactFragment) -> str:
    rel, start, end = fragment
    return f"{rel}:{start}:{end}"


def _gather_fragments(unit: Unit) -> GroundingContext:
    """Assemble a facts unit from its source fragments.

    This packs the function bodies the packer co-located, so the model sees the path in
    one focused window.
    """
    parts: list[str] = []
    included: list[str] = []
    included_files: list[str] = []
    source_spans: list[SourceSpan] = []
    total = 0
    identities = unit.fragment_identities or tuple(_fragment_identity(fragment) for fragment in unit.fragments)
    rendered = [
        fragment
        for index, fragment in enumerate(unit.fragments)
        if not any(
            other_index != index
            and other[0] == fragment[0]
            and other[1] <= fragment[1]
            and other[2] >= fragment[2]
            and (other[1] < fragment[1] or other[2] > fragment[2] or other_index < index)
            for other_index, other in enumerate(unit.fragments)
        )
    ]
    rendered = list(dict.fromkeys(rendered))
    for fragment in rendered:
        rel, start, end = fragment
        text = _read_unit_text(unit, rel)
        if end > len(text):
            raise UnitSourceError(f"unit {unit.name} fragment exceeds source file {rel}")
        seg = text[start:end]
        first_line = text[:start].count("\n") + 1
        parts.append(numbered_source(rel, seg, first_line))
        source_spans.append(_source_span(rel, seg, first_line))
        included_files.append(rel)
        included.extend(
            identity
            for identity, candidate in zip(identities, unit.fragments, strict=True)
            if candidate[0] == rel and start <= candidate[1] and end >= candidate[2]
        )
        total += len(seg)
        if total >= _SETTINGS.target_gathered_source_chars_per_unit:
            break
    relationship_text = render_relationships(unit.relationships)
    if relationship_text:
        parts.insert(0, relationship_text)
    relationship_identities = tuple(relationship.identity for relationship in unit.relationships)
    required = (*identities, *relationship_identities)
    included.extend(relationship_identities)
    included_set = set(included)
    evidence = definition_evidence(unit.root, unit.definition_plan) if unit.definition_plan is not None else ()
    return GroundingContext(
        text="\n\n".join(parts),
        files=tuple(dict.fromkeys(included_files)),
        source="repository",
        coverage=GroundingCoverage(
            required=required,
            included=tuple(included),
            omitted=(*(identity for identity in required if identity not in included_set),),
            unresolved=unit.unresolved_identities,
        ),
        evidence=evidence,
        source_spans=tuple(source_spans),
    )


def gather_context(unit: Unit) -> GroundingContext:
    """Pack a unit and report whether its owned evidence fit.

    A single call can trace across them without live file access. The cap that stops
    packing counts source characters, so the returned block runs over it by the width of the
    line numbers.
    """
    if unit.grounding is not None:
        return unit.grounding
    if unit.fragments:
        return _gather_fragments(unit)
    parts: list[str] = []
    included: list[str] = []
    source_spans: list[SourceSpan] = []
    total = 0
    for i, rel in enumerate(unit.files):
        text = _read_unit_text(unit, rel)
        if i == 0 and unit.span is not None:
            start, end = unit.span
            if end > len(text):
                raise UnitSourceError(f"unit {unit.name} span exceeds source file {rel}")
            first, text = text[:start].count("\n") + 1, text[start:end]
        else:
            first, text = 1, text[: _SETTINGS.max_secondary_source_chars_per_file]
        parts.append(numbered_source(rel, text, first))
        source_spans.append(_source_span(rel, text, first))
        included.append(rel)
        total += len(text)
        if total >= _SETTINGS.target_gathered_source_chars_per_unit:
            break
    required = unit.files
    return GroundingContext(
        text="\n\n".join(parts),
        files=tuple(included),
        source="repository",
        coverage=GroundingCoverage(required=required, included=tuple(included)),
        source_spans=tuple(source_spans),
    )


def gather(unit: Unit) -> str:
    """Return the prompt text for a repository unit."""
    return gather_context(unit).text


def repository_context(workspace: Path) -> GroundingContext:
    """Exclude untouched inventory templates from the shared unit context."""
    parts: list[str] = []

    def add(label: str, rel: str, template: str | None = None) -> None:
        path = workspace / rel
        if not path.is_file():
            return
        text = path.read_text(encoding="utf-8").strip()
        if not text or (template is not None and text == template.strip()):
            return
        parts.append(f"## {label}\n{text}")

    add("Stack", "_stack.md")
    add(
        "Authorization model, trust boundaries, sensitive data",
        "inventory/_auth_model.md",
        AUTH_MODEL_TEMPLATE,
    )
    add("False-positive traps", "_false_positive_traps.md")
    return GroundingContext(text="\n\n".join(parts), source="repository")


def with_facts_summary(shared: GroundingContext | str, workspace: Path) -> GroundingContext | str:
    """Use bounded global facts only when no per-file map can ground each unit."""
    context = shared if isinstance(shared, GroundingContext) else None
    text = context.text if context is not None else shared
    path = workspace / "_facts.md"
    if not path.is_file():
        return shared
    facts = path.read_text(encoding="utf-8").strip()
    if not facts:
        return shared
    if len(facts) > _SETTINGS.max_facts_chars_per_unit:
        facts = facts[: _SETTINGS.max_facts_chars_per_unit] + "\n... [facts truncated, see _facts.md]"
    grounded = f"{text}\n\nTool-extracted facts:\n{facts}\n"
    return replace(context, text=grounded) if context is not None else grounded


def _facts_error(path: Path, exc: Exception) -> ValueError:
    return ValueError(f"facts artifact {path} is corrupt: {exc}. Delete it or remove the workspace to regenerate.")


def _load_facts[T](workspace: Path, name: str, expected: type[T], empty: T) -> T:
    path = workspace / name
    if not path.is_file():
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _facts_error(path, exc) from exc
    if not isinstance(data, expected):
        raise _facts_error(path, TypeError(f"expected {expected.__name__}"))
    return data


def load_facts_by_file(workspace: Path) -> dict[str, str]:
    """Read the per-file facts map used to ground individual units."""
    data = _load_facts(workspace, "_facts_by_file.json", dict, {})
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in data.items()):
        raise _facts_error(workspace / "_facts_by_file.json", TypeError("facts by file must map strings to strings"))
    return {key: value for key, value in data.items() if value}


def load_facts_unit_specs(workspace: Path) -> list[FactUnitSpec]:
    """Read focused unit specifications emitted by the facts backend."""
    path = workspace / "_facts_units.json"
    data = _load_facts(workspace, path.name, list, [])
    try:
        return normalize_fact_unit_specs(data)
    except BackendUnavailable as exc:
        raise _facts_error(path, exc) from exc


def load_facts_graph(workspace: Path) -> dict[str, object]:
    """Read the call and import graph used to expand repository units."""
    data = _load_facts(workspace, "_facts_graph.json", dict, {})
    return cast(dict[str, object], data)


def load_facts_limitations(workspace: Path) -> tuple[FactLimitation, ...]:
    """Read source limitations that keep structured grounding incomplete."""
    path = workspace / "_facts_limitations.json"
    data = _load_facts(workspace, path.name, list, [])
    try:
        return normalize_fact_limitations(data)
    except BackendUnavailable as exc:
        raise _facts_error(path, exc) from exc
