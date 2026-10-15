"""Assemble source and facts context for repository review units.

`Unit` is the worklist item the reviewer processes. Context assembly preserves source
locations and fails on corrupt facts artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cyberjury.numbering import numbered_source
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceSpan,
    candidate_call_context,
    definition_plan_source_files,
    publish_candidate_evidence,
    with_scoped_fact_limitations,
)
from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.facts import BackendUnavailable, FactLimitation, normalize_fact_limitations
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.relationships import RelationshipEvidenceBundle, relationship_evidence_from_data
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

if TYPE_CHECKING:
    from cyberjury.review.navigation import SourceNavigator
    from cyberjury.sources.snapshot import SourceSnapshot

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository


@dataclass(frozen=True, kw_only=True)
class Unit:
    """One unit of the worklist: one source file, or one char span of it.

    `span`, when set, is the char window of the file this unit reviews, so a file too large
    for one call is split across sibling units instead of being silently truncated.
    """

    name: str
    root: str
    files: tuple[str, ...]
    id: str = ""
    owned_paths: tuple[str, ...] = ()
    span: tuple[int, int] | None = None
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


def gather_context(unit: Unit) -> GroundingContext:
    """Number the unit's source file, or its planned span, at its original line numbers."""
    rel = unit.files[0]
    text = _read_unit_text(unit, rel)
    first = 1
    if unit.span is not None:
        start, end = unit.span
        if end > len(text):
            raise UnitSourceError(f"unit {unit.name} span exceeds source file {rel}")
        first, text = text[:start].count("\n") + 1, text[start:end]
    return GroundingContext(
        text=numbered_source(rel, text, first),
        files=(rel,),
        source="repository",
        coverage=GroundingCoverage(required=(rel,), included=(rel,)),
        source_spans=(_source_span(rel, text, first),),
    )


def facts_for_unit(unit: Unit, facts_by_file: dict[str, str]) -> str:
    """Select complete facts only by exact repository path."""
    blocks: list[str] = []
    for rel in unit.files:
        block = facts_by_file.get(rel)
        if not block:
            continue
        blocks.append(block)
    return "\n".join(blocks)


def ground_unit(
    unit: Unit,
    *,
    facts_by_file: dict[str, str],
    limitations: tuple[FactLimitation, ...],
    navigator: SourceNavigator | None,
    source_snapshot: SourceSnapshot,
) -> Unit:
    """Bind one planned unit to its complete initial evidence envelope."""
    context = gather_context(unit)
    source_files = tuple(dict.fromkeys((*context.files, *definition_plan_source_files(unit.definition_plan))))
    candidate = (
        candidate_call_context(
            unit.root,
            unit.definition_plan,
            navigator.relationship_evidence,
            max_chars=_SETTINGS.max_relationship_chars_per_unit,
        )
        if navigator is not None
        else None
    )
    if candidate is not None and candidate.text:
        context = replace(
            context,
            text="\n\n".join((candidate.text, context.text)),
            evidence=publish_candidate_evidence(context.evidence, candidate.source_evidence),
        )
        source_files = tuple(
            dict.fromkeys(
                (
                    *source_files,
                    *(item.source_span.file for item in candidate.source_evidence if item.source_span is not None),
                )
            )
        )
    context = with_scoped_fact_limitations(context, limitations, source_files=source_files)
    context = replace(
        context,
        facts=facts_for_unit(unit, facts_by_file),
        navigator=navigator,
        source_snapshot=source_snapshot,
        snapshot_files=source_files,
    )
    return replace(unit, grounding=context)


def ground_units(
    units: tuple[Unit, ...],
    *,
    facts_by_file: dict[str, str],
    limitations: tuple[FactLimitation, ...],
    navigator: SourceNavigator | None,
    source_snapshot: SourceSnapshot,
) -> tuple[Unit, ...]:
    """Ground every planned unit in its stable worklist order."""
    if not source_snapshot.matches():
        raise UnitSourceError("repository source changed before initial grounding")
    grounded = tuple(
        ground_unit(
            unit,
            facts_by_file=facts_by_file,
            limitations=limitations,
            navigator=navigator,
            source_snapshot=source_snapshot,
        )
        for unit in units
    )
    if not source_snapshot.matches():
        raise UnitSourceError("repository source changed during initial grounding")
    return grounded


def facts_summary(workspace: Path) -> str:
    """Return bounded global facts for units that no per-file facts map can ground."""
    path = workspace / "_facts.md"
    if not path.is_file():
        return ""
    facts = path.read_text(encoding="utf-8").strip()
    if not facts:
        return ""
    if len(facts) > _SETTINGS.max_facts_chars_per_unit:
        facts = facts[: _SETTINGS.max_facts_chars_per_unit] + "\n... [facts truncated, see _facts.md]"
    return f"Syntax hints for the repository (unverified; cite only delivered source):\n{facts}\n"


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


def load_facts_graph(workspace: Path) -> dict[str, object]:
    """Read the call and import graph used to expand repository units."""
    data = _load_facts(workspace, "_facts_graph.json", dict, {})
    return cast(dict[str, object], data)


def load_relationship_evidence(workspace: Path) -> RelationshipEvidenceBundle:
    """Read deterministic producer evidence used by model relationship resolution."""
    path = workspace / "_relationship_evidence.json"
    data = _load_facts(workspace, path.name, dict, {})
    if not data:
        return RelationshipEvidenceBundle()
    try:
        return relationship_evidence_from_data(data)
    except BackendUnavailable as exc:
        raise _facts_error(path, exc) from exc


def load_facts_limitations(workspace: Path) -> tuple[FactLimitation, ...]:
    """Read source limitations that keep structured grounding incomplete."""
    path = workspace / "_facts_limitations.json"
    data = _load_facts(workspace, path.name, list, [])
    try:
        return normalize_fact_limitations(data)
    except BackendUnavailable as exc:
        raise _facts_error(path, exc) from exc
