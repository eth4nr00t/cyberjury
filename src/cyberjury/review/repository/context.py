"""Assemble source and facts context for repository review units."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.review.context import (
    GroundingContext,
    definition_plan_source_files,
    numbered_source_range,
    publish_evidence,
    syntax_hints,
    with_scoped_fact_limitations,
)
from cyberjury.review.paths import safe_repository_path
from cyberjury.review.prepare import SharedGrounding
from cyberjury.review.prompts import fenced_source
from cyberjury.review.repository.model import RepositoryUnit
from cyberjury.review.seed_sources import candidate_call_context
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_SETTINGS = DEFAULT_REVIEW_SETTINGS.repository
_EXECUTION = DEFAULT_REVIEW_SETTINGS.execution


class UnitSourceError(RuntimeError):
    """A unit source file could not be read, so the unit review must fail loud."""


def _read_unit_text(unit: RepositoryUnit, rel: str) -> str:
    path = safe_repository_path(unit.root, rel)
    if path is None:
        raise UnitSourceError(f"unit {unit.name} references unsafe source path {rel!r}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UnitSourceError(f"unit {unit.name} could not read source file {rel}: {exc}") from exc


def gather_context(unit: RepositoryUnit) -> GroundingContext:
    """Number the unit's source file, or its planned span, at its original line numbers."""
    rel = unit.file
    text = _read_unit_text(unit, rel)
    start, end = unit.span or (0, len(text))
    if end > len(text):
        raise UnitSourceError(f"unit {unit.name} span exceeds source file {rel}")
    numbered, span = numbered_source_range(rel, text, start, end)
    return GroundingContext(
        text="",
        seed=f"Code under review, cited as `seed`:\n{fenced_source(numbered)}",
        files=(rel,),
        source_spans=(span,),
    )


def ground_repository_unit(unit: RepositoryUnit, shared: SharedGrounding) -> GroundingContext:
    """Bind one planned unit to its complete initial evidence envelope."""
    context = gather_context(unit)
    navigator = shared.navigator
    source_files = tuple(dict.fromkeys((*context.files, *definition_plan_source_files(unit.definition_plan))))
    candidate = (
        candidate_call_context(
            unit.root,
            unit.definition_plan,
            navigator.relationship_evidence,
            max_chars=_SETTINGS.max_relationship_chars_per_unit,
            deliver_chars=_EXECUTION.max_initial_candidate_source_chars,
        )
        if navigator is not None
        else None
    )
    if candidate is not None and candidate.text:
        context = replace(
            context,
            text=candidate.text,
            evidence=publish_evidence(context.evidence, candidate.published),
            source_evidence=candidate.delivered,
        )
        source_files = tuple(dict.fromkeys((*source_files, *candidate.source_files)))
    context = with_scoped_fact_limitations(context, shared.facts.limitations, source_files=source_files)
    return replace(
        context,
        syntax_hints=syntax_hints(
            unit.definition_plan,
            context.files,
            shared.facts.by_file,
            max_chars_per_file=_EXECUTION.max_syntax_hint_chars_per_file,
        ),
        navigator=navigator,
        source_snapshot=shared.snapshot,
        snapshot_files=source_files,
    )
