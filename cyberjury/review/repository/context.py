"""Assemble source and facts context for repository review units.

`Unit` is the worklist item the reviewer processes. Context assembly preserves source
locations, excludes untouched workspace templates, and fails on corrupt facts artifacts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cyberjury.numbering import numbered_source
from cyberjury.review.paths import safe_repository_path

_GATHER_PER_FILE = 24_000
_GATHER_TOTAL = 120_000
_FACTS_CONTEXT_CAP = 16_000

AUTH_MODEL_TEMPLATE = """\
# Authorization Model, Trust Boundaries, Sensitive Data

Built once in Phase 1, every unit refers to this instead of re-deriving it. See
"Phase 1: Map the Attack Surface" in METHODOLOGY.md.

## Access control mechanism

## Actors and trust boundaries

## Sensitive data map
"""


@dataclass(frozen=True, kw_only=True)
class Unit:
    """One unit of the worklist: the files it owns plus the files it traces into.

    `span`, when set, is the char window of the first owned file this unit reviews, so a
    file too large for one call is split across sibling units instead of being silently
    truncated. `fragments`, when set, are source slices this unit reviews instead of whole
    files, so a call-path unit co-locates a function and its call-graph neighborhood rather
    than a char window. `files` still names the source files for facts grounding and
    coverage bookkeeping.
    """

    name: str
    root: str
    files: tuple[str, ...]
    span: tuple[int, int] | None = None
    fragments: tuple[tuple[str, int, int], ...] = ()


class UnitSourceError(RuntimeError):
    """A unit source file could not be read, so the unit review must fail loud."""


def _first_line(text: str, start: int) -> int:
    return text[:start].count("\n") + 1


def _read_unit_text(unit: Unit, rel: str) -> str:
    path = safe_repository_path(unit.root, rel)
    if path is None:
        raise UnitSourceError(f"unit {unit.name} references unsafe source path {rel!r}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise UnitSourceError(f"unit {unit.name} could not read source file {rel}: {exc}") from exc


def _gather_fragments(unit: Unit) -> str:
    """Assemble a call-path unit from its source fragments.

    This packs the function bodies the packer co-located, so the model sees the path in
    one focused window.
    """
    parts: list[str] = []
    total = 0
    for rel, start, end in unit.fragments:
        text = _read_unit_text(unit, rel)
        seg = text[start:end]
        parts.append(numbered_source(rel, seg, _first_line(text, start)))
        total += len(seg)
        if total >= _GATHER_TOTAL:
            break
    return "\n\n".join(parts)


def gather(unit: Unit) -> str:
    """Pack the unit's files into one block.

    A single call can trace across them without live file access. The cap that stops
    packing counts source characters, so the returned block runs over it by the width of the
    line numbers.
    """
    if unit.fragments:
        return _gather_fragments(unit)
    parts: list[str] = []
    total = 0
    for i, rel in enumerate(unit.files):
        text = _read_unit_text(unit, rel)
        if i == 0 and unit.span is not None:
            start, end = unit.span
            first, text = _first_line(text, start), text[start:end]
        else:
            first, text = 1, text[:_GATHER_PER_FILE]
        parts.append(numbered_source(rel, text, first))
        total += len(text)
        if total >= _GATHER_TOTAL:
            break
    return "\n\n".join(parts)


def repository_context(workspace: Path) -> str:
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
    return "\n\n".join(parts)


def with_facts_summary(shared: str, workspace: Path) -> str:
    """Use bounded global facts only when no per-file map can ground each unit."""
    path = workspace / "_facts.md"
    if not path.is_file():
        return shared
    facts = path.read_text(encoding="utf-8").strip()
    if not facts:
        return shared
    if len(facts) > _FACTS_CONTEXT_CAP:
        facts = facts[:_FACTS_CONTEXT_CAP] + "\n... [facts truncated, see _facts.md]"
    return f"{shared}\n\nTool-extracted facts:\n{facts}\n"


def _facts_error(path: Path, exc: Exception) -> ValueError:
    return ValueError(f"facts artifact {path} is corrupt: {exc}. Delete it or remove the workspace to regenerate.")


def _load_facts(workspace: Path, name: str, expected: type, empty):
    path = workspace / name
    if not path.is_file():
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _facts_error(path, exc) from exc
    return data if isinstance(data, expected) else empty


def load_facts_by_file(workspace: Path) -> dict[str, str]:
    """Read the per-file facts map used to ground individual units."""
    data = _load_facts(workspace, "_facts_by_file.json", dict, {})
    return {str(key): str(value) for key, value in data.items() if value}


def load_facts_units(workspace: Path) -> list:
    """Read focused call path units emitted by the facts backend."""
    return _load_facts(workspace, "_facts_units.json", list, [])


def load_facts_graph(workspace: Path) -> dict:
    """Read the call and import graph used to expand repository units."""
    return _load_facts(workspace, "_facts_graph.json", dict, {})
