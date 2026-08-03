"""A suite is a named tag selection over the cases and benchmarks that already exist, not a
second hand-maintained list of them. A suite names tags, and a case or benchmark joins when
it carries any of those tags, so adding a case to the library lands it in every suite it
belongs to without editing the suite. An empty tag list selects everything.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_SUITES_DIR = Path(__file__).resolve().parent / "suites"


@dataclass(frozen=True, kw_only=True)
class Suite:
    name: str
    description: str = ""
    tags: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()  # optional filter, diff or repository, empty selects both


def load_suite(name_or_path: str | Path) -> Suite:
    """Load a suite by name from the shipped suites, or from a path. An unknown name fails
    loud with the known suites, so a typo is obvious rather than a silently empty run."""
    p = Path(name_or_path)
    if not p.is_file():
        p = _SUITES_DIR / f"{name_or_path}.yaml"
    if not p.is_file():
        known = ", ".join(sorted(s.stem for s in _SUITES_DIR.glob("*.yaml"))) or "none"
        raise ValueError(f"no suite '{name_or_path}'. Known: {known}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return Suite(
        name=str(data.get("name", p.stem)),
        description=str(data.get("description", "")),
        tags=tuple(data.get("tags") or ()),
        kinds=tuple(data.get("kinds") or ()),
    )


def all_suites() -> list[Suite]:
    return [load_suite(s.stem) for s in sorted(_SUITES_DIR.glob("*.yaml"))]


def _matches(suite: Suite, tags) -> bool:
    if not suite.tags:
        return True
    return bool(set(suite.tags) & set(tags))


def select_cases(suite: Suite, cases):
    """The diff cases the suite selects, by tag. A suite scoped to repository only selects none."""
    if suite.kinds and "diff" not in suite.kinds:
        return []
    return [c for c in cases if _matches(suite, c.tags)]


def select_benchmarks(suite: Suite, benchmarks):
    """The repository benchmarks the suite selects, by tag. A suite scoped to diff only selects
    none. A benchmark's tags come from its manifest."""
    if suite.kinds and "repository" not in suite.kinds:
        return []
    return [b for b in benchmarks if _matches(suite, b.tags)]
