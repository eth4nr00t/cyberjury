"""The shipped diff probe cases and their loader. Small realistic patches, one or more per
vulnerability class, plus safe lookalikes that must stay clean. Synthetic and authored
here, not third-party, so they ship publicly. The cases live as data under benchmarks/diff,
mirroring the knowledge guides taxonomy, languages/<language>/cases.yaml with frameworks
grouped within each file, and protocols/<protocol>/cases.yaml for language-independent
protocol cases, each row naming the knowledge it exercises so the coverage matrix attributes
it. A positive carries a category and should
yield a finding, a safe case carries none and should stay clean.

This module is engine-free on purpose, so the coverage matrix can read the cases without
importing the audit runner.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.schema import knowledge_refs

CASES_DIR = Path(__file__).resolve().parent / "benchmarks" / "diff"


@dataclass(frozen=True, kw_only=True)
class DiffCase:
    name: str
    diff: str
    category: str = ""
    knowledge: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    # the review domain whose knowledge and prompt the probe runs the case under, so a
    # Solidity case scores against the evm domain, not the web default
    domain: str = "web"

    @property
    def is_positive(self) -> bool:
        return bool(self.category)


def _case(row, i: int) -> DiffCase:
    if "diff" not in row:
        raise ValueError(f"cases[{i}] ({row.get('name', '?')}) has no diff")
    return DiffCase(
        name=str(row["name"]),
        diff=str(row["diff"]),
        category=str(row.get("category") or ""),
        knowledge=knowledge_refs(row.get("knowledge")),
        tags=tuple(row.get("tags") or ()),
        domain=str(row.get("domain") or "web"),
    )


def load_cases(path: str | Path) -> list[DiffCase]:
    """Load cases from a YAML list of {name, category, diff, knowledge, tags, domain}, failing loud
    on a row with no diff rather than silently probing nothing."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rows = data.get("cases") if isinstance(data, dict) else data
    if not rows:
        raise ValueError(f"no cases in {path}")
    return [_case(r, i) for i, r in enumerate(rows)]


def default_cases() -> list[DiffCase]:
    """The shipped probe cases, every cases.yaml under benchmarks/diff concatenated. A
    cases.yaml is found at any depth, so a new language, protocol, or framework subtree
    joins the library without any wiring. A name must be unique across files, since suites
    and the coverage matrix key on it, so a collision fails loud rather than last wins."""
    files = sorted(CASES_DIR.rglob("cases.yaml"))
    if not files:
        raise ValueError(f"no cases.yaml under {CASES_DIR}")
    cases: list[DiffCase] = []
    seen: dict[str, Path] = {}
    for f in files:
        for case in load_cases(f):
            if case.name in seen:
                raise ValueError(
                    f"diff case '{case.name}' is defined in two files, {seen[case.name]} "
                    f"and {f}. A case name must be unique across the library, rename one."
                )
            seen[case.name] = f
            cases.append(case)
    return cases
