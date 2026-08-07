"""Knowledge coverage: scan the knowledge tree and cross it against the registry, so a
vulnerability class or a guide that no eval exercises is a visible gap, not a silent one.

Knowledge is data and the engine is generic, invariant 1. This module makes that
measurable. For each knowledge file it counts the positive and safe diff benchmark tasks and the
repository planted and safe entries that exercise it, split by public and private provenance, and it
reports the gate problems the doc defines: a benchmark reference that resolves to no real file,
an answer key entry that names no knowledge at all, and a vulnerability with no whole-repository
target.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyberjury.domains.registry import available_domains, get_domain
from evals import registry
from evals.schema import knowledge_refs, load_answer_key
from evals.scorers.match import category_of


@dataclass(frozen=True, kw_only=True)
class KnowledgeItem:
    """One knowledge file the matrix tracks, addressed by its namespaced ref."""

    ref: str  # vuln:<id> or guide:<path>, the form a benchmark references
    kind: str
    path: Path


@dataclass(kw_only=True)
class Coverage:
    """How much eval evidence exercises one knowledge item, by source and provenance."""

    item: KnowledgeItem
    diff_positive: int = 0
    diff_safe: int = 0
    repository_planted: int = 0
    repository_safe: int = 0
    public: int = 0
    private: int = 0

    @property
    def diff_covered(self) -> bool:
        return bool(self.diff_positive or self.diff_safe)

    @property
    def repository_covered(self) -> bool:
        return bool(self.repository_planted or self.repository_safe)

    @property
    def covered(self) -> bool:
        return self.diff_covered or self.repository_covered


@dataclass(frozen=True, kw_only=True)
class CoverageProblem:
    """A gate-facing coverage gap. unresolved-reference is broken benchmark data,
    entry-without-knowledge is unscored attribution, and missing-repository-target is the
    integration gap where no whole-repository benchmark plants the class."""

    kind: str
    ref: str
    detail: str


def scan_knowledge() -> dict[str, KnowledgeItem]:
    """Every vulnerability class and guide across all registered domains, keyed by namespaced
    ref. The guide ref mirrors its path under guides/, languages/python and
    frameworks/python/fastapi, the exact form a benchmark or an answer key references. Refs
    are flat across domains, so a stem two domains share fails loud rather than letting one
    silently shadow the other."""
    items: dict[str, KnowledgeItem] = {}

    def add(ref: str, kind: str, path: Path) -> None:
        prior = items.get(ref)
        if prior is not None and prior.path != path:
            raise ValueError(
                f"knowledge ref {ref} is defined in two domains, {prior.path} and {path}. "
                f"Refs are flat across domains, rename one or namespace the ref."
            )
        items[ref] = KnowledgeItem(ref=ref, kind=kind, path=path)

    for name in available_domains():
        paths = get_domain(name).paths
        for f in sorted(paths.vulnerabilities_dir.glob("*.md")):
            add(f"vuln:{f.stem}", "vulnerability", f)
        guides_dir = paths.languages_dir.parent
        if not guides_dir.is_dir():
            continue
        for f in sorted(guides_dir.rglob("*.md")):
            rel = f.relative_to(guides_dir).with_suffix("").as_posix()
            add(f"guide:{rel}", "guide", f)
    return items


def _diff_case_refs(cases=None) -> list[tuple[str, bool, tuple[str, ...], str]]:
    """Each diff benchmark as name, is_positive, knowledge refs, provenance. A benchmark names
    the knowledge it exercises, a safe lookalike included, so it attributes to the class it
    guards. A positive with no explicit knowledge falls back to its category."""
    rows: list[tuple[str, bool, tuple[str, ...], str]] = []
    for c in cases if cases is not None else _default_cases():
        refs = c.knowledge or ((f"vuln:{category_of(c.category)}",) if c.category else ())
        rows.append((c.name, c.is_positive, refs, c.provenance))
    return rows


def _default_cases():
    from evals.diff_cases import default_cases

    return default_cases()


def coverage_matrix(cases=None) -> dict[str, Coverage]:
    """Cross every knowledge item against the diff benchmarks and the repository benchmarks the
    registry sees, tallying how each is exercised. A ref that no knowledge file backs is
    not counted here, it is reported as an unresolved-reference problem instead."""
    items = scan_knowledge()
    cov = {ref: Coverage(item=it) for ref, it in items.items()}

    for _, is_positive, refs, provenance in _diff_case_refs(cases):
        for ref in refs:
            c = cov.get(ref)
            if c is None:
                continue
            if is_positive:
                c.diff_positive += 1
            else:
                c.diff_safe += 1
            setattr(c, provenance, getattr(c, provenance) + 1)

    for bench in registry.all_benchmarks().values():
        key = load_answer_key(bench.answer_key, task_id=bench.task_id)
        for entry in key.planted:
            for ref in entry.knowledge:
                c = cov.get(ref)
                if c is None:
                    continue
                c.repository_planted += 1
                setattr(c, bench.provenance, getattr(c, bench.provenance) + 1)
        for entry in key.safe:
            for ref in entry.knowledge:
                c = cov.get(ref)
                if c is None:
                    continue
                c.repository_safe += 1
                setattr(c, bench.provenance, getattr(c, bench.provenance) + 1)
    return cov


def _all_referenced(cases=None) -> list[tuple[str, str]]:
    """Every knowledge ref any benchmark names, manifest level and per entry, paired with a
    where label, so an unresolved one can be reported against its source."""
    refs: list[tuple[str, str]] = []
    for case in cases if cases is not None else _default_cases():
        for ref in case.knowledge:
            refs.append((ref, f"diff benchmark '{case.name}' manifest"))
        if case.answer_key is None:
            continue
        for entry in (*case.answer_key.planted, *case.answer_key.safe):
            for ref in entry.knowledge:
                refs.append((ref, f"diff benchmark '{case.name}' entry '{entry.id}'"))
    for bench in registry.all_benchmarks().values():
        for ref in knowledge_refs(bench.knowledge):
            refs.append((ref, f"benchmark '{bench.id}' manifest"))
        key = load_answer_key(bench.answer_key)
        for entry in (*key.planted, *key.safe):
            for ref in entry.knowledge:
                refs.append((ref, f"benchmark '{bench.id}' entry '{entry.id}'"))
    return refs


def coverage_problems(cov: dict[str, Coverage] | None = None) -> list[CoverageProblem]:
    """The gate-facing gaps, in a stable order. Every referenced knowledge file must exist,
    every answer key entry should name at least one knowledge item, and every vulnerability needs
    a whole-repository benchmark, the rules from the design doc."""
    cases = _default_cases()
    cov = coverage_matrix(cases) if cov is None else cov
    problems: list[CoverageProblem] = []

    for ref, c in sorted(cov.items()):
        if c.item.kind != "vulnerability":
            continue
        if not c.repository_planted:
            problems.append(
                CoverageProblem(
                    kind="missing-repository-target",
                    ref=ref,
                    detail="no whole-repository benchmark plants this class, so its "
                    "cross-file and business-logic recall is unmeasured",
                )
            )

    known = set(scan_knowledge())
    for ref, where in _all_referenced(cases):
        if ref not in known:
            problems.append(
                CoverageProblem(
                    kind="unresolved-reference",
                    ref=ref,
                    detail=f"{where} references {ref}, which matches no knowledge file",
                )
            )

    for bench in registry.all_benchmarks().values():
        key = load_answer_key(bench.answer_key, task_id=bench.task_id)
        for entry in (*key.planted, *key.safe):
            if not entry.knowledge:
                problems.append(
                    CoverageProblem(
                        kind="entry-without-knowledge",
                        ref=entry.id,
                        detail=f"benchmark '{bench.id}' entry '{entry.id}' names no knowledge",
                    )
                )
    for case in cases:
        if case.answer_key is None:
            continue
        for entry in (*case.answer_key.planted, *case.answer_key.safe):
            if not entry.knowledge:
                problems.append(
                    CoverageProblem(
                        kind="entry-without-knowledge",
                        ref=entry.id,
                        detail=f"diff benchmark '{case.name}' entry '{entry.id}' names no knowledge",
                    )
                )
    return problems


def format_matrix(cov: dict[str, Coverage], problems: list[CoverageProblem]) -> str:
    """A plain table of coverage by knowledge item, then the gap list. Uncovered files are
    the point, they name what the benchmark library still has to reach."""
    rows = sorted(cov.values(), key=lambda c: (c.item.kind, c.item.ref))
    lines = ["=== knowledge coverage ===", f"  {'knowledge':52} diff+  diff-  repository+  repository-  prov"]
    for c in rows:
        prov = "/".join(p for p, n in (("pub", c.public), ("priv", c.private)) if n) or "-"
        if not c.covered:
            flag = "  UNCOVERED"
        elif c.item.kind == "vulnerability" and not c.repository_covered:
            flag = "  REPOSITORY-UNCOVERED"
        else:
            flag = ""
        lines.append(
            f"  {c.item.ref:52} {c.diff_positive:>4}  {c.diff_safe:>4}  "
            f"{c.repository_planted:>4}  {c.repository_safe:>4}  {prov}{flag}"
        )
    uncovered = sum(1 for c in rows if not c.covered)
    repository_gap = sum(1 for c in rows if c.item.kind == "vulnerability" and not c.repository_covered)
    vulns = sum(1 for c in rows if c.item.kind == "vulnerability")
    lines.append(f"  {uncovered} of {len(rows)} knowledge files have no eval coverage")
    lines.append(f"  {repository_gap} of {vulns} vulnerability classes have no whole-repository target")
    if problems:
        lines.append("")
        lines.append(f"=== coverage problems ({len(problems)}) ===")
        for p in problems:
            lines.append(f"  [{p.kind}] {p.ref}  {p.detail}")
    return "\n".join(lines)
