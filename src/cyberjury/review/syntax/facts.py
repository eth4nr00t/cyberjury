"""Coordinate syntax analysis into the shared Facts contract."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from functools import cache
from importlib.metadata import version
from pathlib import Path

from cyberjury.canonical import canonical_sha256
from cyberjury.review.detection import Detection
from cyberjury.review.facts import Facts
from cyberjury.review.syntax.analyzer import analyze_repository, load_specs
from cyberjury.review.syntax.graph import facts_from_repository
from cyberjury.review.syntax.sources import collect_navigation_evidence, reviewable_sources


@cache
def syntax_backend_id() -> str:
    """Bind facts receipts to the effective queries, grammars, and package versions."""
    specs = load_specs()
    packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in specs.values()})
    versions = {package: version(package) for package in packages}
    payload = {
        "backend": "cyberjury.review.syntax",
        "specs": {name: asdict(spec) for name, spec in sorted(specs.items())},
        "versions": versions,
    }
    return canonical_sha256(payload)


def extract_syntax_facts(
    root: str | Path,
    files: Sequence[str],
    navigation_files: Sequence[str],
    detection: Detection,
    *,
    progress: Callable[[int, int], None],
) -> Facts:
    """Extract source evidence from the snapshot files and disclose source level limitations."""
    base = Path(root).resolve()
    analyzed = analyze_repository(reviewable_sources(base, files, detection, load_specs()), progress=progress)
    navigation = collect_navigation_evidence(base, analyzed, navigation_files)
    facts = facts_from_repository(replace(analyzed, sources={**analyzed.sources, **navigation}))
    return replace(facts, limitations=analyzed.limitations)
