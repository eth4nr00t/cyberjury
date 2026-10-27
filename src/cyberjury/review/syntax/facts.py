"""Coordinate syntax analysis into the shared Facts contract."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from functools import cache
from importlib.metadata import version
from pathlib import Path

from cyberjury.canonical import canonical_sha256
from cyberjury.review.facts import Facts
from cyberjury.review.syntax.analyzer import AnalyzableSource, analyze_repository, load_specs, spec_for
from cyberjury.review.syntax.graph import facts_from_repository


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


def analyzable_sources(root: str | Path, files: Sequence[str]) -> list[AnalyzableSource]:
    """Pair each review file of a language with a grammar with that language's analyzer."""
    base, specs = Path(root).resolve(), load_specs()
    return [(base / rel, rel, spec) for rel in files if (spec := spec_for(specs, rel)) is not None]


def extract_syntax_facts(root: str | Path, files: Sequence[str], *, progress: Callable[[int, int], None]) -> Facts:
    """Extract syntax evidence from the review files and disclose source level limitations."""
    analyzed = analyze_repository(analyzable_sources(root, files), progress=progress)
    return replace(facts_from_repository(analyzed), limitations=analyzed.limitations)
