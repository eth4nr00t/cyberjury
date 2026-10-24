"""Coordinate syntax analysis into the shared Facts contract."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, replace
from functools import cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cyberjury.canonical import canonical_sha256
from cyberjury.review.detection import Detection
from cyberjury.review.facts import FactLimitation, Facts
from cyberjury.review.syntax.analyzer import AnalyzedRepository, analyze_repository, load_specs
from cyberjury.review.syntax.graph import facts_from_repository
from cyberjury.review.syntax.sources import collect_navigation_evidence, reviewable_sources


@cache
def syntax_backend_id() -> str:
    """Bind facts receipts to the effective queries, grammars, and package versions."""
    specs = load_specs()
    packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in specs.values()})
    versions = {}
    for package in packages:
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "missing"
    payload = {
        "backend": "cyberjury.review.syntax",
        "specs": {name: asdict(spec) for name, spec in sorted(specs.items())},
        "versions": versions,
    }
    return canonical_sha256(payload)


def extract_syntax_facts(
    root: str | Path, files: Sequence[str], navigation_files: Sequence[str], detection: Detection
) -> Facts:
    """Extract source evidence from the snapshot files and disclose source level limitations."""
    base = Path(root).resolve()
    analyzed = analyze_repository(reviewable_sources(base, files, detection, load_specs()))
    navigation = collect_navigation_evidence(base, analyzed, navigation_files)
    facts, excluded = _facts_without_failing_files(
        replace(analyzed, sources={**analyzed.sources, **navigation.navigation_sources})
    )
    limitations = (*analyzed.limitations, *navigation.limitations, *excluded)
    return replace(facts, limitations=tuple(dict.fromkeys(limitations)))


def _facts_without_failing_files(repository: AnalyzedRepository) -> tuple[Facts, tuple[FactLimitation, ...]]:
    try:
        return facts_from_repository(repository), ()
    except Exception:
        failing = {}
        for file in _analyzed_files(repository):
            try:
                facts_from_repository(_only_files(repository, {file}, sources_too=True))
            except Exception as file_exc:
                failing[file] = type(file_exc).__name__
        if not failing:
            raise
        kept = _analyzed_files(repository).difference(failing)
        facts = facts_from_repository(_only_files(repository, kept))
        excluded = tuple(
            FactLimitation(source=file, analyzer="syntax graph", reason=f"analysis failed ({name})")
            for file, name in sorted(failing.items())
        )
        return facts, excluded


def _analyzed_files(repository: AnalyzedRepository) -> set[str]:
    files = {definition.file for definition in repository.definitions}
    for by_file in (
        repository.imports,
        repository.namespaces,
        repository.qualified_uses,
        repository.structural_relationships,
    ):
        files.update(file for file, items in by_file.items() if items)
    return files


def _only_files(repository: AnalyzedRepository, files: set[str], *, sources_too: bool = False) -> AnalyzedRepository:
    sources = {file: text for file, text in repository.sources.items() if file in files} if sources_too else None
    return replace(
        repository,
        sources=repository.sources if sources is None else sources,
        definitions=tuple(definition for definition in repository.definitions if definition.file in files),
        imports={file: items for file, items in repository.imports.items() if file in files},
        namespaces={file: items for file, items in repository.namespaces.items() if file in files},
        qualified_uses={file: items for file, items in repository.qualified_uses.items() if file in files},
        structural_relationships={
            file: items for file, items in repository.structural_relationships.items() if file in files
        },
    )
