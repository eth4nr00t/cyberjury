"""Collect repository navigation evidence outside parsed Web sources."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.web.facts.analyzer import (
    AnalyzableSource,
    AnalyzedDefinition,
    AnalyzedImport,
    AnalyzedNamespace,
    AnalyzedQualifiedUse,
    AnalyzedRepository,
    LangSpec,
    spec_for,
)
from cyberjury.review.facts import FactLimitation
from cyberjury.review.failures import BackendUnavailable

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


@dataclass(frozen=True, kw_only=True)
class RepositoryNavigationEvidence:
    """Repository scoped source evidence not parsed by a language grammar."""

    navigation_sources: dict[str, str]
    limitations: tuple[FactLimitation, ...] = ()


@dataclass(frozen=True, kw_only=True)
class ResolvedRepository:
    """Repository validated syntax records ready for shared graph construction."""

    definitions: tuple[AnalyzedDefinition, ...]
    syntax_imports: dict[str, list[AnalyzedImport]]
    syntax_namespaces: dict[str, list[AnalyzedNamespace]]
    qualified_uses: dict[str, list[AnalyzedQualifiedUse]]
    sources: dict[str, str]
    producer_version: str


def load_profile_detection() -> Detection:
    """Load the Web profile rules used while resolving review scope."""
    from cyberjury.detection import load_detection

    return load_detection(_DETECTION_FILE)


def reviewable_sources(
    base: Path,
    detection: Detection,
    specs: dict[str, LangSpec],
) -> list[AnalyzableSource]:
    """Resolve repository files that belong to the analyzer input."""
    sources: list[AnalyzableSource] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        try:
            if not path.resolve().is_relative_to(base):
                continue
        except OSError:
            continue
        rel = path.relative_to(base).as_posix()
        if detection.is_skipped_dir(Path(rel).parts[:-1]) or detection.is_test_path(rel):
            continue
        spec = spec_for(specs, rel)
        if spec is not None:
            sources.append((path, rel, spec))
    return sources


def collect_navigation_evidence(
    base: Path,
    analyzed: AnalyzedRepository,
    detection: Detection,
) -> RepositoryNavigationEvidence:
    """Publish unparsed source text for navigation without assigning bindings."""
    from cyberjury.review.paths import source_navigation_files

    navigation_sources: dict[str, str] = {}
    limitations: list[FactLimitation] = []
    for rel in source_navigation_files(base, detection):
        if rel in analyzed.sources:
            continue
        try:
            text = (base / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            limitations.append(
                FactLimitation(
                    source=rel,
                    analyzer="web-resolver",
                    reason="could not read repository navigation evidence",
                )
            )
            continue
        navigation_sources[rel] = text.replace("\r\n", "\n").replace("\r", "\n")
    return RepositoryNavigationEvidence(
        navigation_sources=navigation_sources,
        limitations=tuple(limitations),
    )


def resolve_repository(
    analyzed: AnalyzedRepository,
    navigation: RepositoryNavigationEvidence,
) -> ResolvedRepository:
    """Validate analyzer coordinates against exact repository source text."""
    overlap = set(analyzed.sources).intersection(navigation.navigation_sources)
    if overlap:
        raise BackendUnavailable(f"navigation evidence duplicates analyzed source: {', '.join(sorted(overlap))}")
    sources = {**analyzed.sources, **navigation.navigation_sources}
    for definition in analyzed.definitions:
        source = _source(sources, definition.file)
        _range(source, definition.start, definition.end, f"definition {definition.file}:{definition.name}")
        for callsite in definition.callsites:
            selected = _range(source, callsite.start, callsite.end, f"callsite {definition.file}:{callsite.callee}")
            if selected != callsite.expression:
                raise BackendUnavailable(
                    f"callsite source does not match analyzed expression at {definition.file}:{callsite.start}"
                )
            for argument in callsite.arguments:
                selected = _range(
                    source,
                    argument.start,
                    argument.end,
                    f"call argument {definition.file}:{argument.position}",
                )
                if selected != argument.expression:
                    raise BackendUnavailable(
                        f"call argument source does not match analyzed expression at {definition.file}:{argument.start}"
                    )
        for parameter in definition.parameters:
            selected = _range(
                source,
                parameter.start,
                parameter.end,
                f"parameter {definition.file}:{parameter.position}",
            )
            if selected != parameter.declaration:
                raise BackendUnavailable(
                    f"parameter source does not match analyzed declaration at {definition.file}:{parameter.start}"
                )
        if definition.receiver is not None:
            selected = _range(
                source,
                definition.receiver.start,
                definition.receiver.end,
                f"receiver {definition.file}:{definition.receiver.name}",
            )
            if selected != definition.receiver.declaration:
                raise BackendUnavailable(
                    "receiver source does not match analyzed declaration at "
                    f"{definition.file}:{definition.receiver.start}"
                )
    for label, records in (
        ("import", analyzed.imports),
        ("namespace", analyzed.namespaces),
        ("qualified use", analyzed.qualified_uses),
    ):
        for file, values in records.items():
            source = _source(sources, file)
            for value in values:
                _range(source, value.start, value.end, f"{label} {file}")
    return ResolvedRepository(
        definitions=analyzed.definitions,
        syntax_imports=analyzed.imports,
        syntax_namespaces=analyzed.namespaces,
        qualified_uses=analyzed.qualified_uses,
        sources=sources,
        producer_version=analyzed.producer_version,
    )


def _source(sources: dict[str, str], file: str) -> str:
    try:
        return sources[file]
    except KeyError as exc:
        raise BackendUnavailable(f"resolved syntax evidence has no repository source for {file}") from exc


def _range(source: str, start: int, end: int, label: str) -> str:
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
        or start < 0
        or end <= start
        or end > len(source)
    ):
        raise BackendUnavailable(f"resolved syntax evidence has an invalid source range for {label}")
    return source[start:end]


__all__ = [
    "RepositoryNavigationEvidence",
    "ResolvedRepository",
    "collect_navigation_evidence",
    "load_profile_detection",
    "resolve_repository",
    "reviewable_sources",
]
