"""Collect repository navigation evidence outside parsed Web sources."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.profiles.base import content_paths
from cyberjury.profiles.web.facts.analyzer import AnalyzableSource, AnalyzedRepository, LangSpec, spec_for
from cyberjury.review.facts import FactLimitation

if TYPE_CHECKING:
    from cyberjury.detection import Detection

_DETECTION_FILE = content_paths(Path(__file__).resolve().parents[1]).detection_file


@dataclass(frozen=True, kw_only=True)
class RepositoryNavigationEvidence:
    """Repository scoped source evidence not parsed by a language grammar."""

    navigation_sources: dict[str, str]
    limitations: tuple[FactLimitation, ...] = ()


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


__all__ = [
    "RepositoryNavigationEvidence",
    "collect_navigation_evidence",
    "load_profile_detection",
    "reviewable_sources",
]
