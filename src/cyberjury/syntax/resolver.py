"""Collect repository navigation evidence outside parsed syntax sources."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from cyberjury.review.facts import FactLimitation
from cyberjury.syntax.analyzer import (
    AnalyzableSource,
    AnalyzedRepository,
    LangSpec,
    spec_for,
)

if TYPE_CHECKING:
    from cyberjury.detection import Detection


@dataclass(frozen=True, kw_only=True)
class RepositoryNavigationEvidence:
    """Repository scoped source evidence not parsed by a language grammar."""

    navigation_sources: dict[str, str]
    limitations: tuple[FactLimitation, ...] = ()


def reviewable_sources(
    base: Path,
    files: Sequence[str],
    detection: Detection,
    specs: dict[str, LangSpec],
) -> list[AnalyzableSource]:
    """Select the snapshot files that belong to the analyzer input."""
    sources: list[AnalyzableSource] = []
    for rel in files:
        if detection.is_skipped_dir(PurePosixPath(rel).parts[:-1]) or detection.is_test_path(rel):
            continue
        spec = spec_for(specs, rel)
        if spec is not None:
            sources.append((base / rel, rel, spec))
    return sources


def collect_navigation_evidence(
    base: Path,
    analyzed: AnalyzedRepository,
    navigation_files: Sequence[str],
) -> RepositoryNavigationEvidence:
    """Publish unparsed source text for navigation without assigning bindings."""
    navigation_sources: dict[str, str] = {}
    limitations: list[FactLimitation] = []
    for rel in navigation_files:
        if rel in analyzed.sources:
            continue
        try:
            text = (base / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            limitations.append(
                FactLimitation(
                    source=rel,
                    analyzer="source-resolver",
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
    "reviewable_sources",
]
