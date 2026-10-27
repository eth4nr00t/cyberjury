"""Select analyzer input files and collect navigation evidence outside parsed syntax sources."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from cyberjury.review.detection import Detection
from cyberjury.review.syntax.analyzer import (
    AnalyzableSource,
    AnalyzedRepository,
    LangSpec,
    spec_for,
)


def reviewable_sources(
    base: Path,
    files: Sequence[str],
    detection: Detection,
    specs: dict[str, LangSpec],
) -> list[AnalyzableSource]:
    """Select the snapshot files that belong to the analyzer input."""
    sources: list[AnalyzableSource] = []
    for rel in files:
        if (
            detection.is_ignored(rel)
            or detection.is_dependency(rel)
            or detection.is_test_path(rel)
            or rel in detection.oversized_files
        ):
            continue
        spec = spec_for(specs, rel)
        if spec is not None:
            sources.append((base / rel, rel, spec))
    return sources


def collect_navigation_evidence(
    base: Path,
    analyzed: AnalyzedRepository,
    navigation_files: Sequence[str],
) -> dict[str, str]:
    """Return the text of every navigation file the analyzer did not parse, without assigning bindings."""
    return {rel: (base / rel).read_text(encoding="utf-8") for rel in navigation_files if rel not in analyzed.sources}
