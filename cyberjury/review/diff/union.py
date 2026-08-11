"""Diff finding identity and folding policies for the shared accumulator."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.finding import Finding
from cyberjury.review.engine import FindingAccumulator
from cyberjury.review.provenance import found_by_tuple


def _fold(existing: Finding, incoming: Finding) -> Finding:
    """Preserve first report text while folding all independent provenance."""
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    return replace(existing, found_by=found_by) if found_by != existing.found_by else existing


def role_accumulator() -> FindingAccumulator[Finding]:
    """Deduplicate one role loop by report location and category."""
    return FindingAccumulator(
        key=lambda finding: (finding.file, finding.line, finding.category),
        fold=_fold,
        grade=lambda finding: finding.severity,
        with_grade=lambda finding, severity: replace(finding, severity=severity),
    )


def finding_accumulator() -> FindingAccumulator[Finding]:
    """Keep distinct standard findings that share one category and location."""
    return FindingAccumulator(
        key=lambda finding: (finding.file, finding.line, finding.category, finding.description),
        fold=_fold,
    )
