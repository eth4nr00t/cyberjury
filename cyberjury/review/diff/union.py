"""Diff finding identity and folding policies for the shared accumulator."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.finding import Finding
from cyberjury.review.engine import FindingAccumulator
from cyberjury.review.provenance import found_by_tuple


def _identity(finding: Finding) -> tuple[str, int | None, str, str, tuple[str, int | None, str]]:
    anchor = finding.change_anchor
    anchor_identity = (anchor.file, anchor.line, anchor.side) if anchor is not None else ("", None, "")
    return finding.file, finding.line, finding.category, finding.description, anchor_identity


def _union_text(existing: str, incoming: str) -> str:
    if not incoming or incoming in existing:
        return existing
    return f"{existing}\n\n{incoming}" if existing else incoming


def _fold(existing: Finding, incoming: Finding) -> Finding:
    """Preserve first report text while folding all independent provenance."""
    found_by = found_by_tuple(existing.found_by, incoming.found_by)
    description = _union_text(existing.description, incoming.description)
    exploit_scenario = _union_text(existing.exploit_scenario, incoming.exploit_scenario)
    recommendation = _union_text(existing.recommendation, incoming.recommendation)
    evidence_refs = tuple(dict.fromkeys((*existing.evidence_refs, *incoming.evidence_refs)))
    confidence = max(existing.confidence, incoming.confidence)
    if (
        found_by == existing.found_by
        and description == existing.description
        and exploit_scenario == existing.exploit_scenario
        and recommendation == existing.recommendation
        and evidence_refs == existing.evidence_refs
        and confidence == existing.confidence
    ):
        return existing
    return replace(
        existing,
        description=description,
        exploit_scenario=exploit_scenario,
        recommendation=recommendation,
        confidence=confidence,
        evidence_refs=evidence_refs,
        found_by=found_by,
    )


def role_accumulator() -> FindingAccumulator[Finding]:
    """Keep distinct role findings that share one report location."""
    return FindingAccumulator(
        key=_identity,
        fold=_fold,
        grade=lambda finding: finding.severity,
        with_grade=lambda finding, severity: replace(finding, severity=severity),
    )


def finding_accumulator() -> FindingAccumulator[Finding]:
    """Keep distinct standard findings that share one report location."""
    return FindingAccumulator(
        key=_identity,
        fold=_fold,
    )
