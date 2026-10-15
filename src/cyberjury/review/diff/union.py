"""Diff finding identity and folding policies for the shared accumulator."""

from __future__ import annotations

from dataclasses import replace

from cyberjury.finding import Finding
from cyberjury.review.engine import FindingAccumulator
from cyberjury.review.provenance import found_by_tuple


def _normalized(text: str) -> str:
    return " ".join(text.lower().split())


def _identity(finding: Finding) -> tuple | str:
    if finding.source_operation_id:
        return (
            "source-operation",
            finding.source_operation_id,
            finding.category.strip().lower().replace("_", "-"),
            _normalized(finding.description),
        )
    return finding.candidate_id


def _union_text(existing: str, incoming: str) -> str:
    """Append incoming text unless it only repeats existing text up to case and whitespace."""
    if not incoming or _normalized(incoming) in _normalized(existing):
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


def finding_accumulator() -> FindingAccumulator[Finding]:
    """Keep distinct findings that share one report location."""
    return FindingAccumulator(
        key=_identity,
        fold=_fold,
    )
