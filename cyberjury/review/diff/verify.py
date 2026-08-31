"""Adapt diff findings to the shared verification route."""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberjury.finding import Finding
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, finding_id
from cyberjury.review.verification import (
    Confirmer,
    VerificationCandidate,
    Verifier,
    VerifyResult,
    verify_findings,
)

FindingProvenance = tuple[str, ...] | dict[tuple, tuple[str, ...]]


@dataclass(frozen=True, kw_only=True)
class DiffVerifyResult:
    """Diff verification output with retained findings and failure count."""

    findings: list[Finding]
    dropped: list[tuple[Finding, str]]
    degraded: bool = False
    errors: int = 0
    error_details: list[str] = field(default_factory=list)
    incomplete: list[Finding] = field(default_factory=list)


def verify_diff_findings(
    findings: list[Finding],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    found_by: FindingProvenance = (),
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    trace: Trace | None = None,
) -> DiffVerifyResult:
    """Verify diff findings through the shared recall safe route."""
    candidates, by_source = _candidates_from_findings(findings, found_by=found_by)
    result = verify_findings(
        candidates,
        verifier,
        root,
        confirmers=confirmers,
        votes=votes,
        concurrency=concurrency,
        trace=trace,
    )
    return _result_from_verified(result, by_source)


def _candidates_from_findings(
    findings: list[Finding],
    *,
    found_by: FindingProvenance = (),
) -> tuple[list[VerificationCandidate], dict[str, Finding]]:
    candidates: list[VerificationCandidate] = []
    by_source: dict[str, Finding] = {}
    for i, finding in enumerate(findings):
        source = f"diff-{i}"
        by_source[source] = finding
        if isinstance(found_by, dict):
            provenance = found_by.get(_key(finding), finding.found_by)
        else:
            provenance = found_by or finding.found_by
        evidence = " ".join(
            part
            for part in (
                finding.description,
                finding.exploit_scenario,
                finding.recommendation,
            )
            if part
        )
        candidates.append(
            VerificationCandidate(
                title=finding.description or finding.category or finding.file,
                category=finding.category,
                file=finding.file,
                line=finding.line,
                severity=finding.severity,
                evidence=evidence,
                source=source,
                finding_id=finding_id(finding),
                found_by=provenance,
            )
        )
    return candidates, by_source


def _key(finding: Finding) -> tuple:
    return (finding.file, finding.line, finding.category)


def _result_from_verified(result: VerifyResult, by_source: dict[str, Finding]) -> DiffVerifyResult:
    kept = [by_source[c.source] for c in result.retained if c.source in by_source]
    dropped = [
        (by_source[c.source], f"verified false positive: {reason}")
        for c, reason in result.refuted
        if c.source in by_source
    ]
    degraded = result.errors > 0 or bool(result.incomplete)
    incomplete = [by_source[c.source] for c in result.incomplete if c.source in by_source]
    return DiffVerifyResult(
        findings=kept,
        dropped=dropped,
        degraded=degraded,
        errors=result.errors,
        error_details=result.error_details,
        incomplete=incomplete,
    )
