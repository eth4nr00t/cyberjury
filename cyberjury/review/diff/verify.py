"""Diff finding verification through the repository verifier."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.finding import Finding
from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verifier import Confirmer, Verifier, VerifyResult, verify_findings


@dataclass(frozen=True, kw_only=True)
class DiffVerifyResult:
    """Diff verification output with retained findings and failure count."""

    findings: list[Finding]
    dropped: list[tuple[Finding, str]]
    degraded: bool = False
    errors: int = 0


def verify_diff_findings(
    findings: list[Finding],
    verifier: Verifier,
    root: str,
    *,
    confirmers: list[Confirmer] | None = None,
    votes: int = 1,
    concurrency: int = 6,
) -> DiffVerifyResult:
    """Run deterministic verification over diff findings."""
    candidates, by_source = _candidates_from_findings(findings)
    result = verify_findings(
        candidates,
        verifier,
        root,
        confirmers=confirmers,
        votes=votes,
        concurrency=concurrency,
    )
    return _result_from_verified(result, by_source)


def _candidates_from_findings(findings: list[Finding]) -> tuple[list[Candidate], dict[str, Finding]]:
    candidates: list[Candidate] = []
    by_source: dict[str, Finding] = {}
    for i, finding in enumerate(findings):
        source = f"diff-{i}"
        by_source[source] = finding
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
            Candidate(
                title=finding.description or finding.category or finding.file,
                category=finding.category,
                file=finding.file,
                line=finding.line,
                severity=finding.severity,
                evidence=evidence,
                source=source,
            )
        )
    return candidates, by_source


def _result_from_verified(result: VerifyResult, by_source: dict[str, Finding]) -> DiffVerifyResult:
    kept = [by_source[c.source] for c in result.confirmed if c.source in by_source]
    dropped = [
        (by_source[c.source], f"verified false positive: {reason}")
        for c, reason in result.refuted
        if c.source in by_source
    ]
    degraded = result.errors > 0 or bool(result.incomplete)
    return DiffVerifyResult(findings=kept, dropped=dropped, degraded=degraded, errors=result.errors)
