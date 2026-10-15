"""Score and fold Diff Review benchmark results."""

from __future__ import annotations

from pathlib import Path

from cyberjury.finding import Finding
from cyberjury.review.trace import Trace
from evals.benchmarks.cases import DiffCase
from evals.score.engine import score as score_reports
from evals.score.report import Report, ReportChangeAnchor, ReportLocation
from evals.score.result import Result


def empty_result() -> Result:
    """Create an empty Diff Review batch result."""
    return Result(target="diff")


def case_result(case: DiffCase) -> Result:
    """Create a case result with stable recall denominators."""
    return Result(target="diff", n_findings=len(case.answer_key.findings))


def merge(result: Result, other: Result) -> None:
    """Fold one case score into a batch result."""
    result.found.extend(other.found)
    result.missed.extend(other.missed)
    result.false_positives.extend(other.false_positives)
    result.extra.extend(other.extra)
    result.n_findings += other.n_findings
    result.n_reports += other.n_reports
    result.errors += other.errors
    result.error_details.extend(other.error_details)


def record_failure(result: Result, case: DiffCase, failure: Exception | str) -> str:
    """Retain one case failure and return its display text."""
    error = f"{type(failure).__name__}: {failure}" if isinstance(failure, Exception) else failure
    result.errors += 1
    result.error_details.append(f"{case.name}: {error}")
    return error


def apply_score(result: Result, scored: Result, *, scope: str) -> None:
    """Apply one task scoped answer key score without changing its denominator."""

    def qualify(check_id: str) -> str:
        return f"{scope}:{check_id}"

    result.n_reports += scored.n_reports
    result.found.extend(qualify(check_id) for check_id in scored.found)
    result.missed.extend(qualify(check_id) for check_id in scored.missed)
    result.false_positives.extend(qualify(check_id) for check_id in scored.false_positives)
    result.extra.extend(scored.extra)


def score(case: DiffCase, findings: list[Finding], root: Path, trace: Trace | None) -> Result:
    """Score findings against the case answer key."""
    scored = score_reports(
        case.answer_key,
        reports_from_findings(findings),
        source_root=str(root),
        trace=trace,
    )
    if trace is not None:
        trace(
            {
                "event": "score",
                "stage": "finished",
                "reports": scored.n_reports,
                "found": scored.found,
                "missed": scored.missed,
                "extra": scored.extra,
            }
        )
    return scored


def reports_from_findings(findings: list[Finding]) -> list[Report]:
    """Convert product findings to scorer reports."""
    reports: list[Report] = []
    for index, finding in enumerate(findings):
        change_anchor = finding.change_anchor
        reports.append(
            Report(
                name=f"{finding.file}:{finding.line or 0}:{index}",
                locations=(ReportLocation(finding.file, finding.line or None),),
                change_anchor=(
                    ReportChangeAnchor(
                        file=change_anchor.file,
                        line=change_anchor.line,
                        side=change_anchor.side,
                    )
                    if change_anchor
                    else None
                ),
            )
        )
    return reports
