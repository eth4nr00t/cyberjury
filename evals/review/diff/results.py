"""Score and fold Diff Review benchmark results."""

from __future__ import annotations

from pathlib import Path

from cyberjury.finding import Finding
from cyberjury.review.trace import Trace
from evals.benchmarks.cases import DiffCase
from evals.score.engine import score as score_reports
from evals.score.report import Report
from evals.score.result import Result


def empty_result() -> Result:
    """Create an empty Diff Review batch result."""
    return Result(target="diff")


def case_result(case: DiffCase) -> Result:
    """Create a case result with stable recall denominators."""
    findings = len(case.answer_key.findings) if case.answer_key else int(case.is_positive)
    file_findings = 0
    if case.answer_key:
        file_findings = sum(1 for check in case.answer_key.findings if check.files)
    return Result(target="diff", n_findings=findings, n_file_findings=file_findings)


def merge(result: Result, other: Result) -> None:
    """Fold one case score into a batch result."""
    result.found.extend(other.found)
    result.missed.extend(other.missed)
    result.false_positives.extend(other.false_positives)
    result.extra.extend(other.extra)
    result.file_found.extend(other.file_found)
    result.file_missed.extend(other.file_missed)
    result.n_findings += other.n_findings
    result.n_file_findings += other.n_file_findings
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
    result.file_found.extend(qualify(check_id) for check_id in scored.file_found)
    result.file_missed.extend(qualify(check_id) for check_id in scored.file_missed)


def apply_unkeyed(result: Result, case: DiffCase, findings: list[Finding]) -> None:
    """Apply coarse positive or clean scoring when no answer key exists."""
    result.n_reports += len(findings)
    hit = bool(findings)
    if case.is_positive:
        (result.found if hit else result.missed).append(case.name)
    elif hit:
        result.false_positives.append(case.name)


def score(case: DiffCase, findings: list[Finding], root: Path | None, trace: Trace | None) -> Result | None:
    """Score findings when the benchmark provides an answer key."""
    if case.answer_key is None:
        return None
    scored = score_reports(
        case.answer_key,
        reports_from_findings(findings),
        source_root=str(root) if root else None,
        endpoint_required=False,
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
        text = " ".join((finding.description, finding.exploit_scenario, finding.recommendation))
        reports.append(
            Report.make(
                f"{finding.file}:{finding.line or 0}:{index}",
                "",
                finding.category,
                [finding.file],
                text=text,
                lines=[finding.line] if finding.line else [],
            )
        )
    return reports
