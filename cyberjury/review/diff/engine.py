"""Compose diff adapters around the shared review engine."""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable

from cyberjury.detection import Detection, load_detection
from cyberjury.finding import Finding
from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.review.diff.context import changed_line_ranges, diff_local_context
from cyberjury.review.diff.model import strip_unreviewable_files
from cyberjury.review.diff.reviewer import AdversarialAuditRunner, AuditRunner, guides_for_diff
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import finding_accumulator, role_accumulator
from cyberjury.review.diff.verify import verify_diff_findings
from cyberjury.review.engine import (
    JudgmentProgress,
    ReviewCycle,
    ReviewOutcome,
    extend_review_outcome,
    review_plan,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, bind_trace, emit_trace, finding_id
from cyberjury.review.verification import Confirmer, Verifier, verification_failure_reason
from cyberjury.review.vulnerabilities import VulnerabilityCatalog


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffReviewResult:
    """The complete diff review outcome and findings rejected by verification."""

    outcome: ReviewOutcome[Finding]
    dropped: list[tuple[Finding, str]]


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _diff_path_key(path: str) -> str:
    path = path.removeprefix("./")
    return path[2:] if path[:2] in ("a/", "b/") else path


def _normalize_finding_lines(findings: list[Finding], diff: str, detection: Detection) -> list[Finding]:
    ranges = changed_line_ranges(diff, detection)
    out: list[Finding] = []
    for f in findings:
        if f.line is None:
            out.append(f)
            continue
        file_ranges = ranges.get(_diff_path_key(f.file))
        if not file_ranges or not _line_in_ranges(f.line, file_ranges):
            out.append(dataclasses.replace(f, line=None))
            continue
        out.append(f)
    return out


def run_diff_review(
    diff: str,
    *,
    provider: Provider,
    model: str,
    mode: str = "standard",
    max_rounds: int = DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds,
    finder_model: str | None = None,
    challenger_model: str | None = None,
    judge_model: str | None = None,
    finder_provider: Provider | None = None,
    challenger_provider: Provider | None = None,
    judge_provider: Provider | None = None,
    finder_label: str | None = None,
    challenger_label: str | None = None,
    judge_label: str | None = None,
    context: str = "",
    context_for_diff: Callable[[str], str] | None = None,
    verification_root: str | None = None,
    verifier: Verifier | None = None,
    verification_confirmers: list[Confirmer] | None = None,
    verification_found_by: tuple[str, ...] = (),
    verification_votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
    concurrency: int = DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency,
    verification_concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
    batch_failures: list[ReviewUnitFailure] | None = None,
    profile: ReviewProfile | None = None,
    on_batch: Callable[[int, int, float], None] | None = None,
    on_judgment: JudgmentProgress | None = None,
    trace: Trace | None = None,
) -> DiffReviewResult:
    """Return findings and explicit incomplete state for one diff review."""
    plan = review_plan(mode, max_rounds=max_rounds)
    profile = profile or default_profile()
    content = profile.paths
    trace = bind_trace(trace, review_id=f"review-{uuid.uuid4().hex[:16]}", target="diff", mode=mode)
    focus, do_not_report = profile.diff_focus, profile.diff_do_not_report
    detection = load_detection(content.detection_file)
    diff, _ = strip_unreviewable_files(diff, detection)
    if not diff.strip():
        return DiffReviewResult(outcome=ReviewOutcome(findings=[]), dropped=[])
    if context_for_diff is None and not context:
        context = diff_local_context(diff, detection=detection)

    adversarial_runner = (
        AdversarialAuditRunner(
            provider=provider,
            model=model,
            finder_model=finder_model,
            challenger_model=challenger_model,
            judge_model=judge_model,
            finder_provider=finder_provider,
            challenger_provider=challenger_provider,
            judge_provider=judge_provider,
            finder_label=finder_label,
            challenger_label=challenger_label,
            judge_label=judge_label,
            content=content,
            focus=focus,
            do_not_report=do_not_report,
        )
        if mode == "adversarial"
        else None
    )
    standard_runner = (
        AuditRunner(provider=provider, model=model, content=content, focus=focus, do_not_report=do_not_report)
        if mode == "standard"
        else None
    )

    def _run_one(_round: int, d: str, known: list[Finding]) -> ReviewCycle[Finding]:
        local_context = context_for_diff(d) if context_for_diff is not None else context
        if mode == "adversarial":
            return adversarial_runner.review_round(
                d,
                context=local_context,
                stack=guides_for_diff(d, content),
                known=known,
                trace=trace,
                round_id=_round,
            )
        return standard_runner.review_round(
            d,
            context=local_context,
            finder_label=finder_label or model,
            on_judgment=on_judgment,
            trace=trace,
        )

    review_outcome = run_batches(
        diff,
        _run_one,
        plan=plan,
        accumulator=role_accumulator() if mode == "adversarial" else finding_accumulator(),
        failures=batch_failures,
        concurrency=concurrency,
        on_batch=on_batch,
    )
    if review_outcome.failures or review_outcome.errors or review_outcome.failure_reason:
        emit_trace(
            trace,
            "review_failed",
            errors=review_outcome.errors,
            failures=len(review_outcome.failures),
            reason=review_outcome.failure_reason[:500],
        )
    findings = review_outcome.findings

    catalog = VulnerabilityCatalog.load(content.vulnerabilities_dir)
    findings = [dataclasses.replace(f, category=catalog.close_category(f.category)) for f in findings]
    before_normalization = findings
    findings = _normalize_finding_lines(findings, diff, detection)
    for before, after in zip(before_normalization, findings, strict=True):
        emit_trace(
            trace,
            "finding",
            stage="normalized",
            finding_id=finding_id(after),
            file=after.file,
            line=after.line,
            original_line=before.line,
            category=after.category,
            description=after.description[:500],
        )

    verification_errors = 0
    verification_error_details: list[str] = []
    verification_incomplete: list[Finding] = []

    if verifier is not None:
        if verification_root is None:
            raise ValueError("verification_root is required when verifier is set")
        verified = verify_diff_findings(
            findings,
            verifier,
            verification_root,
            confirmers=verification_confirmers,
            found_by=verification_found_by,
            votes=verification_votes,
            concurrency=verification_concurrency,
            trace=trace,
        )
        kept = verified.findings
        dropped = verified.dropped
        verification_errors = verified.errors
        verification_error_details = verified.error_details
        verification_incomplete = verified.incomplete
    else:
        kept = findings
        dropped = []
    for finding in kept:
        emit_trace(
            trace,
            "finding",
            stage="kept",
            finding_id=finding_id(finding),
            file=finding.file,
            line=finding.line,
            category=finding.category,
        )
    for finding, reason in dropped:
        emit_trace(
            trace,
            "finding",
            stage="dropped",
            finding_id=finding_id(finding),
            file=finding.file,
            line=finding.line,
            category=finding.category,
            reason=reason[:500],
        )
    outcome = extend_review_outcome(
        review_outcome,
        findings=kept,
        incomplete=verification_incomplete,
        errors=verification_errors,
        failure_reason=verification_failure_reason(verification_error_details),
    )
    emit_trace(
        trace,
        "review_finished",
        status="incomplete" if outcome.degraded else "complete",
        findings=len(kept),
        errors=outcome.errors,
        incomplete=len(outcome.incomplete),
    )
    return DiffReviewResult(outcome=outcome, dropped=dropped)


def audit_diff(diff: str, **kwargs) -> tuple[list[Finding], list[tuple[Finding, str]], bool]:
    """Keep the legacy tuple API while new callers consume the complete outcome."""
    result = run_diff_review(diff, **kwargs)
    return result.outcome.findings, result.dropped, result.outcome.degraded
