"""Compose diff adapters around the shared review engine."""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable
from typing import cast

from cyberjury.detection import Detection, load_detection
from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.profiles.base import ContentPaths, ReviewProfile
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.review.context import GroundingContext, GroundingCoverage, merge_grounding_coverage
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
    diff_line_ranges,
    diff_local_context,
    strip_unreviewable_files,
)
from cyberjury.review.diff.reviewer import AdversarialAuditRunner, AuditRunner, guides_for_diff
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import finding_accumulator, role_accumulator
from cyberjury.review.diff.verify import DiffVerifyResult, verify_diff_findings
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


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffRoleOptions:
    """Role seats and convergence settings for one diff review."""

    mode: str = "standard"
    max_rounds: int = DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
    finder_model: str | None = None
    challenger_model: str | None = None
    judge_model: str | None = None
    finder_provider: Provider | None = None
    challenger_provider: Provider | None = None
    judge_provider: Provider | None = None
    finder_label: str | None = None
    challenger_label: str | None = None
    judge_label: str | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffGroundingOptions:
    """Static and per-unit repository grounding for one diff review."""

    context: GroundingContext | str = ""
    context_for_diff: Callable[[str], GroundingContext | str] | None = None
    prepare_diff: Callable[[str], list[DiffUnit]] | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffVerificationOptions:
    """Candidate verification route and vote settings."""

    root: str | None = None
    verifier: Verifier | None = None
    confirmers: list[Confirmer] | None = None
    found_by: tuple[str, ...] = ()
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffExecutionOptions:
    """Batch scheduling, progress, profile, and trace hooks."""

    concurrency: int = DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency
    batch_failures: list[ReviewUnitFailure] | None = None
    profile: ReviewProfile | None = None
    on_batch: Callable[[int, int, float], None] | None = None
    on_judgment: JudgmentProgress | None = None
    trace: Trace | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffReviewOptions:
    """Coherent option groups for one diff review."""

    roles: DiffRoleOptions = dataclasses.field(default_factory=DiffRoleOptions)
    grounding: DiffGroundingOptions = dataclasses.field(default_factory=DiffGroundingOptions)
    verification: DiffVerificationOptions = dataclasses.field(default_factory=DiffVerificationOptions)
    execution: DiffExecutionOptions = dataclasses.field(default_factory=DiffExecutionOptions)


@dataclasses.dataclass(frozen=True, kw_only=True)
class _DiffRunners:
    standard: AuditRunner | None
    adversarial: AdversarialAuditRunner | None


@dataclasses.dataclass(frozen=True, kw_only=True)
class _LocationNormalization:
    finding: Finding
    incomplete: bool = False


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _diff_path_key(path: str) -> str:
    path = path.removeprefix("./")
    return path[2:] if path[:2] in ("a/", "b/") else path


def _normalize_finding_line(
    finding: Finding,
    ranges: DiffLineRanges,
) -> _LocationNormalization:
    """Require one current hunk location and one exact old or new change anchor."""
    if finding.line is None:
        return _LocationNormalization(finding=finding, incomplete=True)
    current_ranges = ranges.current.get(_diff_path_key(finding.file), ())
    if not _line_in_ranges(finding.line, current_ranges):
        return _LocationNormalization(finding=finding, incomplete=True)
    anchor = finding.change_anchor or ChangeAnchor(file=finding.file, line=finding.line, side="new")
    anchor_ranges = ranges.new if anchor.side == "new" else ranges.old
    file_ranges = anchor_ranges.get(_diff_path_key(anchor.file), ())
    if not _line_in_ranges(anchor.line, file_ranges):
        return _LocationNormalization(finding=dataclasses.replace(finding, change_anchor=anchor), incomplete=True)
    return _LocationNormalization(finding=dataclasses.replace(finding, change_anchor=anchor))


def run_diff_review(
    diff: str,
    *,
    provider: Provider,
    model: str,
    options: DiffReviewOptions | None = None,
) -> DiffReviewResult:
    """Return findings and explicit incomplete state for one diff review."""
    return _run_diff_review(diff, provider=provider, model=model, options=options or DiffReviewOptions())


def _run_diff_review(
    diff: str,
    *,
    provider: Provider,
    model: str,
    options: DiffReviewOptions,
) -> DiffReviewResult:
    roles = options.roles
    grounding = options.grounding
    execution = options.execution
    plan = review_plan(roles.mode, max_rounds=roles.max_rounds)
    profile = execution.profile or default_profile()
    content = profile.paths
    trace = bind_trace(
        execution.trace,
        review_id=f"review-{uuid.uuid4().hex[:16]}",
        target="diff",
        mode=roles.mode,
    )
    focus, do_not_report = profile.diff_focus, profile.diff_do_not_report
    detection = load_detection(content.detection_file)
    diff, _ = strip_unreviewable_files(diff, detection)
    if not diff.strip():
        return DiffReviewResult(outcome=ReviewOutcome(findings=[]), dropped=[])
    if grounding.context_for_diff is None and not grounding.context:
        grounding = dataclasses.replace(grounding, context=diff_local_context(diff, detection=detection))
    runners = _build_runners(provider, model, roles, content, focus, do_not_report)
    review_outcome = run_batches(
        diff,
        lambda round_no, unit, known: _review_unit(
            round_no,
            unit,
            known,
            model=model,
            roles=roles,
            grounding=grounding,
            runners=runners,
            content=content,
            trace=trace,
            on_judgment=execution.on_judgment,
        ),
        plan=plan,
        accumulator=role_accumulator() if roles.mode == "adversarial" else finding_accumulator(),
        failures=execution.batch_failures,
        prepare=grounding.prepare_diff,
        concurrency=execution.concurrency,
        on_batch=execution.on_batch,
    )
    _trace_review_failure(trace, review_outcome)
    findings, location_incomplete = _normalize_findings(review_outcome.findings, diff, detection, content, trace)
    verified = _verify_candidates(findings, options.verification, trace)
    _trace_verification(verified, trace)
    outcome = extend_review_outcome(
        review_outcome,
        findings=verified.findings,
        incomplete=[*location_incomplete, *verified.incomplete],
        errors=verified.errors,
        failure_reason=verification_failure_reason(verified.error_details),
    )
    emit_trace(
        trace,
        "review_finished",
        status="incomplete" if outcome.degraded else "complete",
        findings=len(verified.findings),
        errors=outcome.errors,
        incomplete=len(outcome.incomplete),
    )
    return DiffReviewResult(outcome=outcome, dropped=verified.dropped)


def _build_runners(
    provider: Provider,
    model: str,
    roles: DiffRoleOptions,
    content: ContentPaths,
    focus: str,
    do_not_report: str,
) -> _DiffRunners:
    adversarial = (
        AdversarialAuditRunner(
            provider=provider,
            model=model,
            finder_model=roles.finder_model,
            challenger_model=roles.challenger_model,
            judge_model=roles.judge_model,
            finder_provider=roles.finder_provider,
            challenger_provider=roles.challenger_provider,
            judge_provider=roles.judge_provider,
            finder_label=roles.finder_label,
            challenger_label=roles.challenger_label,
            judge_label=roles.judge_label,
            content=content,
            focus=focus,
            do_not_report=do_not_report,
        )
        if roles.mode == "adversarial"
        else None
    )
    standard = (
        AuditRunner(provider=provider, model=model, content=content, focus=focus, do_not_report=do_not_report)
        if roles.mode == "standard"
        else None
    )
    return _DiffRunners(standard=standard, adversarial=adversarial)


def _review_unit(
    round_no: int,
    unit: DiffUnit,
    known: list[Finding],
    *,
    model: str,
    roles: DiffRoleOptions,
    grounding: DiffGroundingOptions,
    runners: _DiffRunners,
    content: ContentPaths,
    trace: Trace | None,
    on_judgment: JudgmentProgress | None,
) -> ReviewCycle[Finding]:
    grounded = _unit_grounding(unit, grounding)
    coverage = grounded.coverage if isinstance(grounded, GroundingContext) else None
    _trace_grounding(trace, coverage)
    if unit.definition_plan is not None and coverage is not None and not coverage.reviewable:
        return ReviewCycle(findings=[], errors=1, failure_reason=coverage.failure_reason, grounding=coverage)
    if roles.mode == "adversarial":
        if runners.adversarial is None:
            raise ValueError("adversarial review has no adversarial runner")
        cycle = runners.adversarial.review_round(
            unit.diff,
            context=grounded,
            stack=guides_for_diff(unit.diff, content),
            known=known,
            trace=trace,
            round_id=round_no,
        )
    else:
        if runners.standard is None:
            raise ValueError("standard review has no standard runner")
        cycle = runners.standard.review_round(
            unit.diff,
            context=grounded,
            finder_label=roles.finder_label or model,
            on_judgment=on_judgment,
            trace=trace,
        )
    if coverage is None:
        return cycle
    return dataclasses.replace(cycle, grounding=merge_grounding_coverage((coverage, cycle.grounding)))


def _unit_grounding(unit: DiffUnit, options: DiffGroundingOptions) -> GroundingContext | str:
    if unit.grounding is not None:
        return unit.grounding
    if options.context_for_diff is not None:
        return options.context_for_diff(unit.diff)
    return options.context


def _trace_grounding(trace: Trace | None, coverage: GroundingCoverage | None) -> None:
    if coverage is None:
        return
    emit_trace(
        trace,
        "grounding",
        required=list(coverage.required),
        included=list(coverage.included),
        omitted=list(coverage.missing),
        unresolved=list(coverage.unresolved),
        limitations=list(coverage.limitations),
        complete=coverage.complete,
    )


def _trace_review_failure(trace: Trace | None, review_outcome: ReviewOutcome[Finding]) -> None:
    if review_outcome.failures or review_outcome.errors or review_outcome.failure_reason:
        emit_trace(
            trace,
            "review_failed",
            errors=review_outcome.errors,
            failures=len(review_outcome.failures),
            reason=review_outcome.failure_reason[:500],
        )


def _normalize_findings(
    findings: list[Finding],
    diff: str,
    detection: Detection,
    content: ContentPaths,
    trace: Trace | None,
) -> tuple[list[Finding], list[Finding]]:
    catalog = VulnerabilityCatalog.load(content.vulnerabilities_dir)
    findings = [dataclasses.replace(f, category=catalog.close_category(f.category)) for f in findings]
    ranges = diff_line_ranges(diff, detection)
    normalized: list[Finding] = []
    incomplete: list[Finding] = []
    for before in findings:
        location = _normalize_finding_line(before, ranges)
        after = location.finding
        if location.incomplete:
            incomplete.append(after)
            emit_trace(
                trace,
                "finding",
                stage="incomplete_location",
                finding_id=finding_id(after),
                file=after.file,
                line=after.line,
                original_line=before.line,
                change_anchor=after.change_anchor.to_dict() if after.change_anchor else None,
                category=after.category,
                description=after.description[:500],
            )
            continue
        normalized.append(after)
        emit_trace(
            trace,
            "finding",
            stage="normalized",
            finding_id=finding_id(after),
            file=after.file,
            line=after.line,
            original_line=before.line,
            change_anchor=after.change_anchor.to_dict() if after.change_anchor else None,
            category=after.category,
            description=after.description[:500],
        )
    return normalized, incomplete


def _verify_candidates(
    findings: list[Finding],
    options: DiffVerificationOptions,
    trace: Trace | None,
) -> DiffVerifyResult:
    if options.verifier is not None:
        if options.root is None:
            raise ValueError("verification_root is required when verifier is set")
        return verify_diff_findings(
            findings,
            options.verifier,
            options.root,
            confirmers=options.confirmers,
            found_by=options.found_by,
            votes=options.votes,
            concurrency=options.concurrency,
            trace=trace,
        )
    return DiffVerifyResult(findings=findings, dropped=[])


def _trace_verification(verified: DiffVerifyResult, trace: Trace | None) -> None:
    for finding in verified.findings:
        emit_trace(
            trace,
            "finding",
            stage="kept",
            finding_id=finding_id(finding),
            file=finding.file,
            line=finding.line,
            category=finding.category,
        )
    for finding, reason in verified.dropped:
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


def _options_from_adapter(values: dict[str, object]) -> DiffReviewOptions:
    supported = {
        "mode",
        "max_rounds",
        "finder_model",
        "challenger_model",
        "judge_model",
        "finder_provider",
        "challenger_provider",
        "judge_provider",
        "finder_label",
        "challenger_label",
        "judge_label",
        "context",
        "context_for_diff",
        "prepare_diff",
        "verification_root",
        "verifier",
        "verification_confirmers",
        "verification_found_by",
        "verification_votes",
        "concurrency",
        "verification_concurrency",
        "batch_failures",
        "profile",
        "on_batch",
        "on_judgment",
        "trace",
    }
    unknown = sorted(set(values).difference(supported))
    if unknown:
        names = ", ".join(unknown)
        raise TypeError(f"unknown diff review arguments: {names}")
    return DiffReviewOptions(
        roles=DiffRoleOptions(
            mode=cast("str", values.get("mode", "standard")),
            max_rounds=cast(
                "int",
                values.get("max_rounds", DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds),
            ),
            finder_model=cast("str | None", values.get("finder_model")),
            challenger_model=cast("str | None", values.get("challenger_model")),
            judge_model=cast("str | None", values.get("judge_model")),
            finder_provider=cast("Provider | None", values.get("finder_provider")),
            challenger_provider=cast("Provider | None", values.get("challenger_provider")),
            judge_provider=cast("Provider | None", values.get("judge_provider")),
            finder_label=cast("str | None", values.get("finder_label")),
            challenger_label=cast("str | None", values.get("challenger_label")),
            judge_label=cast("str | None", values.get("judge_label")),
        ),
        grounding=DiffGroundingOptions(
            context=cast("GroundingContext | str", values.get("context", "")),
            context_for_diff=cast("Callable[[str], GroundingContext | str] | None", values.get("context_for_diff")),
            prepare_diff=cast("Callable[[str], list[DiffUnit]] | None", values.get("prepare_diff")),
        ),
        verification=DiffVerificationOptions(
            root=cast("str | None", values.get("verification_root")),
            verifier=cast("Verifier | None", values.get("verifier")),
            confirmers=cast("list[Confirmer] | None", values.get("verification_confirmers")),
            found_by=cast("tuple[str, ...]", values.get("verification_found_by", ())),
            votes=cast(
                "int",
                values.get("verification_votes", DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required),
            ),
            concurrency=cast(
                "int",
                values.get(
                    "verification_concurrency",
                    DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
                ),
            ),
        ),
        execution=DiffExecutionOptions(
            concurrency=cast("int", values.get("concurrency", DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency)),
            batch_failures=cast("list[ReviewUnitFailure] | None", values.get("batch_failures")),
            profile=cast("ReviewProfile | None", values.get("profile")),
            on_batch=cast("Callable[[int, int, float], None] | None", values.get("on_batch")),
            on_judgment=cast("JudgmentProgress | None", values.get("on_judgment")),
            trace=cast("Trace | None", values.get("trace")),
        ),
    )


def audit_diff(
    diff: str,
    *,
    provider: Provider,
    model: str,
    **adapter_options: object,
) -> tuple[list[Finding], list[tuple[Finding, str]], bool]:
    """Expose the tuple outcome for callers that do not need completion details."""
    result = run_diff_review(
        diff,
        provider=provider,
        model=model,
        options=_options_from_adapter(adapter_options),
    )
    return result.outcome.findings, result.dropped, result.outcome.degraded
