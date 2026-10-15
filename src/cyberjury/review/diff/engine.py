"""Compose diff adapters around the shared review engine."""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable

from cyberjury.detection import Detection, load_detection
from cyberjury.finding import Finding
from cyberjury.profiles.base import ReviewProfile, bind_profile_content, profile_binding
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.providers.metering import UsageMeter
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
    merge_grounding_coverage,
    source_location_receipt,
)
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
    canonical_diff_path,
    diff_line_ranges,
    has_diff_hunk,
    strip_unreviewable_files,
)
from cyberjury.review.diff.reviewer import AuditRunner
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import finding_accumulator
from cyberjury.review.diff.verify import DiffVerifyResult, verify_diff_findings
from cyberjury.review.engine import (
    JudgmentProgress,
    ReviewCycle,
    ReviewOutcome,
    extend_review_outcome,
)
from cyberjury.review.knowledge import load_review_brief
from cyberjury.review.navigation import SourceNavigator, bind_source_operation
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS, positive_concurrency
from cyberjury.review.trace import Trace, bind_trace, emit_trace, finding_id
from cyberjury.review.verification import Confirmer, VerificationRecord, Verifier, verification_failure_reason
from cyberjury.sources.snapshot import SourceSnapshot


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffReviewResult:
    """The complete outcome with verification decisions."""

    outcome: ReviewOutcome[Finding]
    dropped: list[tuple[Finding, str]]
    verification_records: list[VerificationRecord] = dataclasses.field(default_factory=list)
    verification_candidate_ids: tuple[str, ...] = ()
    usage: dict[str, int] | None = None
    model_calls: list[dict[str, object]] = dataclasses.field(default_factory=list)
    findings_artifact: FindingsArtifact | None = None
    outcome_artifact: OutcomeArtifact | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffGroundingOptions:
    """Repository unit preparation for one diff review."""

    prepare_diff: Callable[[str], list[DiffUnit]]
    source_snapshot: SourceSnapshot | None = None
    navigator: SourceNavigator | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffVerificationOptions:
    """Candidate verification route and concurrency."""

    root: str | None = None
    verifier: Verifier | None = None
    confirmers: tuple[Confirmer, ...] | None = None
    found_by: tuple[str, ...] = ()
    concurrency: int = DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency

    def __post_init__(self) -> None:
        """Keep confirmer ownership stable after option construction."""
        if self.confirmers is not None and not isinstance(self.confirmers, tuple):
            object.__setattr__(self, "confirmers", tuple(self.confirmers))
        if not isinstance(self.found_by, tuple):
            object.__setattr__(self, "found_by", tuple(self.found_by))


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffExecutionOptions:
    """Batch scheduling, progress, profile, and trace hooks."""

    concurrency: int = DEFAULT_REVIEW_SETTINGS.diff.default_batch_concurrency
    profile: ReviewProfile | None = None
    on_batch: Callable[[int, int, float], None] | None = None
    on_judgment: JudgmentProgress | None = None
    trace: Trace | None = None
    meter: UsageMeter | None = None


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffReviewOptions:
    """Coherent option groups for one diff review."""

    grounding: DiffGroundingOptions
    verification: DiffVerificationOptions = dataclasses.field(default_factory=DiffVerificationOptions)
    execution: DiffExecutionOptions = dataclasses.field(default_factory=DiffExecutionOptions)


@dataclasses.dataclass(frozen=True, kw_only=True)
class _LocationNormalization:
    finding: Finding
    incomplete: bool = False
    primary_receipt: str = ""
    failure_reason: str = ""


def _validate_diff_options(model: str, options: DiffReviewOptions) -> None:
    if not isinstance(model, str) or not model.strip():
        raise ValueError("diff review model must be a nonempty string")
    positive_concurrency(options.execution.concurrency, "review concurrency")
    positive_concurrency(options.verification.concurrency, "verification concurrency")
    if not callable(options.grounding.prepare_diff):
        raise ValueError("repository diff preparation is required")
    if options.verification.verifier is not None and options.verification.root is None:
        raise ValueError("verification_root is required when verifier is set")


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _normalize_finding_line(
    finding: Finding,
    ranges: DiffLineRanges,
    source_evidence: tuple[SourceEvidence, ...] = (),
    seed_spans: tuple[SourceSpan, ...] = (),
) -> _LocationNormalization:
    """Require one evidenced post change location and one exact change anchor."""
    if finding.line is None:
        return _LocationNormalization(finding=finding, incomplete=True, failure_reason="primary line is missing")
    current_path = canonical_diff_path(finding.file, ranges.current)
    current_ranges = ranges.current.get(current_path, ())
    receipt = source_location_receipt(
        file=finding.file,
        line=finding.line,
        evidence_refs=finding.evidence_refs,
        seed_spans=seed_spans,
        source_evidence=source_evidence,
    )
    primary_in_patch = _line_in_ranges(finding.line, current_ranges)
    if not primary_in_patch and receipt is None:
        return _LocationNormalization(
            finding=finding,
            incomplete=True,
            failure_reason="primary location has no current patch line or cited source receipt",
        )
    canonical_finding = dataclasses.replace(
        finding,
        file=current_path if primary_in_patch else receipt.file,
    )
    anchor = finding.change_anchor
    if anchor is None:
        return _LocationNormalization(
            finding=canonical_finding,
            incomplete=True,
            primary_receipt="patch" if primary_in_patch else receipt.evidence_ref,
            failure_reason="change anchor is missing",
        )
    anchor_ranges = ranges.new if anchor.side == "new" else ranges.old
    anchor_file = canonical_diff_path(anchor.file, anchor_ranges)
    canonical_anchor = dataclasses.replace(anchor, file=anchor_file)
    file_ranges = anchor_ranges.get(anchor_file, ())
    if not _line_in_ranges(anchor.line, file_ranges):
        return _LocationNormalization(
            finding=dataclasses.replace(canonical_finding, change_anchor=canonical_anchor),
            incomplete=True,
            primary_receipt="patch" if primary_in_patch else receipt.evidence_ref,
            failure_reason="change anchor is not an exact changed line on its declared side",
        )
    return _LocationNormalization(
        finding=dataclasses.replace(canonical_finding, change_anchor=canonical_anchor),
        primary_receipt="patch" if primary_in_patch else receipt.evidence_ref,
    )


def run_diff_review(
    diff: str,
    *,
    provider: Provider,
    model: str,
    options: DiffReviewOptions,
    finder_label: str | None = None,
) -> DiffReviewResult:
    """Return findings and explicit incomplete state for one diff review."""
    _validate_diff_options(model, options)
    grounding = options.grounding
    execution = options.execution
    profile = bind_profile_content(execution.profile or default_profile())
    bound_profile = profile_binding(profile)
    content = profile.paths
    trace = bind_trace(
        execution.trace,
        review_id=f"review-{uuid.uuid4().hex[:16]}",
        target="diff",
    )
    detection = load_detection(content.detection_file)
    diff, _ = strip_unreviewable_files(diff, detection)
    if not diff.strip():
        outcome = ReviewOutcome(
            findings=(),
            scheduling=SchedulingReceipt.empty(stop_reason="no_reviewable_units"),
        )
        emit_trace(
            trace,
            "review_finished",
            status="complete",
            findings=0,
            errors=0,
            incomplete=0,
        )
        usage = execution.meter.snapshot() if execution.meter is not None else None
        if profile_binding(profile).profile_sha256 != bound_profile.profile_sha256:
            raise ValueError("review profile changed while the diff review was running")
        return DiffReviewResult(
            outcome=outcome,
            dropped=[],
            verification_records=[],
            verification_candidate_ids=(),
            usage=usage,
            model_calls=execution.meter.call_snapshot() if execution.meter is not None else [],
        )
    if not has_diff_hunk(diff):
        raise ValueError("diff review input is nonempty but contains no unified diff hunk")
    runner = AuditRunner(
        provider=provider,
        model=model,
        content=content,
        review_brief=load_review_brief(kernel_file=content.security_kernel_file),
    )
    review_outcome = run_batches(
        diff,
        lambda unit: _review_unit(
            unit,
            runner=runner,
            finder_label=finder_label or model,
            detection=detection,
            trace=trace,
            on_judgment=execution.on_judgment,
        ),
        accumulator=finding_accumulator(),
        prepare=grounding.prepare_diff,
        concurrency=execution.concurrency,
        on_batch=execution.on_batch,
    )
    _trace_review_failure(trace, review_outcome)
    findings = review_outcome.findings
    _trace_normalized(findings, trace)
    verified = _verify_candidates(
        findings,
        options.verification,
        trace,
        source_snapshot=options.grounding.source_snapshot,
    )
    _trace_verification(verified, trace)
    outcome = extend_review_outcome(
        review_outcome,
        findings=verified.findings,
        incomplete=verified.incomplete,
        errors=verified.errors,
        failure_reason=verification_failure_reason(verified.error_details),
    )
    usage = execution.meter.snapshot() if execution.meter is not None else None
    if profile_binding(profile).profile_sha256 != bound_profile.profile_sha256:
        raise ValueError("review profile changed while the diff review was running")
    emit_trace(
        trace,
        "review_finished",
        status="incomplete" if outcome.degraded else "complete",
        findings=len(verified.findings),
        errors=outcome.errors,
        incomplete=len(outcome.incomplete),
        source_revision=(
            options.grounding.source_snapshot.snapshot_id if options.grounding.source_snapshot is not None else ""
        ),
        usage=usage or {},
    )
    return DiffReviewResult(
        outcome=outcome,
        dropped=verified.dropped,
        verification_records=verified.records,
        verification_candidate_ids=verified.candidate_ids,
        usage=usage,
        model_calls=execution.meter.call_snapshot() if execution.meter is not None else [],
    )


def _review_unit(
    unit: DiffUnit,
    *,
    runner: AuditRunner,
    finder_label: str,
    detection: Detection,
    trace: Trace | None,
    on_judgment: JudgmentProgress | None,
) -> ReviewCycle[Finding]:
    grounded = _unit_grounding(unit)
    coverage = grounded.coverage
    _trace_grounding(trace, coverage)
    if unit.definition_plan is not None and coverage is not None and not coverage.reviewable:
        return ReviewCycle(findings=[], errors=1, failure_reason=coverage.failure_reason, grounding=coverage)
    cycle = runner.review_unit(
        unit.diff,
        context=grounded,
        finder_label=finder_label,
        on_judgment=on_judgment,
        trace=trace,
    )
    cycle = _validate_unit_locations(cycle, unit, detection, grounded, trace)
    cycle = _bind_unit_operations(cycle, grounded, trace)
    if coverage is None:
        return cycle
    return dataclasses.replace(cycle, grounding=merge_grounding_coverage((coverage, cycle.grounding)))


def _bind_unit_operations(
    cycle: ReviewCycle[Finding],
    grounding: GroundingContext,
    trace: Trace | None,
) -> ReviewCycle[Finding]:
    """Bind report lines to exact callsites without inferring ambiguous operations."""
    session = grounding.navigator.session() if grounding.navigator is not None else None
    findings = [bind_source_operation(finding, session) for finding in cycle.findings]
    for before, after in zip(cycle.findings, findings, strict=True):
        if after.source_operation_id and after.source_operation_id != before.source_operation_id:
            emit_trace(
                trace,
                "finding",
                stage="source_operation_bound",
                finding_id=after.candidate_id,
                source_operation_id=after.source_operation_id,
                file=after.file,
                line=after.line,
            )
    return dataclasses.replace(cycle, findings=findings)


def _validate_unit_locations(
    cycle: ReviewCycle[Finding],
    unit: DiffUnit,
    detection: Detection,
    grounding: GroundingContext,
    trace: Trace | None,
) -> ReviewCycle[Finding]:
    """Validate location provenance before findings leave their review unit."""
    ranges = diff_line_ranges(unit.diff, detection)
    findings: list[Finding] = []
    incomplete = list(cycle.incomplete)
    evidence = tuple(dict.fromkeys((*grounding.source_evidence, *cycle.source_evidence)))
    for finding in cycle.findings:
        location = _normalize_finding_line(finding, ranges, evidence, grounding.source_spans)
        if location.incomplete:
            incomplete.append(location.finding)
            emit_trace(
                trace,
                "finding",
                stage="location_incomplete",
                finding_id=finding_id(location.finding),
                file=location.finding.file,
                line=location.finding.line,
                primary_receipt=location.primary_receipt,
                change_anchor=(
                    location.finding.change_anchor.to_dict() if location.finding.change_anchor is not None else None
                ),
                reason=location.failure_reason,
            )
        else:
            findings.append(location.finding)
            emit_trace(
                trace,
                "finding",
                stage="location_validated",
                finding_id=finding_id(location.finding),
                file=location.finding.file,
                line=location.finding.line,
                primary_receipt=location.primary_receipt,
                change_anchor=location.finding.change_anchor.to_dict(),
            )
    if len(findings) == len(cycle.findings):
        return cycle if findings == cycle.findings else dataclasses.replace(cycle, findings=findings)
    reason = "one or more findings lack a current unit location receipt or exact change anchor"
    return dataclasses.replace(
        cycle,
        findings=findings,
        incomplete=incomplete,
        failure_reason=". ".join(part for part in (cycle.failure_reason, reason) if part),
    )


def _unit_grounding(unit: DiffUnit) -> GroundingContext:
    if unit.grounding is not None:
        return unit.grounding
    raise ValueError("repository grounding is missing from the prepared diff unit")


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


def _trace_normalized(findings: list[Finding], trace: Trace | None) -> None:
    for finding in findings:
        emit_trace(
            trace,
            "finding",
            stage="normalized",
            finding_id=finding_id(finding),
            file=finding.file,
            line=finding.line,
            change_anchor=finding.change_anchor.to_dict() if finding.change_anchor else None,
            category=finding.category,
            description=finding.description[:500],
        )


def _verify_candidates(
    findings: list[Finding],
    options: DiffVerificationOptions,
    trace: Trace | None,
    *,
    source_snapshot: SourceSnapshot | None,
) -> DiffVerifyResult:
    if options.verifier is not None:
        return verify_diff_findings(
            findings,
            options.verifier,
            options.root,
            confirmers=options.confirmers,
            found_by=options.found_by,
            concurrency=options.concurrency,
            trace=trace,
            source_snapshot=source_snapshot,
        )
    return DiffVerifyResult(
        findings=findings,
        dropped=[],
        candidate_ids=tuple(finding_id(finding) for finding in findings),
    )


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
