"""Compose diff adapters around the shared review engine."""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable
from typing import cast

from cyberjury.detection import Detection, load_detection, load_patch_syntax
from cyberjury.finding import Finding
from cyberjury.profiles.base import ContentPaths, ReviewProfile
from cyberjury.profiles.registry import default_profile
from cyberjury.providers.base import Provider
from cyberjury.review.consolidation import (
    ConsolidationResult,
    CoveredFinding,
    consolidate_verified_findings,
    consolidation_failure_reason,
)
from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    merge_grounding_coverage,
    source_location_is_grounded,
)
from cyberjury.review.diff.model import (
    DiffLineRanges,
    DiffUnit,
    diff_line_ranges,
    diff_local_context,
    has_diff_hunk,
    strip_unreviewable_files,
)
from cyberjury.review.diff.reviewer import AdversarialAuditRunner, AuditRunner, guides_for_diff
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import finding_accumulator, role_accumulator
from cyberjury.review.diff.verify import DiffVerifyResult, verify_diff_findings
from cyberjury.review.engine import (
    JudgmentProgress,
    PendingWorkRecord,
    ReviewCycle,
    ReviewOutcome,
    extend_review_outcome,
    review_schedule,
)
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.trace import Trace, bind_trace, emit_trace, finding_id
from cyberjury.review.verification import Confirmer, Verifier, verification_failure_reason
from cyberjury.review.vulnerabilities import VulnerabilityCatalog


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffReviewResult:
    """The complete outcome with rejected and coverage folded findings separated."""

    outcome: ReviewOutcome[Finding]
    dropped: list[tuple[Finding, str]]
    covered: list[CoveredFinding[Finding]] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True, kw_only=True)
class DiffRoleOptions:
    """Role seats and convergence settings for one diff review."""

    mode: str = "standard"
    max_rounds: int | None = None
    finder_model: str | None = None
    challenger_model: str | None = None
    judge_model: str | None = None
    finder_provider: Provider | None = None
    challenger_provider: Provider | None = None
    judge_provider: Provider | None = None
    finder_label: str | None = None
    challenger_label: str | None = None
    judge_label: str | None = None

    def __post_init__(self) -> None:
        """Make the configured round cap match the selected mode."""
        if self.max_rounds is None:
            rounds = 1 if self.mode == "standard" else DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
            object.__setattr__(self, "max_rounds", rounds)


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
    confirmers: tuple[Confirmer, ...] | None = None
    found_by: tuple[str, ...] = ()
    votes: int = DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required
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


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_diff_options(model: str, options: DiffReviewOptions) -> None:
    if not isinstance(model, str) or not model.strip():
        raise ValueError("diff review model must be a nonempty string")
    _positive_integer(options.execution.concurrency, "review concurrency")
    _positive_integer(options.verification.votes, "verification votes")
    _positive_integer(options.verification.concurrency, "verification concurrency")
    if options.verification.verifier is not None and options.verification.root is None:
        raise ValueError("verification_root is required when verifier is set")
    if options.verification.confirmers is not None:
        for index, confirmer in enumerate(options.verification.confirmers):
            if (
                not isinstance(confirmer, tuple)
                or len(confirmer) != 2
                or not isinstance(confirmer[0], str)
                or not callable(getattr(confirmer[1], "holds", None))
            ):
                raise ValueError(f"verification confirmer {index + 1} is invalid")


def _line_in_ranges(line: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def _diff_path_key(path: str) -> str:
    path = path.removeprefix("./")
    return path[2:] if path[:2] in ("a/", "b/") else path


def _normalize_finding_line(
    finding: Finding,
    ranges: DiffLineRanges,
    source_evidence: tuple[SourceEvidence, ...] = (),
) -> _LocationNormalization:
    """Require one evidenced post change location and one exact change anchor."""
    if finding.line is None:
        return _LocationNormalization(finding=finding, incomplete=True)
    current_ranges = ranges.current.get(_diff_path_key(finding.file), ())
    grounded_location = source_location_is_grounded(
        file=finding.file,
        line=finding.line,
        evidence_refs=finding.evidence_refs,
        source_evidence=source_evidence,
    )
    if not _line_in_ranges(finding.line, current_ranges) and not grounded_location:
        return _LocationNormalization(finding=finding, incomplete=True)
    anchor = finding.change_anchor
    if anchor is None:
        return _LocationNormalization(finding=finding, incomplete=True)
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
    _validate_diff_options(model, options)
    roles = options.roles
    grounding = options.grounding
    execution = options.execution
    plan = review_schedule(roles.mode, max_rounds=cast("int", roles.max_rounds))
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
    patch_syntax = load_patch_syntax(content.detection_file)
    diff, _ = strip_unreviewable_files(diff, detection)
    if not diff.strip():
        outcome = ReviewOutcome(findings=(), requires_convergence=False)
        emit_trace(
            trace,
            "review_finished",
            status="complete",
            findings=0,
            errors=0,
            incomplete=0,
        )
        return DiffReviewResult(outcome=outcome, dropped=[], covered=[])
    if not has_diff_hunk(diff):
        raise ValueError("diff review input is nonempty but contains no unified diff hunk")
    if grounding.context_for_diff is None and not grounding.context:
        grounding = dataclasses.replace(
            grounding,
            context_for_diff=lambda unit_diff: diff_local_context(
                unit_diff,
                detection=detection,
                patch_syntax=patch_syntax,
            ),
        )
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
            detection=detection,
            trace=trace,
            on_judgment=execution.on_judgment,
        ),
        plan=plan,
        execute_pending=lambda round_no, unit, known, pending: _review_unit(
            round_no,
            unit,
            known,
            pending=pending,
            model=model,
            roles=roles,
            grounding=grounding,
            runners=runners,
            content=content,
            detection=detection,
            trace=trace,
            on_judgment=execution.on_judgment,
        ),
        accumulator=role_accumulator() if roles.mode == "adversarial" else finding_accumulator(),
        prepare=grounding.prepare_diff,
        concurrency=execution.concurrency,
        on_batch=execution.on_batch,
    )
    _trace_review_failure(trace, review_outcome)
    findings = _normalize_findings(review_outcome.findings, content, trace)
    verified = _verify_candidates(findings, options.verification, trace)
    _trace_verification(verified, trace)
    consolidated = _consolidate_candidates(
        verified,
        provider,
        model,
        roles,
        trace,
        enabled=options.verification.verifier is not None,
    )
    outcome = extend_review_outcome(
        review_outcome,
        findings=consolidated.findings,
        incomplete=verified.incomplete,
        errors=verified.errors + consolidated.errors,
        failure_reason=". ".join(
            reason
            for reason in (
                verification_failure_reason(verified.error_details),
                consolidation_failure_reason(consolidated.error_details),
            )
            if reason
        ),
    )
    emit_trace(
        trace,
        "review_finished",
        status="incomplete" if outcome.degraded else "complete",
        findings=len(consolidated.findings),
        errors=outcome.errors,
        incomplete=len(outcome.incomplete),
    )
    return DiffReviewResult(outcome=outcome, dropped=verified.dropped, covered=consolidated.covered)


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
        AuditRunner(
            provider=roles.finder_provider or provider,
            model=roles.finder_model or model,
            content=content,
            focus=focus,
            do_not_report=do_not_report,
        )
        if roles.mode == "standard"
        else None
    )
    return _DiffRunners(standard=standard, adversarial=adversarial)


def _review_unit(
    round_no: int,
    unit: DiffUnit,
    known: list[Finding],
    *,
    pending: tuple[PendingWorkRecord, ...] = (),
    model: str,
    roles: DiffRoleOptions,
    grounding: DiffGroundingOptions,
    runners: _DiffRunners,
    content: ContentPaths,
    detection: Detection,
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
            pending=pending,
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
    cycle = _validate_unit_locations(cycle, unit, detection, grounded)
    if coverage is None:
        return cycle
    return dataclasses.replace(cycle, grounding=merge_grounding_coverage((coverage, cycle.grounding)))


def _validate_unit_locations(
    cycle: ReviewCycle[Finding],
    unit: DiffUnit,
    detection: Detection,
    grounding: GroundingContext | str,
) -> ReviewCycle[Finding]:
    """Validate location provenance before findings leave their review unit."""
    ranges = diff_line_ranges(unit.diff, detection)
    findings: list[Finding] = []
    incomplete = list(cycle.incomplete)
    initial_evidence = grounding.source_evidence if isinstance(grounding, GroundingContext) else ()
    evidence = tuple(dict.fromkeys((*initial_evidence, *cycle.source_evidence)))
    for finding in cycle.findings:
        location = _normalize_finding_line(finding, ranges, evidence)
        if location.incomplete:
            incomplete.append(location.finding)
        else:
            findings.append(location.finding)
    if len(findings) == len(cycle.findings):
        return cycle
    reason = "one or more findings lack a current unit location receipt or exact change anchor"
    return dataclasses.replace(
        cycle,
        findings=findings,
        incomplete=incomplete,
        failure_reason=". ".join(part for part in (cycle.failure_reason, reason) if part),
    )


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
    content: ContentPaths,
    trace: Trace | None,
) -> list[Finding]:
    catalog = VulnerabilityCatalog.load(content.vulnerabilities_dir)
    findings = [dataclasses.replace(f, category=catalog.close_category(f.category)) for f in findings]
    for finding in findings:
        emit_trace(
            trace,
            "finding",
            stage="normalized",
            finding_id=finding_id(finding),
            file=finding.file,
            line=finding.line,
            original_line=finding.line,
            change_anchor=finding.change_anchor.to_dict() if finding.change_anchor else None,
            category=finding.category,
            description=finding.description[:500],
        )
    return findings


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


def _finding_coverage_record(finding: Finding) -> dict[str, object]:
    """Expose only the evidence needed to compare verified attack paths."""
    return {
        "category": finding.category,
        "file": finding.file,
        "line": finding.line,
        "description": finding.description,
        "exploit_scenario": finding.exploit_scenario,
        "recommendation": finding.recommendation,
        "change_anchor": finding.change_anchor.to_dict() if finding.change_anchor else None,
    }


def _consolidate_candidates(
    verified: DiffVerifyResult,
    provider: Provider,
    model: str,
    roles: DiffRoleOptions,
    trace: Trace | None,
    *,
    enabled: bool,
) -> ConsolidationResult[Finding]:
    """Consolidate only a complete set of verified diff findings."""
    if not enabled or verified.errors or verified.incomplete:
        return ConsolidationResult(findings=verified.findings)
    result = consolidate_verified_findings(
        verified.findings,
        provider=roles.judge_provider or provider,
        model=roles.judge_model or model,
        record=_finding_coverage_record,
    )
    for item in result.covered:
        emit_trace(
            trace,
            "finding",
            stage="covered",
            finding_id=finding_id(item.finding),
            file=item.finding.file,
            line=item.finding.line,
            category=item.finding.category,
            reason=item.reason[:500],
        )
    return result


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
                "int | None",
                values.get("max_rounds"),
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
            confirmers=cast("tuple[Confirmer, ...] | None", values.get("verification_confirmers")),
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
    return list(result.outcome.findings), result.dropped, result.outcome.degraded
