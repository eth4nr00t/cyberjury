"""Shared judgment orchestration for every review target."""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from threading import Lock
from time import perf_counter
from typing import Literal, TypedDict

from cyberjury.json_parse import extract_json_object
from cyberjury.review.context import (
    EvidencePromptContext,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    merge_grounding_coverage,
    select_evidence,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.navigation import SourceNavigationError, SourceNavigationSession
from cyberjury.review.provenance import label_judged, tag_found_by
from cyberjury.review.trace import Trace, emit_trace
from cyberjury.severity import median


class RoleResponseError(RuntimeError):
    """A role reply cannot support a complete judgment."""


type RoleReply = dict[str, object]


class RebuttalRecord(TypedDict, total=False):
    """A Challenger objection to one finder candidate."""

    title: str
    finding: str
    reason: str
    evidence: str


class PendingWorkRecord(TypedDict, total=False):
    """A role request for dynamic or off-model investigation."""

    title: str
    file: str
    line: int
    reason: str
    suggested_check: str


def parse_role_response(
    text: str,
    *,
    role: str,
    required_keys: tuple[str, ...],
    optional_list_keys: tuple[str, ...] = (),
) -> RoleReply:
    """Require the role contract so malformed output cannot become a clean result."""
    obj = extract_json_object(text)
    missing = [key for key in required_keys if obj is None or key not in obj]
    if missing:
        fields = ", ".join(missing)
        raise RoleResponseError(f"{role} reply had no usable JSON object with required fields: {fields}")
    invalid = [key for key in required_keys if not isinstance(obj[key], list)]
    if invalid:
        fields = ", ".join(invalid)
        raise RoleResponseError(f"{role} reply had non-list required fields: {fields}")
    invalid_optional = [key for key in optional_list_keys if key in obj and not isinstance(obj[key], list)]
    if invalid_optional:
        fields = ", ".join(invalid_optional)
        raise RoleResponseError(f"{role} reply had non-list optional fields: {fields}")
    return obj


ReviewMode = Literal["standard", "adversarial"]
CompletionPolicy = Literal["single", "converge"]
JudgmentProgress = Callable[[int, int, str, float], None]


@dataclass(frozen=True, kw_only=True)
class ReviewPlan:
    """The role depth and coded stopping policy for one review run."""

    mode: ReviewMode
    max_rounds: int
    min_rounds: int = 1
    converge_after: int = 2
    completion: CompletionPolicy | None = None
    stop_on_failure: bool = True

    def __post_init__(self) -> None:
        """Reject invalid public plans before a scheduler can consume them."""
        if self.mode not in {"standard", "adversarial"}:
            raise ValueError(f"unknown review mode {self.mode!r}")
        completion = (
            self.completion if self.completion is not None else ("single" if self.mode == "standard" else "converge")
        )
        if completion not in {"single", "converge"}:
            raise ValueError(f"unknown review completion policy {completion!r}")
        object.__setattr__(self, "completion", completion)
        values = {
            "max_rounds": self.max_rounds,
            "min_rounds": self.min_rounds,
            "converge_after": self.converge_after,
        }
        invalid = [name for name, value in values.items() if value < 1]
        if invalid:
            raise ValueError(f"review plan values must be positive: {', '.join(invalid)}")
        if self.min_rounds > self.max_rounds:
            raise ValueError("review plan min_rounds cannot exceed max_rounds")


def review_plan(
    mode: str,
    *,
    max_rounds: int,
    min_rounds: int = 1,
    converge_after: int = 2,
    completion: CompletionPolicy | None = None,
    stop_on_failure: bool = True,
) -> ReviewPlan:
    """Validate one target policy before any model work begins."""
    return ReviewPlan(
        mode=mode,
        max_rounds=max_rounds,
        min_rounds=min_rounds,
        converge_after=converge_after,
        completion=completion,
        stop_on_failure=stop_on_failure,
    )


@dataclass(frozen=True, kw_only=True)
class RoleChallenge[T]:
    """The Challenger rebuttals and independently found candidates."""

    rebuttals: list[RebuttalRecord]
    new_findings: list[T]


@dataclass(frozen=True, kw_only=True)
class RoleJudgment[T]:
    """The Judge survivors and work that still needs investigation."""

    findings: list[T]
    pending: list[PendingWorkRecord] = field(default_factory=list)

    @property
    def investigate(self) -> list[PendingWorkRecord]:
        """Expose pending dynamic checks under the result API name."""
        return self.pending


@dataclass(frozen=True, kw_only=True)
class EvidenceJudgment[T]:
    """Findings and grounding receipt from one bounded evidence exchange."""

    findings: list[T]
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    failure_reason: str = ""
    prompt_context: str = ""
    prompt_controls: str = ""


def run_evidence_judgment[T](
    context: GroundingContext,
    *,
    ask: Callable[[EvidencePromptContext], RoleReply],
    findings_from_reply: Callable[[RoleReply], list[T]],
    accumulator: FindingAccumulator[T],
    target_chars: int,
    max_followups: int = 1,
    evidence_refs: Callable[[T], tuple[str, ...]] | None = None,
    trace: Trace | None = None,
    judgment_id: int | None = None,
) -> EvidenceJudgment[T]:
    """Run bounded evidence and source navigation without losing earlier findings."""
    if max_followups < 1:
        raise ValueError("max_followups must be positive")
    prompt = _with_request_budget(context.prompt, max_followups)
    coverage = context.coverage
    available_refs = {"seed", *coverage.references}
    findings: list[T] = []
    navigation = context.navigator.session() if context.navigator is not None else None
    for exchange in range(max_followups + 1):
        try:
            reply = ask(prompt)
            parsed = findings_from_reply(reply)
            requested = reply.get("evidence_requests", [])
            source_queries = reply.get("source_queries", [])
            if not isinstance(requested, list):
                raise EvidenceRequestError("evidence_requests must be a list")
            if not isinstance(source_queries, list):
                raise SourceNavigationError("source_queries must be a list")
            requested = list(requested)
            source_queries = list(source_queries)
            if evidence_refs is not None:
                requested, source_queries = _implicit_reference_requests(
                    parsed,
                    evidence_refs=evidence_refs,
                    available=available_refs,
                    evidence_ids={item.id for item in context.evidence},
                    navigation=navigation,
                    evidence_requests=requested,
                    source_queries=source_queries,
                )
                parsed, deferred = _partition_evidence_bound_findings(
                    parsed,
                    evidence_refs=evidence_refs,
                    available=available_refs,
                    requested=_requested_reference_ids(requested, source_queries),
                )
            else:
                deferred = []
            accumulator.add(parsed)
        except Exception as exc:
            if exchange == 0:
                raise
            return EvidenceJudgment(
                findings=findings,
                grounding=merge_grounding_coverage(
                    (coverage, GroundingCoverage(unresolved=(f"evidence exchange {exchange + 1} failed",)))
                ),
                failure_reason=_failure_reason(exc),
                prompt_context=prompt.source,
                prompt_controls=prompt.controls,
            )
        findings = accumulator.findings
        if not requested and not source_queries:
            return EvidenceJudgment(
                findings=findings,
                grounding=coverage,
                prompt_context=prompt.source,
                prompt_controls=prompt.controls,
            )
        if exchange == max_followups:
            unresolved = ("source navigation round limit reached",)
            emit_trace(
                trace,
                "navigation",
                stage="limit_reached",
                judgment=judgment_id,
                exchange=exchange + 1,
                requests=source_queries if isinstance(source_queries, list) else [],
            )
            return EvidenceJudgment(
                findings=findings,
                grounding=merge_grounding_coverage((coverage, GroundingCoverage(unresolved=unresolved))),
                failure_reason=f"finder requested evidence after {max_followups} follow ups",
                prompt_context=prompt.source,
                prompt_controls=prompt.controls,
            )
        blocks: list[str] = []
        try:
            if requested:
                selected = select_evidence(context.evidence, requested, target_chars=target_chars)
                selected_coverage = replace(selected.coverage, references=tuple(requested))
                coverage = merge_grounding_coverage((coverage, selected_coverage))
                available_refs.update(requested)
                blocks.append(f"Requested exact repository evidence:\n{selected.text}")
                emit_trace(
                    trace,
                    "evidence",
                    stage="delivered",
                    judgment=judgment_id,
                    ids=list(requested),
                    identities=list(selected.coverage.included),
                    characters=len(selected.text),
                )
            if source_queries:
                if navigation is None:
                    raise SourceNavigationError("source_queries are unavailable for this judgment")
                navigated = navigation.execute(source_queries, target_chars=target_chars)
                coverage = merge_grounding_coverage((coverage, navigated.coverage))
                available_refs.update(navigated.coverage.references)
                blocks.append(navigated.text)
                emit_trace(
                    trace,
                    "navigation",
                    stage="delivered",
                    judgment=judgment_id,
                    exchange=exchange + 1,
                    requests=source_queries,
                    queries=len(source_queries) if isinstance(source_queries, list) else 0,
                    identities=list(navigated.coverage.included),
                    characters=len(navigated.text),
                )
        except (EvidenceRequestError, SourceNavigationError) as exc:
            unresolved = tuple(item for item in requested if isinstance(item, str))
            if not unresolved:
                unresolved = (f"source navigation exchange {exchange + 1}",)
            return EvidenceJudgment(
                findings=findings,
                grounding=merge_grounding_coverage((coverage, GroundingCoverage(unresolved=unresolved))),
                failure_reason=str(exc),
                prompt_context=prompt.source,
                prompt_controls=prompt.controls,
            )
        prompt = EvidencePromptContext(
            source=prompt.source,
            controls=(
                f"{prompt.controls}\n\nSource navigation exchange {exchange + 1}:\n"
                + "\n\n".join(blocks)
                + "\n\n"
                + _request_budget_instruction(max_followups - exchange - 1)
                + (
                    f" {len(deferred)} provisional finding or findings cited evidence requested in the prior "
                    "reply and were not accepted. Reassess and return them again only if the delivered source "
                    "supports them."
                    if deferred
                    else ""
                )
            ),
        )
    raise AssertionError("unreachable source navigation loop")


def _with_request_budget(prompt: EvidencePromptContext, remaining: int) -> EvidencePromptContext:
    """Publish the bounded request budget outside the source evidence block."""
    instruction = _request_budget_instruction(remaining)
    controls = f"{prompt.controls}\n\n{instruction}" if prompt.controls else instruction
    return EvidencePromptContext(source=prompt.source, controls=controls)


def _request_budget_instruction(remaining: int) -> str:
    """Tell the model whether another evidence request can be fulfilled."""
    if remaining == 0:
        return (
            "No evidence or source request batches remain. Return the final judgment using only source "
            "already delivered. Empty both `evidence_requests` and `source_queries`. A further request "
            "makes this judgment incomplete."
        )
    label = "batch remains" if remaining == 1 else "batches remain"
    return (
        f"Evidence request budget: {remaining} request {label}. Batch every independent request that can "
        "be named from the current evidence into one response. Return empty `evidence_requests` and "
        "`source_queries` as soon as the assigned judgment can be completed."
    )


def _partition_evidence_bound_findings[T](
    findings: list[T],
    *,
    evidence_refs: Callable[[T], tuple[str, ...]],
    available: set[str],
    requested: set[str],
) -> tuple[list[T], list[T]]:
    """Keep evidence bound findings and defer ones awaiting requested source."""
    accepted: list[T] = []
    deferred: list[T] = []
    for index, finding in enumerate(findings):
        refs = evidence_refs(finding)
        if not refs:
            raise RoleResponseError(f"findings[{index}].evidence_refs must not be empty")
        unknown = tuple(ref for ref in refs if ref not in available)
        if not unknown:
            accepted.append(finding)
            continue
        if set(unknown).issubset(requested):
            deferred.append(finding)
            continue
        raise RoleResponseError(f"findings[{index}].evidence_refs contain unread source ids: {', '.join(unknown)}")
    return accepted, deferred


def _implicit_reference_requests[T](
    findings: list[T],
    *,
    evidence_refs: Callable[[T], tuple[str, ...]],
    available: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
    evidence_requests: list[object],
    source_queries: list[object],
) -> tuple[list[object], list[object]]:
    """Turn exact unread citations into requests without accepting their finding."""
    requested_evidence = {item for item in evidence_requests if isinstance(item, str)}
    requested_sources = {
        target
        for query in source_queries
        if isinstance(query, dict) and query.get("kind") == "read_source"
        for target in (query.get("target"),)
        if isinstance(target, str)
    }
    for finding in findings:
        for reference in evidence_refs(finding):
            if reference in available:
                continue
            if reference in evidence_ids and reference not in requested_evidence:
                evidence_requests.append(reference)
                requested_evidence.add(reference)
                continue
            if navigation is not None and navigation.can_read(reference) and reference not in requested_sources:
                source_queries.append({"kind": "read_source", "target": reference})
                requested_sources.add(reference)
    return evidence_requests, source_queries


def _requested_reference_ids(evidence: object, source: object) -> set[str]:
    """Return ids this reply asks the engine to deliver before its next judgment."""
    requested = {item for item in evidence if isinstance(item, str)} if isinstance(evidence, list) else set()
    if not isinstance(source, list):
        return requested
    requested.update(
        target
        for query in source
        if isinstance(query, dict) and query.get("kind") == "read_source"
        for target in (query.get("target"),)
        if isinstance(target, str)
    )
    return requested


@dataclass(frozen=True, kw_only=True)
class RoleRound[T]:
    """One role round with recall-safe fallback and explicit failure state."""

    findings: list[T]
    pending: list[PendingWorkRecord] = field(default_factory=list)
    clean: bool = True
    failure_role: str = ""
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)

    @property
    def investigate(self) -> list[PendingWorkRecord]:
        """Expose pending dynamic checks under the result API name."""
        return self.pending


@dataclass(frozen=True, kw_only=True)
class ReviewCycle[T]:
    """One target adapter result consumed by the shared scheduler."""

    findings: list[T]
    failures: list[ReviewUnitFailure] = field(default_factory=list)
    pending: list[PendingWorkRecord] = field(default_factory=list)
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)

    @property
    def clean(self) -> bool:
        """Allow judgment with visible limitations while rejecting unavailable evidence."""
        return self.errors == 0 and not self.failures and not self.failure_reason and self.grounding.reviewable


@dataclass(frozen=True, kw_only=True)
class ReviewOutcome[T]:
    """The shared completion contract for one review target."""

    findings: list[T]
    failures: list[ReviewUnitFailure] = field(default_factory=list)
    incomplete: list[T] = field(default_factory=list)
    pending: list[PendingWorkRecord] = field(default_factory=list)
    errors: int = 0
    converged: bool = True
    requires_convergence: bool = True
    rounds: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)

    @property
    def complete(self) -> bool:
        """Require convergence and no failed or incomplete judgment step."""
        convergence_met = self.converged or not self.requires_convergence
        return (
            convergence_met
            and not self.failures
            and not self.incomplete
            and not self.pending
            and self.errors == 0
            and not self.failure_reason
            and self.grounding.complete
        )

    @property
    def degraded(self) -> bool:
        """Expose every incomplete outcome through one target-neutral signal."""
        return not self.complete

    @property
    def investigate(self) -> list[PendingWorkRecord]:
        """Expose pending dynamic checks under the result API name."""
        return self.pending


def extend_review_outcome[T](
    outcome: ReviewOutcome[T],
    *,
    findings: list[T],
    failures: list[ReviewUnitFailure] | None = None,
    incomplete: Iterable[T] = (),
    errors: int = 0,
    failure_reason: str = "",
    grounding: GroundingCoverage | None = None,
) -> ReviewOutcome[T]:
    """Add target postprocessing without losing the shared completion state."""
    return ReviewOutcome(
        findings=findings,
        failures=outcome.failures if failures is None else failures,
        incomplete=[*outcome.incomplete, *incomplete],
        pending=outcome.pending,
        errors=outcome.errors + errors,
        converged=outcome.converged,
        requires_convergence=outcome.requires_convergence,
        rounds=outcome.rounds,
        failure_reason=". ".join(reason for reason in (outcome.failure_reason, failure_reason) if reason),
        grounding=merge_grounding_coverage(
            (outcome.grounding, grounding) if grounding is not None else (outcome.grounding,)
        ),
    )


def _failure_reason(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def run_role_round[T](
    *,
    find: Callable[[], list[T] | EvidenceJudgment[T]],
    finder_label: str,
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    challenge: Callable[[list[T]], RoleChallenge[T]] | None = None,
    challenger_label: str = "",
    judge: Callable[[list[T], RoleChallenge[T]], RoleJudgment[T]] | None = None,
    judge_label: str = "",
) -> RoleRound[T]:
    """Run one shared role sequence and preserve candidates produced before a failure."""
    if (challenge is None) != (judge is None):
        raise ValueError("challenger and judge callbacks must be configured together")
    try:
        finder_result = find()
        if isinstance(finder_result, EvidenceJudgment):
            finder_findings = tag_found_by(finder_result.findings, finder_label)
            grounding = finder_result.grounding
            if finder_result.failure_reason:
                return RoleRound(
                    findings=finder_findings,
                    clean=False,
                    failure_role="finder",
                    failure_reason=finder_result.failure_reason,
                    grounding=grounding,
                )
        else:
            finder_findings = tag_found_by(finder_result, finder_label)
            grounding = GroundingCoverage()
    except Exception as exc:
        return RoleRound(
            findings=[],
            clean=False,
            failure_role="finder",
            failure_reason=_failure_reason(exc),
        )

    if challenge is None or judge is None:
        return RoleRound(findings=finder_findings, grounding=grounding)

    try:
        challenged = challenge(finder_findings)
        challenger_findings = tag_found_by(challenged.new_findings, challenger_label)
    except Exception as exc:
        return RoleRound(
            findings=finder_findings,
            clean=False,
            failure_role="challenger",
            failure_reason=_failure_reason(exc),
            grounding=grounding,
        )

    fallback = [*finder_findings, *challenger_findings]
    try:
        judged = judge(finder_findings, challenged)
    except Exception as exc:
        return RoleRound(
            findings=fallback,
            clean=False,
            failure_role="judge",
            failure_reason=_failure_reason(exc),
            grounding=grounding,
        )

    findings = label_judged(
        judged.findings,
        finder_findings,
        challenger_findings,
        key=key,
        title=title,
        finder_label=finder_label,
        challenger_label=challenger_label,
        judge_label=judge_label,
    )
    return RoleRound(findings=findings, pending=judged.pending, grounding=grounding)


def merge_findings[T](
    pool: dict[Hashable, T],
    incoming: Iterable[T],
    *,
    key: Callable[[T], Hashable],
    fold: Callable[[T, T], T],
) -> int:
    """Grow one finding union while delegating target identity and evidence folding."""
    new = 0
    for finding in incoming:
        identity = key(finding)
        existing = pool.get(identity)
        if existing is None:
            pool[identity] = finding
            new += 1
        else:
            pool[identity] = fold(existing, finding)
    return new


@dataclass
class FindingAccumulator[T]:
    """A monotonic finding union configured by one target policy."""

    key: Callable[[T], Hashable]
    fold: Callable[[T, T], T]
    grade: Callable[[T], str] | None = None
    with_grade: Callable[[T, str], T] | None = None
    pool: dict[Hashable, T] = field(default_factory=dict)
    grade_votes: dict[Hashable, list[str]] = field(default_factory=dict)

    def add(self, findings: Iterable[T]) -> int:
        """Fold one set into the union and return its new identity count."""
        items = list(findings)
        if self.grade is not None:
            for finding in items:
                self.grade_votes.setdefault(self.key(finding), []).append(self.grade(finding))
        return merge_findings(self.pool, items, key=self.key, fold=self.fold)

    @property
    def findings(self) -> list[T]:
        """Return the stable insertion ordered union."""
        if self.grade is None or self.with_grade is None:
            return list(self.pool.values())
        return [
            self.with_grade(finding, median(self.grade_votes.get(identity, [self.grade(finding)])))
            for identity, finding in self.pool.items()
        ]


def run_standard_judgments[T, K](
    judgments: Iterable[K],
    *,
    execute_judgment: Callable[[K, bool], list[T] | EvidenceJudgment[T]],
    describe_judgment: Callable[[K], str],
    finder_label: str,
    accumulator: FindingAccumulator[T],
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    on_judgment: JudgmentProgress | None = None,
    trace: Trace | None = None,
) -> ReviewCycle[T]:
    """Run every standard judgment and preserve findings from successful siblings."""
    planned = list(judgments)
    if not planned:
        raise ValueError("standard review requires at least one judgment")
    reuse_cache = len(planned) > 1
    failures: list[str] = []
    grounding: list[GroundingCoverage] = []
    for index, judgment in enumerate(planned, 1):
        started = perf_counter()
        description = describe_judgment(judgment)
        emit_trace(
            trace,
            "judgment",
            stage="selected",
            judgment=index,
            label=description,
            categories=list(getattr(judgment, "categories", ())),
        )
        role_round = run_role_round(
            find=lambda judgment=judgment: execute_judgment(judgment, reuse_cache),
            finder_label=finder_label,
            key=key,
            title=title,
        )
        grounding.append(role_round.grounding)
        accumulator.add(role_round.findings)
        emit_trace(
            trace,
            "judgment",
            stage="finished",
            judgment=index,
            label=description,
            categories=list(getattr(judgment, "categories", ())),
            count=len(role_round.findings),
            status="ok" if role_round.clean else "failed",
            reason=role_round.failure_reason[:500] if role_round.failure_reason else "",
        )
        if not role_round.clean:
            emit_trace(
                trace,
                "judgment_failed",
                judgment=index,
                label=description,
                reason=role_round.failure_reason[:500],
            )
        if on_judgment is not None:
            on_judgment(index, len(planned), description, round(perf_counter() - started, 1))
        if not role_round.clean:
            failures.append(
                f"{role_round.failure_reason} [knowledge judgment {index}/{len(planned)} for {description}]"
            )
    return ReviewCycle(
        findings=accumulator.findings,
        errors=len(failures),
        failure_reason=". ".join(failures),
        grounding=merge_grounding_coverage(tuple(grounding)),
    )


@dataclass
class ConvergenceState:
    """The shared clean-round convergence rule."""

    converge_after: int = 2
    new_per_round: list[int] = field(default_factory=list)
    clean_per_round: list[bool] = field(default_factory=list)
    pending_per_round: list[bool] = field(default_factory=list)

    def record(self, new_findings: int, *, clean: bool = True, pending: bool = False) -> None:
        """Record one round without letting failed or pending work look converged."""
        self.new_per_round.append(new_findings)
        self.clean_per_round.append(clean)
        self.pending_per_round.append(pending)

    @property
    def converged(self) -> bool:
        """Require consecutive clean, complete rounds that add no identity."""
        if len(self.new_per_round) < self.converge_after:
            return False
        start = -self.converge_after
        return (
            all(count == 0 for count in self.new_per_round[start:])
            and all(self.clean_per_round[start:])
            and not any(self.pending_per_round[start:])
        )


def run_review_cycles[T](
    *,
    plan: ReviewPlan,
    execute: Callable[[int, list[T]], ReviewCycle[T]],
    accumulator: FindingAccumulator[T],
    convergence: ConvergenceState | None = None,
    on_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
) -> ReviewOutcome[T]:
    """Run target supplied cycles through one accumulation and completion contract."""
    state = convergence or ConvergenceState(converge_after=plan.converge_after)
    failures_by_unit: dict[tuple[int, int, tuple[str, ...]], ReviewUnitFailure] = {}
    pending: list[PendingWorkRecord] = []
    errors = 0
    failure_reasons: list[str] = []
    grounding: list[GroundingCoverage] = []
    rounds = 0
    converged = False

    for rounds in range(1, plan.max_rounds + 1):
        cycle = execute(rounds, accumulator.findings)
        new_count = accumulator.add(cycle.findings)
        state.record(new_count, clean=cycle.clean, pending=bool(cycle.pending))
        for failure in cycle.failures:
            failures_by_unit[(failure.index, failure.total, failure.paths)] = failure
        pending = cycle.pending
        errors += cycle.errors
        grounding.append(cycle.grounding)
        if cycle.failure_reason:
            failure_reasons.append(cycle.failure_reason)
        if on_round is not None:
            on_round(rounds, new_count, len(accumulator.findings), cycle)

        if not cycle.clean and plan.stop_on_failure:
            break
        if rounds < plan.min_rounds:
            continue
        if plan.completion == "single":
            break
        if state.converged:
            converged = True
            break

    if plan.completion == "converge" and state.converged:
        converged = True
    if plan.completion == "converge" and not converged:
        failure_reasons.append(f"review did not converge within {plan.max_rounds} rounds")
    merged_grounding = merge_grounding_coverage(tuple(grounding))
    grounding_reason = merged_grounding.failure_reason
    if grounding_reason and grounding_reason not in failure_reasons:
        failure_reasons.append(grounding_reason)
    return ReviewOutcome(
        findings=accumulator.findings,
        failures=list(failures_by_unit.values()),
        pending=pending,
        errors=errors,
        converged=converged,
        requires_convergence=plan.completion == "converge",
        rounds=rounds,
        failure_reason=". ".join(failure_reasons),
        grounding=merged_grounding,
    )


def run_review_units[U, T](
    units: list[U],
    *,
    plan: ReviewPlan,
    execute: Callable[[int, U, list[T]], ReviewCycle[T]],
    accumulator: FindingAccumulator[T],
    failure_for: Callable[[int, int, U, str], ReviewUnitFailure],
    convergence: ConvergenceState | None = None,
    concurrency: int = 1,
    on_unit: Callable[[U, float], None] | None = None,
    on_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
) -> ReviewOutcome[T]:
    """Fan out every target unit inside each shared review cycle."""
    if not units:
        raise ValueError("at least one review unit is required")
    if concurrency < 1:
        raise ValueError("review concurrency must be positive")
    unit_lock = Lock()

    def execute_round(round_no: int, known: list[T]) -> ReviewCycle[T]:
        def invoke(unit: U) -> ReviewCycle[T]:
            started = perf_counter()
            try:
                return execute(round_no, unit, known)
            except Exception as exc:
                return ReviewCycle(
                    findings=[],
                    errors=1,
                    failure_reason=f"{type(exc).__name__}: {exc}",
                )
            finally:
                if on_unit is not None:
                    with unit_lock:
                        on_unit(unit, round(perf_counter() - started, 1))

        if concurrency > 1 and len(units) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                results = list(pool.map(invoke, units))
        else:
            results = [invoke(unit) for unit in units]

        findings = [finding for result in results for finding in result.findings]
        pending = [item for result in results for item in result.pending]
        failures = [
            failure_for(
                index,
                len(units),
                unit,
                result.failure_reason or result.grounding.failure_reason or "review unit failed",
            )
            for index, (unit, result) in enumerate(zip(units, results, strict=True), 1)
            if not result.clean
        ]
        return ReviewCycle(
            findings=findings,
            failures=failures,
            pending=pending,
            errors=sum(result.errors or int(not result.clean) for result in results),
            grounding=merge_grounding_coverage(tuple(result.grounding for result in results)),
        )

    return run_review_cycles(
        plan=plan,
        execute=execute_round,
        accumulator=accumulator,
        convergence=convergence,
        on_round=on_round,
    )
