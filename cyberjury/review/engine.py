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
    SourceEvidence,
    evidence_request_ids,
    merge_grounding_coverage,
    select_evidence,
    with_source_evidence,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.navigation import (
    SourceNavigationError,
    SourceNavigationResult,
    SourceNavigationSession,
    parse_source_queries,
)
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
    object_list_keys: tuple[str, ...] = (),
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
    for key in object_list_keys:
        value = obj.get(key, [])
        if not isinstance(value, list):
            raise RoleResponseError(f"{role} reply had non-list object field: {key}")
        invalid_item = next((index for index, item in enumerate(value) if not isinstance(item, dict)), None)
        if invalid_item is not None:
            raise RoleResponseError(f"{role} reply field {key}[{invalid_item}] must be an object")
    return obj


def parse_navigation_response(text: str, *, role: str) -> RoleReply:
    """Require a source only reply before formal security judgment."""
    obj = parse_role_response(
        text,
        role=role,
        required_keys=("evidence_requests", "source_queries"),
    )
    unexpected = sorted(set(obj) - {"evidence_requests", "source_queries"})
    if unexpected:
        fields = ", ".join(unexpected)
        raise RoleResponseError(f"{role} reply had fields outside the source navigation contract: {fields}")
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
    source_evidence: tuple[SourceEvidence, ...] = ()
    evidence_exchanges: int = 0


@dataclass(frozen=True, kw_only=True)
class GroundingPreparation:
    """Source collected before knowledge judgments start."""

    context: GroundingContext
    navigation: SourceNavigationSession | None
    remaining_followups: int
    failure_reason: str = ""


@dataclass(frozen=True, kw_only=True)
class _ParsedEvidenceReply[T]:
    """One validated model reply before its evidence is delivered."""

    findings: list[T]
    requested: list[str]
    source_queries: list[dict[str, object]]
    deferred: list[T]


@dataclass(frozen=True, kw_only=True)
class _DeliveredEvidence:
    """One atomic evidence batch from every published source catalog."""

    text: str
    coverage: GroundingCoverage
    source_evidence: tuple[SourceEvidence, ...]


def prepare_grounding(
    context: GroundingContext,
    *,
    ask: Callable[[EvidencePromptContext], RoleReply],
    target_chars: int,
    max_followups: int,
    trace: Trace | None = None,
) -> GroundingPreparation:
    """Collect source before knowledge selection under one unit navigation budget."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    navigation = context.navigator.session() if context.navigator is not None else None
    if navigation is None:
        return GroundingPreparation(
            context=context,
            navigation=None,
            remaining_followups=max_followups,
        )
    judgment = run_evidence_judgment(
        context,
        ask=ask,
        findings_from_reply=lambda _reply: [],
        accumulator=FindingAccumulator(key=lambda _item: 0, fold=lambda existing, _incoming: existing),
        target_chars=target_chars,
        max_followups=max_followups,
        trace=trace,
        navigation_session=navigation,
    )
    prepared = with_source_evidence(context, judgment.source_evidence)
    prepared = replace(
        prepared,
        coverage=merge_grounding_coverage((prepared.coverage, judgment.grounding)),
    )
    return GroundingPreparation(
        context=prepared,
        navigation=navigation,
        remaining_followups=max_followups - judgment.evidence_exchanges,
        failure_reason=judgment.failure_reason,
    )


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
    navigation_session: SourceNavigationSession | None = None,
) -> EvidenceJudgment[T]:
    """Run bounded evidence and source navigation without losing earlier findings."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    prompt = _with_request_budget(context.prompt, max_followups)
    coverage = context.coverage
    available_refs = {"seed", *coverage.references}
    findings: list[T] = []
    navigation = navigation_session
    if navigation is None and context.navigator is not None:
        navigation = context.navigator.session()
    source_evidence: list[SourceEvidence] = []
    evidence_exchanges = 0
    for exchange in range(max_followups + 1):
        try:
            reply = ask(prompt)
            parsed_reply = _parse_evidence_reply(
                reply,
                findings_from_reply=findings_from_reply,
                evidence_refs=evidence_refs,
                available_refs=available_refs,
                evidence_ids={item.id for item in context.evidence},
                navigation=navigation,
            )
            accumulator.add(parsed_reply.findings)
        except Exception as exc:
            if exchange == 0:
                raise
            return _evidence_judgment(
                findings=findings,
                coverage=coverage,
                unresolved=(f"evidence exchange {exchange + 1} failed",),
                failure_reason=_failure_reason(exc),
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
            )
        findings = accumulator.findings
        requested = parsed_reply.requested
        source_queries = parsed_reply.source_queries
        deferred = parsed_reply.deferred
        if not requested and not source_queries:
            return _evidence_judgment(
                findings=findings,
                coverage=coverage,
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
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
            return _evidence_judgment(
                findings=findings,
                coverage=coverage,
                unresolved=unresolved,
                failure_reason=f"finder requested evidence after {max_followups} follow ups",
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
            )
        try:
            delivered = _deliver_evidence_exchange(
                context,
                navigation,
                requested=requested,
                source_queries=source_queries,
                target_chars=target_chars,
                trace=trace,
                judgment_id=judgment_id,
                exchange=exchange + 1,
            )
            coverage = merge_grounding_coverage((coverage, delivered.coverage))
            available_refs.update(delivered.coverage.references)
            source_evidence.extend(delivered.source_evidence)
            evidence_exchanges += 1
        except (EvidenceRequestError, SourceNavigationError) as exc:
            unresolved = tuple(item for item in requested if isinstance(item, str))
            if not unresolved:
                unresolved = (f"source navigation exchange {exchange + 1}",)
            return _evidence_judgment(
                findings=findings,
                coverage=coverage,
                unresolved=unresolved,
                failure_reason=str(exc),
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
            )
        prompt = _evidence_continuation(
            prompt,
            delivered=delivered.text,
            exchange=exchange + 1,
            remaining=max_followups - exchange - 1,
            deferred=len(deferred),
        )
    raise AssertionError("unreachable source navigation loop")


def _evidence_judgment[T](
    *,
    findings: list[T],
    coverage: GroundingCoverage,
    prompt: EvidencePromptContext,
    source_evidence: list[SourceEvidence],
    evidence_exchanges: int,
    unresolved: tuple[str, ...] = (),
    failure_reason: str = "",
) -> EvidenceJudgment[T]:
    """Build one terminal evidence result without dropping prior coverage."""
    grounding = (
        merge_grounding_coverage((coverage, GroundingCoverage(unresolved=unresolved))) if unresolved else coverage
    )
    return EvidenceJudgment(
        findings=findings,
        grounding=grounding,
        failure_reason=failure_reason,
        prompt_context=prompt.source,
        prompt_controls=prompt.controls,
        source_evidence=tuple(source_evidence),
        evidence_exchanges=evidence_exchanges,
    )


def _evidence_continuation(
    prompt: EvidencePromptContext,
    *,
    delivered: str,
    exchange: int,
    remaining: int,
    deferred: int,
) -> EvidencePromptContext:
    """Render controls for the next judgment after one atomic delivery."""
    provisional = (
        f" {deferred} provisional finding or findings cited evidence requested in the prior reply and were not "
        "accepted. Reassess and return them again only if the delivered source supports them."
        if deferred
        else ""
    )
    return EvidencePromptContext(
        source=prompt.source,
        controls=(
            f"{prompt.controls}\n\nSource navigation exchange {exchange}:\n{delivered}\n\n"
            f"{_request_budget_instruction(remaining)}{provisional}"
        ),
    )


def _parse_evidence_reply[T](
    reply: RoleReply,
    *,
    findings_from_reply: Callable[[RoleReply], list[T]],
    evidence_refs: Callable[[T], tuple[str, ...]] | None,
    available_refs: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
) -> _ParsedEvidenceReply[T]:
    """Validate one reply before changing accumulated findings or coverage."""
    findings = findings_from_reply(reply)
    raw_requested = reply.get("evidence_requests", [])
    raw_queries = reply.get("source_queries", [])
    if not isinstance(raw_requested, list):
        raise EvidenceRequestError("evidence_requests must be a list")
    if not isinstance(raw_queries, list):
        raise SourceNavigationError("source_queries must be a list")
    source_queries = parse_source_queries(raw_queries)
    requested: list[object] = [*raw_requested]
    if evidence_refs is not None:
        requested = _implicit_reference_requests(
            findings,
            evidence_refs=evidence_refs,
            available=available_refs,
            evidence_ids=evidence_ids,
            navigation=navigation,
            evidence_requests=requested,
        )
    ids = list(evidence_request_ids(requested))
    if evidence_refs is None:
        accepted = findings
        deferred: list[T] = []
    else:
        accepted, deferred = _partition_evidence_bound_findings(
            findings,
            evidence_refs=evidence_refs,
            available=available_refs,
            requested=set(ids),
        )
    return _ParsedEvidenceReply(
        findings=accepted,
        requested=ids,
        source_queries=source_queries,
        deferred=deferred,
    )


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


def _deliver_evidence_exchange(
    context: GroundingContext,
    navigation: SourceNavigationSession | None,
    *,
    requested: list[str],
    source_queries: list[dict[str, object]],
    target_chars: int,
    trace: Trace | None,
    judgment_id: int | None,
    exchange: int,
) -> _DeliveredEvidence:
    """Deliver one request batch under one budget and one coverage commit."""
    exact = (
        _deliver_exact_evidence(context, navigation, requested, target_chars=target_chars)
        if requested
        else SourceNavigationResult(text="")
    )
    if source_queries and navigation is None:
        raise SourceNavigationError("source_queries are unavailable for this judgment")
    navigated = (
        navigation.execute(source_queries, target_chars=target_chars)
        if navigation is not None and source_queries
        else SourceNavigationResult(text="")
    )
    blocks = [f"Requested exact repository evidence:\n{exact.text}"] if exact.text else []
    if navigated.text:
        blocks.append(navigated.text)
    text = "\n\n".join(blocks)
    one_indivisible_item = len(requested) == 1 and not source_queries
    if len(text) > target_chars and not one_indivisible_item:
        raise EvidenceRequestError(f"evidence exchange exceeds the {target_chars} character target")
    coverage = merge_grounding_coverage((exact.coverage, navigated.coverage))
    if exact.text:
        emit_trace(
            trace,
            "evidence",
            stage="delivered",
            judgment=judgment_id,
            ids=list(exact.coverage.references),
            identities=list(exact.coverage.included),
            characters=len(exact.text),
        )
    if navigated.text:
        emit_trace(
            trace,
            "navigation",
            stage="delivered",
            judgment=judgment_id,
            exchange=exchange,
            requests=source_queries,
            queries=len(source_queries),
            identities=list(navigated.coverage.included),
            characters=len(navigated.text),
        )
    return _DeliveredEvidence(
        text=text,
        coverage=coverage,
        source_evidence=(*exact.source_evidence, *navigated.source_evidence),
    )


def _deliver_exact_evidence(
    context: GroundingContext,
    navigation: SourceNavigationSession | None,
    requested: object,
    *,
    target_chars: int,
) -> SourceNavigationResult:
    """Dispatch registered evidence ids without asking the model where they live."""
    ids = evidence_request_ids(requested)
    published_by_id = {item.id: item for item in context.evidence}
    published_ids = tuple(item for item in ids if item in published_by_id)
    source_ids = tuple(
        item for item in ids if item not in published_by_id and navigation is not None and navigation.can_read(item)
    )
    known = {*published_ids, *source_ids}
    unknown = tuple(item for item in ids if item not in known)
    if unknown:
        raise EvidenceRequestError(f"evidence request contains unknown ids: {', '.join(unknown)}")

    selected = select_evidence(context.evidence, list(published_ids), target_chars=target_chars)
    navigated = (
        navigation.read(list(source_ids), target_chars=target_chars)
        if navigation is not None and source_ids
        else SourceNavigationResult(text="")
    )
    selected_sources = tuple(
        SourceEvidence(
            id=item_id,
            identity=published_by_id[item_id].identity,
            text=published_by_id[item_id].text,
            source_span=published_by_id[item_id].source_span,
        )
        for item_id in published_ids
    )
    return SourceNavigationResult(
        text="\n\n".join(block for block in (selected.text, navigated.text) if block),
        coverage=replace(
            merge_grounding_coverage((selected.coverage, navigated.coverage)),
            references=ids,
        ),
        source_evidence=(*selected_sources, *navigated.source_evidence),
    )


def _implicit_reference_requests[T](
    findings: list[T],
    *,
    evidence_refs: Callable[[T], tuple[str, ...]],
    available: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
    evidence_requests: list[object],
) -> list[object]:
    """Turn exact unread citations into requests without accepting their finding."""
    requested = {item for item in evidence_requests if isinstance(item, str)}
    for finding in findings:
        for reference in evidence_refs(finding):
            if reference in available:
                continue
            if reference in evidence_ids and reference not in requested:
                evidence_requests.append(reference)
                requested.add(reference)
                continue
            if navigation is not None and navigation.can_read(reference) and reference not in requested:
                evidence_requests.append(reference)
                requested.add(reference)
    return evidence_requests


def _requested_reference_ids(evidence: object) -> set[str]:
    """Return ids this reply asks the engine to deliver before its next judgment."""
    return {item for item in evidence if isinstance(item, str)} if isinstance(evidence, list) else set()


@dataclass(frozen=True, kw_only=True)
class RoleRound[T]:
    """One role round with recall-safe fallback and explicit failure state."""

    findings: list[T]
    pending: list[PendingWorkRecord] = field(default_factory=list)
    clean: bool = True
    failure_role: str = ""
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()
    evidence_exchanges: int = 0

    @property
    def investigate(self) -> list[PendingWorkRecord]:
        """Expose pending dynamic checks under the result API name."""
        return self.pending


@dataclass(frozen=True, kw_only=True)
class ReviewCycle[T]:
    """One target adapter result consumed by the shared scheduler."""

    findings: list[T]
    incomplete: list[T] = field(default_factory=list)
    failures: list[ReviewUnitFailure] = field(default_factory=list)
    pending: list[PendingWorkRecord] = field(default_factory=list)
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()

    @property
    def clean(self) -> bool:
        """Allow judgment with visible limitations while rejecting unavailable evidence."""
        return (
            not self.incomplete
            and self.errors == 0
            and not self.failures
            and not self.failure_reason
            and self.grounding.reviewable
        )


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
                    source_evidence=finder_result.source_evidence,
                    evidence_exchanges=finder_result.evidence_exchanges,
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
        return RoleRound(
            findings=finder_findings,
            grounding=grounding,
            source_evidence=(finder_result.source_evidence if isinstance(finder_result, EvidenceJudgment) else ()),
            evidence_exchanges=(finder_result.evidence_exchanges if isinstance(finder_result, EvidenceJudgment) else 0),
        )

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
            source_evidence=(finder_result.source_evidence if isinstance(finder_result, EvidenceJudgment) else ()),
            evidence_exchanges=(finder_result.evidence_exchanges if isinstance(finder_result, EvidenceJudgment) else 0),
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
            source_evidence=(finder_result.source_evidence if isinstance(finder_result, EvidenceJudgment) else ()),
            evidence_exchanges=(finder_result.evidence_exchanges if isinstance(finder_result, EvidenceJudgment) else 0),
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
    return RoleRound(
        findings=findings,
        pending=judged.pending,
        grounding=grounding,
        source_evidence=(finder_result.source_evidence if isinstance(finder_result, EvidenceJudgment) else ()),
        evidence_exchanges=(finder_result.evidence_exchanges if isinstance(finder_result, EvidenceJudgment) else 0),
    )


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


@dataclass(frozen=True, kw_only=True)
class GroundedJudgmentTask[K]:
    """One standard judgment against the current unit evidence revision."""

    judgment: K
    plan: tuple[K, ...]
    context: GroundingContext
    navigation: SourceNavigationSession | None
    remaining_followups: int
    cache: bool
    index: int


@dataclass(frozen=True, kw_only=True)
class _RevisionJudgment[T]:
    """One pack result bound to the evidence revision it reviewed."""

    revision: tuple[tuple[str, str], ...]
    role_round: RoleRound[T]
    seconds: float


@dataclass
class _GroundedStandardState[T]:
    """Mutable state for one unit's revisioned standard judgments."""

    context: GroundingContext
    navigation: SourceNavigationSession | None
    remaining: int
    results: dict[Hashable, _RevisionJudgment[T]] = field(default_factory=dict)
    judgment_count: int = 0


def _planned_judgments[K](
    plan_judgments: Callable[[GroundingContext], Iterable[K]],
    context: GroundingContext,
) -> tuple[K, ...]:
    planned = tuple(plan_judgments(context))
    if not planned:
        raise ValueError("standard review requires at least one judgment")
    return planned


def _judgment_identity[K](judgment: K, describe_judgment: Callable[[K], str]) -> Hashable:
    return tuple(getattr(judgment, "categories", ())), describe_judgment(judgment)


def _evidence_revision(context: GroundingContext) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((item.id, item.identity) for item in context.source_evidence))


def _next_stale_judgment[T, K](
    state: _GroundedStandardState[T],
    planned: tuple[K, ...],
    *,
    describe_judgment: Callable[[K], str],
) -> tuple[int, K] | None:
    revision = _evidence_revision(state.context)
    for index, judgment in enumerate(planned, 1):
        result = state.results.get(_judgment_identity(judgment, describe_judgment))
        if result is None or result.revision != revision:
            return index, judgment
    return None


def _run_revision_judgment[T, K](
    state: _GroundedStandardState[T],
    planned: tuple[K, ...],
    index: int,
    judgment: K,
    *,
    execute_judgment: Callable[[GroundedJudgmentTask[K]], EvidenceJudgment[T]],
    describe_judgment: Callable[[K], str],
    finder_label: str,
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    trace: Trace | None,
) -> None:
    """Replace one stale pack result with a judgment on the current evidence."""
    state.judgment_count += 1
    started = perf_counter()
    description = describe_judgment(judgment)
    emit_trace(
        trace,
        "judgment",
        stage="selected",
        judgment=state.judgment_count,
        evidence_revision=len(state.context.source_evidence),
        label=description,
        categories=list(getattr(judgment, "categories", ())),
    )
    task = GroundedJudgmentTask(
        judgment=judgment,
        plan=planned,
        context=state.context,
        navigation=state.navigation,
        remaining_followups=state.remaining,
        cache=len(planned) > 1 or state.judgment_count > 1,
        index=state.judgment_count,
    )
    role_round = run_role_round(
        find=lambda: execute_judgment(task),
        finder_label=finder_label,
        key=key,
        title=title,
    )
    state.remaining -= role_round.evidence_exchanges
    if state.remaining < 0:
        raise AssertionError("evidence exchange accounting exceeded the unit budget")
    state.context = with_source_evidence(state.context, role_round.source_evidence)
    elapsed = perf_counter() - started
    state.results[_judgment_identity(judgment, describe_judgment)] = _RevisionJudgment(
        revision=_evidence_revision(state.context),
        role_round=role_round,
        seconds=elapsed,
    )
    emit_trace(
        trace,
        "judgment",
        stage="finished",
        judgment=state.judgment_count,
        evidence_revision=len(state.context.source_evidence),
        label=description,
        categories=list(getattr(judgment, "categories", ())),
        count=len(role_round.findings),
        status="ok" if role_round.clean else "failed",
        reason=role_round.failure_reason[:500] if role_round.failure_reason else "",
        plan_index=index,
    )


def _stabilize_revisioned_judgments[T, K](
    state: _GroundedStandardState[T],
    *,
    plan_judgments: Callable[[GroundingContext], Iterable[K]],
    execute_judgment: Callable[[GroundedJudgmentTask[K]], EvidenceJudgment[T]],
    describe_judgment: Callable[[K], str],
    finder_label: str,
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    trace: Trace | None,
) -> tuple[K, ...]:
    """Run only missing or stale packs until every result shares one revision."""
    while True:
        planned = _planned_judgments(plan_judgments, state.context)
        stale = _next_stale_judgment(state, planned, describe_judgment=describe_judgment)
        if stale is None:
            return planned
        index, judgment = stale
        _run_revision_judgment(
            state,
            planned,
            index,
            judgment,
            execute_judgment=execute_judgment,
            describe_judgment=describe_judgment,
            finder_label=finder_label,
            key=key,
            title=title,
            trace=trace,
        )


def run_grounded_standard_judgments[T, K](
    context: GroundingContext,
    *,
    plan_judgments: Callable[[GroundingContext], Iterable[K]],
    execute_judgment: Callable[[GroundedJudgmentTask[K]], EvidenceJudgment[T]],
    describe_judgment: Callable[[K], str],
    finder_label: str,
    accumulator: FindingAccumulator[T],
    key: Callable[[T], Hashable],
    title: Callable[[T], str],
    max_followups: int,
    navigation_session: SourceNavigationSession | None = None,
    remaining_followups: int | None = None,
    preparation_failure_reason: str = "",
    on_judgment: JudgmentProgress | None = None,
    trace: Trace | None = None,
) -> ReviewCycle[T]:
    """Keep only pack judgments made against the final unit evidence revision."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    remaining = max_followups if remaining_followups is None else remaining_followups
    if remaining < 0 or remaining > max_followups:
        raise ValueError("remaining_followups must be within the configured source navigation budget")
    state = _GroundedStandardState[T](
        context=context,
        navigation=(
            navigation_session
            if navigation_session is not None
            else context.navigator.session()
            if context.navigator is not None
            else None
        ),
        remaining=remaining,
    )
    planned = _stabilize_revisioned_judgments(
        state,
        plan_judgments=plan_judgments,
        execute_judgment=execute_judgment,
        describe_judgment=describe_judgment,
        finder_label=finder_label,
        key=key,
        title=title,
        trace=trace,
    )
    failures: list[str] = [preparation_failure_reason] if preparation_failure_reason else []
    grounding = [state.context.coverage]
    for index, judgment in enumerate(planned, 1):
        description = describe_judgment(judgment)
        result = state.results[_judgment_identity(judgment, describe_judgment)]
        role_round = result.role_round
        grounding.append(role_round.grounding)
        accumulator.add(role_round.findings)
        if on_judgment is not None:
            on_judgment(index, len(planned), description, round(result.seconds, 1))
        if not role_round.clean:
            failures.append(
                f"{role_round.failure_reason} [knowledge judgment {index}/{len(planned)} for {description}]"
            )
    return ReviewCycle(
        findings=accumulator.findings,
        errors=len(failures),
        failure_reason=". ".join(failures),
        grounding=merge_grounding_coverage(tuple(grounding)),
        source_evidence=state.context.source_evidence,
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
    incomplete: list[T] = []
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
        incomplete.extend(item for item in cycle.incomplete if item not in incomplete)
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
        incomplete=incomplete,
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
        incomplete = [finding for result in results for finding in result.incomplete]
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
            incomplete=incomplete,
            failures=failures,
            pending=pending,
            errors=sum(result.errors or int(not result.clean) for result in results),
            grounding=merge_grounding_coverage(tuple(result.grounding for result in results)),
            source_evidence=tuple(dict.fromkeys(evidence for result in results for evidence in result.source_evidence)),
        )

    return run_review_cycles(
        plan=plan,
        execute=execute_round,
        accumulator=accumulator,
        convergence=convergence,
        on_round=on_round,
    )
