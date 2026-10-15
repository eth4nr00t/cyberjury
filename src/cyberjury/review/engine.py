"""Shared judgment orchestration for every review target."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Hashable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext, suppress
from dataclasses import dataclass, field, replace
from threading import Lock
from time import perf_counter

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.base import ResponseSchema
from cyberjury.providers.metering import model_call_context, model_call_scope, record_model_parse
from cyberjury.review.context import (
    EvidenceBudgetError,
    EvidencePromptContext,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    UnknownEvidenceRequest,
    evidence_request_ids,
    merge_grounding_coverage,
    select_evidence,
    with_source_evidence,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.navigation import (
    RepeatedSourceQueryError,
    SourceNavigationError,
    SourceNavigationResult,
    SourceNavigationSession,
    SourceQueryLimitError,
    UnknownDefinitionQueryError,
    parse_source_queries,
)
from cyberjury.review.provenance import tag_found_by
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.schemas import validate_response_object
from cyberjury.review.settings import positive_concurrency
from cyberjury.review.trace import Trace, emit_trace
from cyberjury.severity import median


class RoleResponseError(RuntimeError):
    """A role reply cannot support a complete judgment."""


class CorrectableRoleResponseError(RoleResponseError):
    """A response needs one bounded correction using deterministic local facts."""

    def __init__(
        self,
        instruction: str,
        response_findings: tuple[object, ...] = (),
        fallback_findings: tuple[object, ...] = (),
    ) -> None:
        """Separate valid carried candidates from invalid correction fallbacks."""
        self.instruction = instruction
        self.response_findings = response_findings
        self.fallback_findings = fallback_findings
        super().__init__(instruction)


type RoleReply = dict[str, object]


def parse_role_response(
    text: str,
    *,
    role: str,
    response_schema: ResponseSchema,
) -> RoleReply:
    """Require the role contract so malformed output cannot become a clean result."""
    parsed = parse_json_object(text)
    source = "direct" if parsed is not None else "none"

    def fail(message: str) -> None:
        record_model_parse(source, status="failed", failure_reason=message)
        raise RoleResponseError(message)

    if parsed is None:
        fail(f"{role} reply had no complete JSON object")
    try:
        obj = validate_response_object(parsed, response_schema)
    except ValueError as exc:
        fail(f"{role} reply violates {response_schema.name}: {exc}")
    record_model_parse(source)
    return obj


JudgmentProgress = Callable[[str, float], None]
_FAILURE_REASON_LIMIT = 2000
_FAILURE_REASON_TRUNCATED = "... [failure reason truncated]"
_CORRECTION_BUDGET = {
    "response": 1,
    "query_limit": 1,
    "repeated_query": 1,
    "delivered_request": 1,
    "evidence_budget": 2,
    "unknown_definition": 1,
    "unknown_evidence": 2,
}


@dataclass(frozen=True, kw_only=True)
class EvidenceJudgment[T]:
    """Findings and grounding receipt from one bounded evidence exchange."""

    findings: list[T]
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    failure_reason: str = ""
    source_evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _ParsedEvidenceReply[T]:
    """One validated model reply before its evidence is delivered."""

    findings: list[T]
    requested: list[str]
    source_queries: list[dict[str, object]]
    deferred: list[T]
    repeated_evidence_requests: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _DeliveredEvidence:
    """One atomic evidence batch from every published source catalog."""

    text: str
    coverage: GroundingCoverage
    source_evidence: tuple[SourceEvidence, ...]


class _RejectedBatch(Exception):
    """One reply batch the engine did not commit, with the local fact the next reply must correct.

    ``kind`` selects the correction budget. When that budget is spent the judgment ends with
    ``failure_reason`` and ``unresolved``, or re-raises ``fatal`` on the first model call.
    ``provisional`` replaces the provisional candidates shown with the correction when set.
    """

    def __init__(
        self,
        kind: str,
        instruction: str,
        *,
        failure_reason: str,
        unresolved: tuple[str, ...],
        provisional: list[object] | None = None,
        fatal: Exception | None = None,
    ) -> None:
        """Record the correction text and the terminal state used when no correction remains."""
        self.kind = kind
        self.instruction = instruction
        self.failure_reason = failure_reason
        self.unresolved = unresolved
        self.provisional = provisional
        self.fatal = fatal
        super().__init__(failure_reason)


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
    navigation_session: SourceNavigationSession | None = None,
    model_role: str = "finder",
    model_unit_id: str = "",
    review_brief_sha256: str = "",
    finding_prompt_record: Callable[[T], Mapping[str, object]] | None = None,
) -> EvidenceJudgment[T]:
    """Run bounded evidence and source navigation without losing earlier findings."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    navigation_available = navigation_session is not None or context.navigator is not None
    followup_budget = max_followups if navigation_available or context.evidence else 0
    prompt = _with_request_budget(
        replace(context.prompt, navigation_available=navigation_available),
        followup_budget,
    )
    initial_source_coverage = GroundingCoverage(
        included=tuple(dict.fromkeys(item.identity for item in context.source_evidence)),
        references=tuple(dict.fromkeys(item.id for item in context.source_evidence)),
    )
    coverage = merge_grounding_coverage((context.coverage, initial_source_coverage))
    available_refs = {"seed", *coverage.references}

    def union() -> FindingAccumulator[T]:
        return FindingAccumulator(
            key=accumulator.key,
            fold=accumulator.fold,
            grade=accumulator.grade,
            with_grade=accumulator.with_grade,
        )

    provisional = union()
    correction_fallback = union()

    def retained_findings() -> list[T]:
        retained = union()
        retained.add(correction_fallback.findings)
        retained.add(accumulator.findings)
        retained.add(provisional.findings)
        return retained.findings

    navigation = navigation_session
    if navigation is None and context.navigator is not None:
        navigation = context.navigator.session()
    source_evidence: list[SourceEvidence] = list(context.source_evidence)
    evidence_exchanges = 0
    corrections = dict(_CORRECTION_BUDGET)
    unknown_evidence_failure_reason = ""
    model_calls = 0

    def remaining() -> int:
        return max(0, followup_budget - evidence_exchanges)

    def finish(
        unresolved: tuple[str, ...],
        failure_reason: str,
        findings: list[T] | None = None,
    ) -> EvidenceJudgment[T]:
        return _evidence_judgment(
            findings=retained_findings() if findings is None else findings,
            coverage=coverage,
            unresolved=unresolved,
            failure_reason=failure_reason,
            source_evidence=source_evidence,
        )

    while True:
        call_index = model_calls
        model_calls += 1
        try:
            with model_call_context(
                role=model_role,
                trigger="initial_judgment" if call_index == 0 else "evidence_followup",
                unit_id=model_unit_id,
                evidence_revision=_prompt_revision(context, prompt),
                review_brief_sha256=review_brief_sha256,
            ) as call_observation:
                try:
                    context.validate_snapshot()
                    reply = ask(prompt)
                    context.validate_snapshot()
                    parsed_reply = _parse_evidence_reply(
                        reply,
                        findings_from_reply=findings_from_reply,
                        evidence_refs=evidence_refs,
                        available_refs=available_refs,
                        evidence_ids={item.id for item in context.evidence},
                        navigation=navigation,
                    )
                except CorrectableRoleResponseError as exc:
                    record_model_parse("semantic", status="failed", failure_reason=_failure_reason(exc))
                    call_observation.navigation("not_evaluated")
                    accumulator.add(exc.response_findings)
                    correction_fallback.add(exc.fallback_findings)
                    raise _RejectedBatch(
                        "response",
                        "Response correction required. "
                        f"{exc.instruction} Return the complete corrected response. Do not repeat the invalid value.",
                        failure_reason=_failure_reason(exc),
                        unresolved=("model response violates a deterministic response constraint",),
                        provisional=accumulator.findings,
                    ) from exc
                except SourceQueryLimitError as exc:
                    record_model_parse("semantic", status="failed", failure_reason=_failure_reason(exc))
                    call_observation.navigation("not_evaluated")
                    accumulator.add(exc.response_findings)
                    raise _RejectedBatch(
                        "query_limit",
                        f"The previous response returned {exc.count} source queries, but one batch permits "
                        f"at most {exc.limit}. No query in that batch was executed. Return at most {exc.limit} "
                        "distinct queries, keeping only the searches needed to decide the current candidates.",
                        failure_reason=_failure_reason(exc),
                        unresolved=("source query batch exceeds the published limit",),
                        provisional=accumulator.findings,
                        fatal=exc,
                    ) from exc
                except Exception as exc:
                    record_model_parse("semantic", status="failed", failure_reason=_failure_reason(exc))
                    call_observation.navigation("not_evaluated")
                    if call_index == 0:
                        raise
                    return finish((f"model response {call_index + 1} failed",), _failure_reason(exc))
            requested = parsed_reply.requested
            source_queries = parsed_reply.source_queries
            repeated_queries = tuple(
                query for query in source_queries if navigation is not None and navigation.query_was_executed(query)
            )
            if repeated_queries:
                source_queries = [query for query in source_queries if query not in repeated_queries]
            if repeated_queries and not source_queries and not requested and not parsed_reply.findings:
                repeated_query_failure_reason = "source query repeats an earlier query in this session"
                call_observation.navigation(
                    "failed",
                    source_query_count=len(source_queries),
                    evidence_request_count=len(requested),
                    failure_reason=repeated_query_failure_reason,
                )
                raise _RejectedBatch(
                    "repeated_query",
                    _REPEATED_QUERY_CORRECTION,
                    failure_reason=repeated_query_failure_reason,
                    unresolved=(repeated_query_failure_reason,),
                )
            if not requested and not source_queries:
                call_observation.navigation("not_requested")
                repeated_requests = parsed_reply.repeated_evidence_requests
                if repeated_requests and not parsed_reply.findings:
                    raise _RejectedBatch(
                        "delivered_request",
                        f"These requested items are already delivered: {', '.join(repeated_requests)}. "
                        "Cite source receipts directly. Do not request these items again. "
                        "Return the judgment or request different unread evidence.",
                        failure_reason="model repeated an already delivered request without a judgment",
                        unresolved=repeated_requests,
                    )
                accumulator.add(provisional.findings)
                accumulator.add(parsed_reply.findings)
                return finish((), "", findings=accumulator.findings)
            provisional.add((*parsed_reply.findings, *parsed_reply.deferred))
            if evidence_exchanges >= followup_budget:
                call_observation.navigation(
                    "limit_reached",
                    source_query_count=len(source_queries),
                    evidence_request_count=len(requested),
                )
                emit_trace(
                    trace,
                    "navigation",
                    stage="limit_reached",
                    exchange=evidence_exchanges + 1,
                    requests=source_queries if isinstance(source_queries, list) else [],
                )
                return finish(
                    ("source navigation round limit reached",),
                    unknown_evidence_failure_reason or f"finder requested evidence after {followup_budget} follow ups",
                )
            try:
                delivered = _deliver_evidence_exchange(
                    context,
                    navigation,
                    requested=requested,
                    source_queries=source_queries,
                    target_chars=target_chars,
                    trace=trace,
                    exchange=evidence_exchanges + 1,
                )
            except (EvidenceRequestError, SourceNavigationError) as exc:
                call_observation.navigation(
                    "failed",
                    source_query_count=len(source_queries),
                    evidence_request_count=len(requested),
                    failure_reason=str(exc),
                )
                unresolved = tuple(requested) or (f"source navigation exchange {evidence_exchanges + 1}",)
                rejected = _delivery_rejection(
                    exc,
                    unresolved=unresolved,
                    provisional=provisional.findings,
                    requested=requested,
                    available_ids={
                        *(item.id for item in context.evidence),
                        *(item for item in available_refs if item != "seed"),
                        *(navigation.readable_ids if navigation is not None else ()),
                    },
                )
                if rejected is None:
                    return finish(unresolved, str(exc))
                raise rejected from exc
            coverage = merge_grounding_coverage((coverage, delivered.coverage))
            available_refs.update(delivered.coverage.references)
            source_evidence.extend(delivered.source_evidence)
            evidence_exchanges += 1
            call_observation.navigation(
                "delivered" if delivered.text else "not_requested",
                delta_ids=tuple(dict.fromkeys(item.id for item in delivered.source_evidence)),
                delta_text=delivered.text,
                source_query_count=len(source_queries),
                evidence_request_count=len(requested),
            )
            prompt = _continue_prompt(
                prompt,
                f"Evidence exchange {evidence_exchanges}:\n{delivered.text}",
                remaining(),
                provisional=_provisional_records(provisional.findings, finding_prompt_record),
                durable=True,
            )
        except _RejectedBatch as rejected:
            if corrections[rejected.kind] < 1:
                if rejected.fatal is not None and call_index == 0:
                    raise rejected.fatal from None
                return finish(rejected.unresolved, rejected.failure_reason)
            corrections[rejected.kind] -= 1
            if rejected.kind == "unknown_evidence":
                unknown_evidence_failure_reason = rejected.failure_reason
            prompt = _continue_prompt(
                prompt,
                rejected.instruction,
                remaining(),
                provisional=(
                    _provisional_records(rejected.provisional, finding_prompt_record)
                    if rejected.provisional is not None
                    else None
                ),
            )


_REPEATED_QUERY_CORRECTION = (
    "The previous response repeated an already executed source query. "
    "Do not repeat it. Use the evidence already delivered and return the final judgment."
)


def _delivery_rejection(
    exc: EvidenceRequestError | SourceNavigationError,
    *,
    unresolved: tuple[str, ...],
    provisional: list[object],
    requested: list[str],
    available_ids: set[str],
) -> _RejectedBatch | None:
    """Classify one undelivered exchange into its correction, or None when no correction applies."""
    failure = str(exc)
    if isinstance(exc, EvidenceBudgetError):
        return _RejectedBatch(
            "evidence_budget",
            f"The previous evidence exchange was not delivered because {failure}. "
            "No source query or evidence read from that exchange was committed. Return a smaller batch containing "
            "only the evidence and searches needed for the next decision. You may request the "
            "remaining independent items in a later exchange.",
            failure_reason=failure,
            unresolved=unresolved,
            provisional=provisional,
        )
    if isinstance(exc, UnknownDefinitionQueryError):
        return _RejectedBatch(
            "unknown_definition",
            "The previous response requested call candidates for an unpublished definition. "
            "Only use a `def-*` id returned by an earlier search in this session. Use the delivered evidence "
            "or return the final judgment instead.",
            failure_reason=failure,
            unresolved=unresolved,
        )
    if isinstance(exc, UnknownEvidenceRequest):
        valid_requested_ids = tuple(item for item in requested if item in available_ids)
        valid_text = (
            " The other ids in the rejected batch were valid but were not delivered. Resubmit only these exact ids: "
            + ", ".join(f"`{item}`" for item in valid_requested_ids)
            + "."
            if valid_requested_ids
            else ""
        )
        return _RejectedBatch(
            "unknown_evidence",
            f"The previous response requested {len(exc.ids)} unpublished evidence ids. "
            f"{valid_text} Use only an exact id published earlier in this judgment. Do not invent or "
            "transform ids. Use already delivered evidence or return the final judgment.",
            failure_reason=failure,
            unresolved=unresolved,
        )
    if isinstance(exc, RepeatedSourceQueryError):
        return _RejectedBatch(
            "repeated_query",
            _REPEATED_QUERY_CORRECTION,
            failure_reason=failure,
            unresolved=unresolved,
        )
    return None


def _prompt_revision(context: GroundingContext, prompt: EvidencePromptContext) -> str:
    """Identify the exact source and controls visible to one model call."""
    snapshot_key = context.source_snapshot.snapshot_id if context.source_snapshot is not None else ""
    material = "\x00".join(("model-prompt-v1", snapshot_key, prompt.source, prompt.controls))
    return f"revision-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"


def _continue_prompt(
    prompt: EvidencePromptContext,
    instruction: str,
    remaining: int,
    *,
    provisional: tuple[Mapping[str, object], ...] | None = None,
    durable: bool = False,
) -> EvidencePromptContext:
    """Keep delivered evidence and replace the correction, provisional findings, and budget."""
    text = instruction.strip()
    return replace(
        prompt,
        revision=prompt.revision + 1,
        delivered=(*prompt.delivered, text) if durable else prompt.delivered,
        correction="" if durable else text,
        provisional=_provisional_instruction(provisional) if provisional is not None else prompt.provisional,
        budget=_request_budget_instruction(remaining, navigation_available=prompt.navigation_available),
    )


def _evidence_judgment[T](
    *,
    findings: list[T],
    coverage: GroundingCoverage,
    source_evidence: list[SourceEvidence],
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
        source_evidence=tuple(source_evidence),
    )


def _provisional_records[T](
    findings: list[T],
    record: Callable[[T], Mapping[str, object]] | None,
) -> tuple[Mapping[str, object], ...]:
    """Keep exact provisional candidates visible across independent model calls."""
    if not findings:
        return ()
    if record is None:
        raise ValueError("provisional findings require a stable prompt record adapter")
    return tuple(record(finding) for finding in findings)


def _provisional_instruction(provisional: tuple[Mapping[str, object], ...]) -> str:
    """Render the prior proposals that a terminal response must decide."""
    if not provisional:
        return ""
    return (
        "Provisional findings from your earlier responses, retained by the engine but not accepted yet:\n"
        f"{json.dumps(provisional, ensure_ascii=False, sort_keys=True)}\n"
        "Return a finding again only to change its content. Omitting it does not withdraw it."
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
    requested_evidence_ids = evidence_request_ids(raw_requested)
    repeated_evidence_requests = tuple(item for item in requested_evidence_ids if item in available_refs)
    unread_evidence_ids = tuple(item for item in requested_evidence_ids if item not in available_refs)
    if not isinstance(raw_queries, list):
        raise SourceNavigationError("source_queries must be a list")
    try:
        source_queries = parse_source_queries(raw_queries)
    except SourceQueryLimitError as exc:
        exc.response_findings = tuple(findings)
        raise
    requested: list[object] = [*unread_evidence_ids]
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
        repeated_evidence_requests=repeated_evidence_requests,
    )


def _with_request_budget(prompt: EvidencePromptContext, remaining: int) -> EvidencePromptContext:
    """Publish the bounded request budget as the final prompt control."""
    return replace(
        prompt,
        budget=_request_budget_instruction(remaining, navigation_available=prompt.navigation_available),
    )


def _request_budget_instruction(remaining: int, *, navigation_available: bool) -> str:
    """Tell the model whether another evidence request can be fulfilled."""
    if remaining == 0:
        return (
            "No evidence or source request batches remain. Return the final judgment using only source "
            "already delivered, with empty `evidence_requests` and `source_queries`. "
            "A further request makes this judgment incomplete."
        )
    label = "batch remains" if remaining == 1 else "batches remain"
    budget = f"Evidence request budget: {remaining} request {label}."
    if not navigation_available:
        return f"Source navigation is unavailable. Return an empty `source_queries` list. {budget}"
    return budget


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
    invalid: list[int] = []
    for index, finding in enumerate(findings):
        unknown = tuple(ref for ref in evidence_refs(finding) if ref not in available)
        if not unknown:
            accepted.append(finding)
        elif set(unknown).issubset(requested):
            deferred.append(finding)
        else:
            invalid.append(index)
    if invalid:
        readable = ", ".join(sorted(available))
        raise CorrectableRoleResponseError(
            f"{', '.join(f'findings[{index}].evidence_refs' for index in invalid)} contain unread source ids. "
            f"Return the response again using only these readable ids: {readable}. "
            "Request any other published evidence before citing it. Do not invent or alter an evidence id.",
            response_findings=tuple(accepted),
            fallback_findings=tuple(findings),
        )
    return accepted, deferred


def _deliver_evidence_exchange(
    context: GroundingContext,
    navigation: SourceNavigationSession | None,
    *,
    requested: list[str],
    source_queries: list[dict[str, object]],
    target_chars: int,
    trace: Trace | None,
    exchange: int,
) -> _DeliveredEvidence:
    """Deliver one request batch under one budget and one coverage commit."""
    transaction = navigation.transaction() if navigation is not None else nullcontext()
    with transaction:
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
        navigation_blocks = [f"Requested exact repository evidence:\n{exact.text}"] if exact.text else []
        if navigated.text:
            navigation_blocks.append(navigated.text)
        text = "\n\n".join(navigation_blocks)
        one_indivisible_item = len(requested) + len(source_queries) == 1
        if len(text) > target_chars and not one_indivisible_item:
            raise EvidenceRequestError(f"evidence exchange exceeds the {target_chars} character target")
    coverage = merge_grounding_coverage((exact.coverage, navigated.coverage))
    if exact.text:
        emit_trace(
            trace,
            "evidence",
            stage="delivered",
            ids=list(exact.coverage.references),
            identities=list(exact.coverage.included),
            characters=len(exact.text),
        )
    if navigated.text:
        emit_trace(
            trace,
            "navigation",
            stage="delivered",
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
        raise UnknownEvidenceRequest(unknown)

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


def _identity_receipt(value: Hashable) -> str:
    """Identify one adapter key without persisting target specific fields."""

    def data(item: object) -> object:
        if item is None or isinstance(item, str | int | float | bool):
            return item
        if isinstance(item, tuple):
            return [data(part) for part in item]
        raise TypeError(f"finding identity contains unsupported {type(item).__name__}")

    encoded = json.dumps(data(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return f"union-{hashlib.sha256(encoded.encode()).hexdigest()[:24]}"


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

    @property
    def identity_receipts(self) -> tuple[str, ...]:
        """Expose stable opaque identities in union insertion order."""
        return tuple(_identity_receipt(identity) for identity in self.pool)


@dataclass(frozen=True, kw_only=True)
class ReviewCycle[T]:
    """One target adapter result consumed by the shared scheduler."""

    findings: list[T]
    incomplete: list[T] = field(default_factory=list)
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()

    @property
    def clean(self) -> bool:
        """Allow judgment with visible limitations while rejecting unavailable evidence."""
        return not self.incomplete and self.errors == 0 and not self.failure_reason and self.grounding.reviewable


@dataclass(frozen=True, kw_only=True)
class ReviewOutcome[T]:
    """The shared completion contract for one review target."""

    findings: tuple[T, ...]
    failures: tuple[ReviewUnitFailure, ...] = ()
    incomplete: tuple[T, ...] = ()
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()
    scheduling: SchedulingReceipt | None = None

    def __post_init__(self) -> None:
        """Bound the persisted failure reason."""
        if len(self.failure_reason) > _FAILURE_REASON_LIMIT:
            end = _FAILURE_REASON_LIMIT - len(_FAILURE_REASON_TRUNCATED)
            object.__setattr__(self, "failure_reason", self.failure_reason[:end] + _FAILURE_REASON_TRUNCATED)

    @property
    def complete(self) -> bool:
        """Require no failed or incomplete judgment step."""
        return (
            not self.failures
            and not self.incomplete
            and self.errors == 0
            and not self.failure_reason
            and self.grounding.complete
        )

    @property
    def degraded(self) -> bool:
        """Expose every incomplete outcome through one target-neutral signal."""
        return not self.complete


def _unique_values[T](values: Iterable[T]) -> tuple[T, ...]:
    unique: list[T] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return tuple(unique)


def extend_review_outcome[T](
    outcome: ReviewOutcome[T],
    *,
    findings: Iterable[T],
    failures: Iterable[ReviewUnitFailure] = (),
    incomplete: Iterable[T] = (),
    errors: int = 0,
    failure_reason: str = "",
    grounding: GroundingCoverage | None = None,
) -> ReviewOutcome[T]:
    """Add target postprocessing without losing the shared completion state."""
    return ReviewOutcome(
        findings=tuple(findings),
        failures=_unique_values((*outcome.failures, *failures)),
        incomplete=_unique_values((*outcome.incomplete, *incomplete)),
        errors=outcome.errors + errors,
        failure_reason=". ".join(reason for reason in (outcome.failure_reason, failure_reason) if reason),
        grounding=merge_grounding_coverage(
            (outcome.grounding, grounding) if grounding is not None else (outcome.grounding,)
        ),
        source_evidence=outcome.source_evidence,
        scheduling=outcome.scheduling,
    )


def _failure_reason(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def run_grounded_judgment[T](
    context: GroundingContext,
    *,
    run_judgment: Callable[[SourceNavigationSession | None], EvidenceJudgment[T]],
    label: str,
    finder_label: str,
    on_judgment: JudgmentProgress | None = None,
    trace: Trace | None = None,
) -> ReviewCycle[T]:
    """Run one grounded judgment per unit and keep candidates produced before a failure."""
    started = perf_counter()
    navigation = context.navigator.session() if context.navigator is not None else None
    emit_trace(trace, "judgment", stage="selected", evidence_revision=context.revision.id, label=label)
    try:
        judgment = run_judgment(navigation)
    except Exception as exc:
        judgment = EvidenceJudgment(findings=[], failure_reason=_failure_reason(exc))
    findings = tag_found_by(judgment.findings, finder_label)
    final = with_source_evidence(context, judgment.source_evidence)
    emit_trace(
        trace,
        "judgment",
        stage="finished",
        evidence_revision=final.revision.id,
        label=label,
        count=len(findings),
        status="failed" if judgment.failure_reason else "ok",
        reason=judgment.failure_reason[:500],
    )
    if on_judgment is not None:
        on_judgment(label, round(perf_counter() - started, 1))
    failure_reason = f"{judgment.failure_reason} [review judgment for {label}]" if judgment.failure_reason else ""
    return ReviewCycle(
        findings=findings,
        errors=int(bool(failure_reason)),
        failure_reason=failure_reason,
        grounding=merge_grounding_coverage((final.coverage, judgment.grounding)),
        source_evidence=final.source_evidence,
    )


def run_review_units[U, T](
    units: list[U],
    *,
    execute: Callable[[U, list[T]], ReviewCycle[T]],
    accumulator: FindingAccumulator[T],
    unit_identity: Callable[[U], str],
    failure_for: Callable[[int, int, U, str], ReviewUnitFailure],
    concurrency: int = 1,
    on_unit: Callable[[U, float], None] | None = None,
) -> ReviewOutcome[T]:
    """Review every unit once, continue past failed units, and record each failure."""
    if not units:
        raise ValueError("at least one review unit is required")
    positive_concurrency(concurrency, "review concurrency")
    unit_ids = tuple(unit_identity(unit) for unit in units)
    if any(not identity for identity in unit_ids):
        raise ValueError("review unit identities must be nonempty")
    if len(set(unit_ids)) != len(unit_ids):
        raise ValueError("review unit identities must be unique")
    started = perf_counter()
    unit_lock = Lock()
    known = accumulator.findings

    def invoke(owned: tuple[str, U]) -> ReviewCycle[T]:
        unit_id, unit = owned
        unit_started = perf_counter()
        try:
            with model_call_scope(unit_id=unit_id):
                return execute(unit, known)
        except Exception as exc:
            return ReviewCycle(findings=[], errors=1, failure_reason=_failure_reason(exc))
        finally:
            if on_unit is not None:
                with unit_lock, suppress(Exception):
                    on_unit(unit, round(perf_counter() - unit_started, 1))

    owned_units = list(zip(unit_ids, units, strict=True))
    if concurrency > 1 and len(units) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(invoke, owned_units))
    else:
        results = [invoke(owned) for owned in owned_units]

    prior_identity_receipts = set(accumulator.identity_receipts)
    for result in results:
        accumulator.add(result.findings)
    union_identity_receipts = accumulator.identity_receipts
    failures = tuple(
        failure_for(
            index,
            len(units),
            unit,
            result.failure_reason or result.grounding.failure_reason or "review unit failed",
        )
        for index, (unit, result) in enumerate(zip(units, results, strict=True), 1)
        if not result.clean
    )
    incomplete = _unique_values(item for result in results for item in result.incomplete)
    errors = sum(result.errors or int(not result.clean) for result in results)
    source_evidence: dict[str, SourceEvidence] = {}
    for item in (evidence for result in results for evidence in result.source_evidence):
        prior = source_evidence.get(item.id)
        if prior is not None and prior != item:
            raise ValueError(f"source evidence {item.id} changed across review units")
        source_evidence[item.id] = item
    grounding = merge_grounding_coverage(tuple(result.grounding for result in results))
    clean = not failures and not incomplete and errors == 0 and grounding.reviewable
    return ReviewOutcome(
        findings=tuple(accumulator.findings),
        failures=failures,
        incomplete=incomplete,
        errors=errors,
        failure_reason=grounding.failure_reason,
        grounding=grounding,
        source_evidence=tuple(source_evidence.values()),
        scheduling=SchedulingReceipt.create(
            unit_ids=unit_ids,
            new_finding_ids=tuple(item for item in union_identity_receipts if item not in prior_identity_receipts),
            union_finding_ids=union_identity_receipts,
            errors=errors,
            failures=len(failures),
            incomplete=len(incomplete),
            clean=clean,
            duration_seconds=round(perf_counter() - started, 3),
        ),
    )
