"""Shared judgment orchestration for every review target."""

from __future__ import annotations

import json
from collections.abc import Callable, Hashable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from threading import Lock
from time import perf_counter
from typing import Protocol

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.base import ResponseSchema
from cyberjury.providers.metering import (
    model_call_context,
    model_call_scope,
    record_model_exchange,
    record_model_parse,
)
from cyberjury.review.context import (
    MAX_EVIDENCE_REQUESTS_PER_BATCH,
    EvidenceBudgetError,
    EvidencePromptContext,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    UnknownEvidenceRequest,
    evidence_request_ids,
    is_evidence_id,
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
from cyberjury.review.schemas import validate_response_object


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

    def fail(message: str) -> None:
        record_model_parse(message)
        raise RoleResponseError(message)

    if parsed is None:
        message = f"{role} reply had no complete JSON object"
        record_model_parse(message)
        raise CorrectableRoleResponseError(
            f"{message}. Return exactly one JSON object that follows the response schema."
        )
    try:
        obj = validate_response_object(parsed, response_schema)
    except ValueError as exc:
        fail(f"{role} reply violates {response_schema.name}: {exc}")
    record_model_parse()
    return obj


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
    findings: list[T]
    requested: list[str]
    source_queries: list[dict[str, object]]
    deferred: list[T]
    repeated_evidence_requests: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _DeliveredEvidence:
    text: str
    coverage: GroundingCoverage
    source_evidence: tuple[SourceEvidence, ...]


class _RejectedBatch(Exception):
    def __init__(
        self,
        kind: str,
        instruction: str,
        *,
        failure_reason: str,
        unresolved: tuple[str, ...],
        fatal: Exception | None = None,
    ) -> None:
        self.kind = kind
        self.instruction = instruction
        self.failure_reason = failure_reason
        self.unresolved = unresolved
        self.fatal = fatal
        super().__init__(failure_reason)


class _MalformedEvidenceRequest(EvidenceRequestError):
    def __init__(self, failure: str, findings: tuple[object, ...], requested: tuple[str, ...]) -> None:
        self.findings = findings
        self.requested = requested
        super().__init__(failure)


class _EvidenceExchange[T]:
    def __init__(
        self,
        context: GroundingContext,
        *,
        findings_from_reply: Callable[[RoleReply], list[T]],
        accumulator: FindingAccumulator[T],
        target_chars: int,
        max_followups: int,
        evidence_refs: Callable[[T], tuple[str, ...]],
        navigation: SourceNavigationSession | None,
        finding_prompt_record: Callable[[T], Mapping[str, object]],
        merge_rule: str,
    ) -> None:
        self.context = context
        self.navigation = navigation
        self.findings_from_reply = findings_from_reply
        self.evidence_refs = evidence_refs
        self.finding_prompt_record = finding_prompt_record
        self.merge_rule = merge_rule
        self.target_chars = target_chars
        self.accumulator = accumulator
        self.provisional = self._union()
        self.correction_fallback = self._union()
        self.followup_budget = max_followups if navigation is not None or context.evidence else 0
        self.prompt = _with_request_budget(
            replace(context.prompt, navigation_available=navigation is not None),
            self.followup_budget,
        )
        initial_source_coverage = GroundingCoverage(
            included=tuple(dict.fromkeys(item.identity for item in context.source_evidence)),
            references=tuple(dict.fromkeys(item.id for item in context.source_evidence)),
        )
        self.coverage = merge_grounding_coverage((context.coverage, initial_source_coverage))
        self.available_refs = {"seed", *self.coverage.references}
        self.source_evidence: list[SourceEvidence] = list(context.source_evidence)
        self.evidence_exchanges = 0
        self.turn = _Turn()
        self.corrections = dict(_CORRECTION_BUDGET)
        self.unknown_evidence_failure_reason = ""
        if navigation is not None:
            navigation.record_delivered(context.source_evidence, seed_spans=context.source_spans)

    def _union(self) -> FindingAccumulator[T]:
        return FindingAccumulator(key=self.accumulator.key, fold=self.accumulator.fold)

    def _retained_findings(self) -> list[T]:
        retained = self._union()
        retained.add(self.correction_fallback.findings)
        retained.add(self.accumulator.findings)
        retained.add(self.provisional.findings)
        return retained.findings

    def _accepted_records(self) -> tuple[Mapping[str, object], ...]:
        accepted = self._union()
        accepted.add(self.accumulator.findings)
        accepted.add(self.provisional.findings)
        return tuple(self.finding_prompt_record(finding) for finding in accepted.findings)

    def _published_ids(self) -> set[str]:
        return {
            *(item.id for item in self.context.evidence),
            *(item for item in self.available_refs if item != "seed"),
            *(self.navigation.readable_ids if self.navigation is not None else ()),
        }

    def _remaining(self) -> int:
        return max(0, self.followup_budget - self.evidence_exchanges)

    def finish(
        self,
        unresolved: tuple[str, ...],
        failure_reason: str,
        findings: list[T] | None = None,
    ) -> EvidenceJudgment[T]:
        return _evidence_judgment(
            findings=self._retained_findings() if findings is None else findings,
            coverage=self.coverage,
            unresolved=unresolved,
            failure_reason=failure_reason,
            source_evidence=self.source_evidence,
        )

    def read_reply(
        self, ask: Callable[[EvidencePromptContext], RoleReply], call_index: int
    ) -> _ParsedEvidenceReply[T] | EvidenceJudgment[T]:
        self.turn = _Turn()
        try:
            return _parse_evidence_reply(
                ask(self.prompt),
                findings_from_reply=self.findings_from_reply,
                evidence_refs=self.evidence_refs,
                available_refs=self.available_refs,
                evidence_ids={item.id for item in self.context.evidence},
                navigation=self.navigation,
            )
        except CorrectableRoleResponseError as exc:
            record_model_parse(_failure_reason(exc))
            self.accumulator.add(exc.response_findings)
            self.correction_fallback.add(exc.fallback_findings)
            raise _RejectedBatch(
                "response",
                f"Response correction required. {exc.instruction} {_CORRECTED_RESPONSE} "
                "Do not repeat the invalid value.",
                failure_reason=_failure_reason(exc),
                unresolved=("model response violates a deterministic response constraint",),
            ) from exc
        except _MalformedEvidenceRequest as exc:
            record_model_parse(_failure_reason(exc))
            self.correction_fallback.add(exc.findings)
            unread = self._published_ids() - self.available_refs
            raise _RejectedBatch(
                "unknown_evidence",
                _malformed_request_correction(str(exc), tuple(item for item in exc.requested if item in unread)),
                failure_reason=_failure_reason(exc),
                unresolved=("model requested an evidence id outside the published id format",),
            ) from exc
        except SourceQueryLimitError as exc:
            record_model_parse(_failure_reason(exc))
            self.accumulator.add(exc.response_findings)
            raise _RejectedBatch(
                "query_limit",
                f"The previous response returned {exc.count} source queries, but one batch permits "
                f"at most {exc.limit}. No query in that batch was executed. Return at most {exc.limit} "
                "distinct queries, keeping only the searches needed to decide the current candidates.",
                failure_reason=_failure_reason(exc),
                unresolved=("source query batch exceeds the published limit",),
                fatal=exc,
            ) from exc
        except Exception as exc:
            record_model_parse(_failure_reason(exc))
            if call_index == 0:
                raise
            return self.finish((f"model response {call_index + 1} failed",), _failure_reason(exc))

    def accept(self, reply: _ParsedEvidenceReply[T]) -> EvidenceJudgment[T] | None:
        requested = [
            str(item)
            for item in _implicit_reference_requests(
                list(self.provisional.findings),
                evidence_refs=self.evidence_refs,
                available=self.available_refs,
                evidence_ids={item.id for item in self.context.evidence},
                navigation=self.navigation,
                evidence_requests=list(reply.requested),
            )
        ]
        self.turn.findings = len(reply.findings)
        self.turn.deferred = len(reply.deferred)
        self.turn.requested = requested
        self.turn.source_queries = [dict(query) for query in reply.source_queries]
        repeated_queries = tuple(
            query
            for query in reply.source_queries
            if self.navigation is not None and self.navigation.query_was_executed(query)
        )
        source_queries = [query for query in reply.source_queries if query not in repeated_queries]
        if repeated_queries and not source_queries and not requested and not reply.findings:
            failure_reason = "source query repeats an earlier query in this session"
            raise _RejectedBatch(
                "repeated_query",
                _REPEATED_QUERY_CORRECTION,
                failure_reason=failure_reason,
                unresolved=(failure_reason,),
            )
        if not requested and not source_queries:
            repeated_requests = reply.repeated_evidence_requests
            if repeated_requests and not reply.findings:
                raise _RejectedBatch(
                    "delivered_request",
                    f"These requested items are already delivered: {', '.join(repeated_requests)}. "
                    "Cite source receipts directly. Do not request these items again. "
                    "Return the judgment or request different unread evidence.",
                    failure_reason="model repeated an already delivered request without a judgment",
                    unresolved=repeated_requests,
                )
            self.accumulator.add(self.provisional.findings)
            self.accumulator.add(reply.findings)
            return self.finish((), "", findings=self.accumulator.findings)
        self.provisional.add((*reply.findings, *reply.deferred))
        cited_only = [item for item in requested if item not in reply.requested]
        if self.evidence_exchanges >= self.followup_budget and cited_only == requested and not source_queries:
            return self.finish(
                tuple(cited_only),
                "findings cite evidence that did not fit in the evidence budget before the follow ups ran out",
            )
        if self.evidence_exchanges >= self.followup_budget:
            return self.finish(
                ("source navigation round limit reached",),
                self.unknown_evidence_failure_reason
                or f"finder requested evidence after {self.followup_budget} follow ups",
            )
        return self._deliver(requested, source_queries)

    def _deliver(self, requested: list[str], source_queries: list[dict[str, object]]) -> EvidenceJudgment[T] | None:
        try:
            delivered, held_ids, held_queries = _deliver_within_budget(
                self.context,
                self.navigation,
                requested=requested,
                source_queries=source_queries,
                target_chars=self.target_chars,
            )
        except (EvidenceRequestError, SourceNavigationError) as exc:
            unresolved = tuple(requested) or (f"source navigation exchange {self.evidence_exchanges + 1}",)
            rejected = _delivery_rejection(
                exc,
                unresolved=unresolved,
                requested=requested,
                available_ids=self._published_ids(),
            )
            if rejected is None:
                return self.finish(unresolved, str(exc))
            raise rejected from exc
        self.turn.delivered = list(delivered.coverage.references)
        self.turn.delivered_chars = len(delivered.text)
        self.turn.held = [*held_ids, *(json.dumps(query, sort_keys=True) for query in held_queries)]
        self.coverage = merge_grounding_coverage((self.coverage, delivered.coverage))
        self.available_refs.update(delivered.coverage.references)
        self.source_evidence.extend(delivered.source_evidence)
        self.evidence_exchanges += 1
        held = _held_notice(held_ids, held_queries, self.target_chars, rounds_left=self._remaining())
        self.prompt = _continue_prompt(
            self.prompt,
            f"Evidence exchange {self.evidence_exchanges}:\n{delivered.text}{held}",
            self._remaining(),
            accepted=self._accepted_records(),
            merge_rule=self.merge_rule,
            durable=True,
        )
        return None

    def reject(self, rejected: _RejectedBatch, call_index: int) -> EvidenceJudgment[T] | None:
        self.turn.correction = rejected.kind
        if self.corrections[rejected.kind] < 1:
            if rejected.fatal is not None and call_index == 0:
                raise rejected.fatal from None
            return self.finish(rejected.unresolved, rejected.failure_reason)
        self.corrections[rejected.kind] -= 1
        if rejected.kind == "unknown_evidence":
            self.unknown_evidence_failure_reason = rejected.failure_reason
        self.prompt = _continue_prompt(
            self.prompt,
            rejected.instruction,
            self._remaining(),
            accepted=self._accepted_records(),
            merge_rule=self.merge_rule,
        )
        return None


def run_evidence_judgment[T](
    context: GroundingContext,
    *,
    ask: Callable[[EvidencePromptContext], RoleReply],
    findings_from_reply: Callable[[RoleReply], list[T]],
    accumulator: FindingAccumulator[T],
    target_chars: int,
    max_followups: int,
    evidence_refs: Callable[[T], tuple[str, ...]],
    navigation: SourceNavigationSession | None,
    finding_prompt_record: Callable[[T], Mapping[str, object]],
    merge_rule: str,
) -> EvidenceJudgment[T]:
    """Run bounded evidence and source navigation without losing earlier findings."""
    exchange = _EvidenceExchange(
        context,
        findings_from_reply=findings_from_reply,
        accumulator=accumulator,
        target_chars=target_chars,
        max_followups=max_followups,
        evidence_refs=evidence_refs,
        navigation=navigation,
        finding_prompt_record=finding_prompt_record,
        merge_rule=merge_rule,
    )
    call_index = 0
    while True:
        with model_call_context(
            role="finder",
            trigger="initial_judgment" if call_index == 0 else "evidence_followup",
        ):
            try:
                reply = exchange.read_reply(ask, call_index)
                result = reply if isinstance(reply, EvidenceJudgment) else exchange.accept(reply)
            except _RejectedBatch as rejected:
                result = exchange.reject(rejected, call_index)
            record_model_exchange(_exchange_record(exchange.turn, result))
        if result is not None:
            return result
        call_index += 1


@dataclass(kw_only=True)
class _Turn:
    findings: int = 0
    deferred: int = 0
    requested: list[str] = field(default_factory=list)
    source_queries: list[dict[str, object]] = field(default_factory=list)
    delivered: list[str] = field(default_factory=list)
    delivered_chars: int = 0
    held: list[str] = field(default_factory=list)
    correction: str | None = None


def _exchange_record(turn: _Turn, result: EvidenceJudgment[object] | None) -> dict[str, object]:
    if result is None:
        outcome, stop_reason = ("correction" if turn.correction is not None else "evidence"), ""
    elif result.failure_reason:
        outcome, stop_reason = "stopped", result.failure_reason
    else:
        outcome, stop_reason = "judgment", ""
    return {
        "outcome": outcome,
        "findings": turn.findings,
        "deferred": turn.deferred,
        "requested": turn.requested,
        "source_queries": turn.source_queries,
        "delivered": turn.delivered,
        "delivered_chars": turn.delivered_chars,
        "held": turn.held,
        "correction": turn.correction,
        "stop_reason": stop_reason,
    }


_CORRECTED_RESPONSE = "Return the corrected response. Previously accepted findings are kept."


def _malformed_request_correction(failure: str, valid_ids: tuple[str, ...]) -> str:
    resubmit = (
        " These requested ids are published and may be requested again: "
        + ", ".join(f"`{item}`" for item in valid_ids)
        + "."
        if valid_ids
        else ""
    )
    return (
        f"The previous response was not committed because {failure}. No evidence was delivered and none of its "
        f"findings were accepted.{resubmit} Request only exact ids published in this review. Do not invent or "
        f"transform ids. {_CORRECTED_RESPONSE}"
    )


_REPEATED_QUERY_CORRECTION = (
    "The previous response repeated an already executed source query. "
    "Do not repeat it. Use the evidence already delivered and return the final judgment."
)


def _delivery_rejection(
    exc: EvidenceRequestError | SourceNavigationError,
    *,
    unresolved: tuple[str, ...],
    requested: list[str],
    available_ids: set[str],
) -> _RejectedBatch | None:
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


def _continue_prompt(
    prompt: EvidencePromptContext,
    instruction: str,
    remaining: int,
    *,
    accepted: tuple[Mapping[str, object], ...],
    merge_rule: str,
    durable: bool = False,
) -> EvidencePromptContext:
    text = instruction.strip()
    return replace(
        prompt,
        delivered=(*prompt.delivered, text) if durable else prompt.delivered,
        correction="" if durable else text,
        provisional=_accepted_instruction(accepted, merge_rule),
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
    grounding = (
        merge_grounding_coverage((coverage, GroundingCoverage(unresolved=unresolved))) if unresolved else coverage
    )
    return EvidenceJudgment(
        findings=findings,
        grounding=grounding,
        failure_reason=failure_reason,
        source_evidence=tuple(source_evidence),
    )


def _accepted_instruction(accepted: tuple[Mapping[str, object], ...], merge_rule: str) -> str:
    if not accepted:
        return ""
    return (
        "Findings already accepted for this unit from your earlier responses:\n"
        f"{json.dumps(accepted, ensure_ascii=False, sort_keys=True)}\n"
        "They stay accepted whether or not you return them, and they cannot be edited or withdrawn. "
        f"{merge_rule} Return only new findings."
    )


def _parse_evidence_reply[T](
    reply: RoleReply,
    *,
    findings_from_reply: Callable[[RoleReply], list[T]],
    evidence_refs: Callable[[T], tuple[str, ...]],
    available_refs: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
) -> _ParsedEvidenceReply[T]:
    findings = findings_from_reply(reply)
    raw_requests = reply.get("evidence_requests", [])
    try:
        requested_evidence_ids = evidence_request_ids(raw_requests)
    except EvidenceRequestError as exc:
        well_formed = tuple(
            item
            for item in (raw_requests if isinstance(raw_requests, list) else ())
            if isinstance(item, str) and is_evidence_id(item)
        )
        raise _MalformedEvidenceRequest(str(exc), tuple(findings), tuple(dict.fromkeys(well_formed))) from exc
    repeated_evidence_requests = tuple(item for item in requested_evidence_ids if item in available_refs)
    unread_evidence_ids = tuple(item for item in requested_evidence_ids if item not in available_refs)
    try:
        source_queries = parse_source_queries(reply.get("source_queries", []))
    except SourceQueryLimitError as exc:
        exc.response_findings = tuple(findings)
        raise
    requested = _implicit_reference_requests(
        findings,
        evidence_refs=evidence_refs,
        available=available_refs,
        evidence_ids=evidence_ids,
        navigation=navigation,
        evidence_requests=[*unread_evidence_ids],
    )
    ids = list(evidence_request_ids(requested))
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
    return replace(
        prompt,
        budget=_request_budget_instruction(remaining, navigation_available=prompt.navigation_available),
    )


def _request_budget_instruction(remaining: int, *, navigation_available: bool) -> str:
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
            f"{', '.join(f'findings[{index}].evidence_refs' for index in invalid)} cite ids that are not published "
            f"in this review. Cite only delivered ids ({readable}) or request a published catalog id before citing "
            "it. Do not invent or alter an evidence id.",
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
) -> _DeliveredEvidence:
    transaction = navigation.transaction() if navigation is not None else nullcontext()
    with transaction:
        exact = (
            _deliver_exact_evidence(context, navigation, requested, target_chars=target_chars)
            if requested
            else SourceNavigationResult(text="")
        )
        if navigation is not None:
            navigation.record_delivered(exact.source_evidence)
        if source_queries and navigation is None:
            raise SourceNavigationError("source_queries are unavailable for this judgment")
        navigated = (
            navigation.execute(source_queries, target_chars=target_chars)
            if navigation is not None and source_queries
            else SourceNavigationResult(text="")
        )
        navigation_blocks = [exact.text] if exact.text else []
        if navigated.text:
            navigation_blocks.append(navigated.text)
        text = "\n\n".join(navigation_blocks)
        one_indivisible_item = len(requested) + len(source_queries) == 1
        if len(text) > target_chars and not one_indivisible_item:
            raise EvidenceBudgetError(f"evidence exchange exceeds the {target_chars} character target")
    coverage = merge_grounding_coverage((exact.coverage, navigated.coverage))
    return _DeliveredEvidence(
        text=text,
        coverage=coverage,
        source_evidence=(*exact.source_evidence, *navigated.source_evidence),
    )


def _deliver_within_budget(
    context: GroundingContext,
    navigation: SourceNavigationSession | None,
    *,
    requested: list[str],
    source_queries: list[dict[str, object]],
    target_chars: int,
) -> tuple[_DeliveredEvidence, list[str], list[dict[str, object]]]:
    capped = requested[:MAX_EVIDENCE_REQUESTS_PER_BATCH]
    for kept in range(len(capped) + len(source_queries), 0, -1):
        kept_ids, kept_queries = capped[:kept], source_queries[: max(0, kept - len(capped))]
        try:
            delivered = _deliver_evidence_exchange(
                context,
                navigation,
                requested=kept_ids,
                source_queries=kept_queries,
                target_chars=target_chars,
            )
        except EvidenceBudgetError:
            if kept == 1:
                raise
            continue
        return delivered, requested[len(kept_ids) :], source_queries[len(kept_queries) :]
    raise ValueError("an evidence exchange needs at least one request")


def _held_notice(
    held_ids: list[str], held_queries: list[dict[str, object]], target_chars: int, *, rounds_left: int
) -> str:
    if not held_ids and not held_queries:
        return ""
    held = [f"`{item}`" for item in held_ids] + [json.dumps(query, sort_keys=True) for query in held_queries]
    notice = f"\n\nNot delivered in this exchange because the batch exceeds the {target_chars} character target: "
    if not rounds_left:
        return f"{notice}{', '.join(held)}."
    return (
        f"{notice}{', '.join(held)}. Evidence cited by a finding is requested again automatically. Request the "
        "other items in a later exchange only if they are still needed."
    )


def _deliver_exact_evidence(
    context: GroundingContext,
    navigation: SourceNavigationSession | None,
    requested: object,
    *,
    target_chars: int,
) -> SourceNavigationResult:
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
    cited: list[object] = []
    for finding in findings:
        for reference in evidence_refs(finding):
            if reference in available or reference in cited:
                continue
            if reference in evidence_ids or (navigation is not None and navigation.can_read(reference)):
                cited.append(reference)
    return [*cited, *(item for item in evidence_requests if item not in cited)]


@dataclass
class FindingAccumulator[T]:
    """A monotonic finding union configured by one target policy."""

    key: Callable[[T], Hashable]
    fold: Callable[[T, T], T]
    pool: dict[Hashable, T] = field(default_factory=dict)

    def add(self, findings: Iterable[T]) -> int:
        """Fold one set into the union and return its new identity count."""
        new = 0
        for finding in findings:
            identity = self.key(finding)
            existing = self.pool.get(identity)
            if existing is None:
                self.pool[identity] = finding
                new += 1
            else:
                self.pool[identity] = self.fold(existing, finding)
        return new

    @property
    def findings(self) -> list[T]:
        """Return the stable insertion ordered union."""
        return list(self.pool.values())


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
        return not self.incomplete and self.errors == 0 and not self.failure_reason and self.grounding.complete


@dataclass(frozen=True, kw_only=True)
class ReviewOutcome[T]:
    """The shared completion contract for one review target."""

    findings: tuple[T, ...]
    failures: tuple[ReviewUnitFailure, ...] = ()
    incomplete: tuple[T, ...] = ()
    errors: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)

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
        failures=tuple(dict.fromkeys((*outcome.failures, *failures))),
        incomplete=tuple(dict.fromkeys((*outcome.incomplete, *incomplete))),
        errors=outcome.errors + errors,
        failure_reason=". ".join(reason for reason in (outcome.failure_reason, failure_reason) if reason),
        grounding=merge_grounding_coverage(
            (outcome.grounding, grounding) if grounding is not None else (outcome.grounding,)
        ),
    )


def _failure_reason(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def run_grounded_judgment[T](
    context: GroundingContext,
    *,
    run_judgment: Callable[[SourceNavigationSession | None], EvidenceJudgment[T]],
    finder_label: str,
) -> ReviewCycle[T]:
    """Run one grounded judgment per unit and keep candidates produced before a failure."""
    navigation = context.navigator.session() if context.navigator is not None else None
    try:
        judgment = run_judgment(navigation)
    except Exception as exc:
        judgment = EvidenceJudgment(findings=[], failure_reason=_failure_reason(exc))
    final = with_source_evidence(context, judgment.source_evidence)
    return ReviewCycle(
        findings=tag_found_by(judgment.findings, finder_label),
        errors=int(bool(judgment.failure_reason)),
        failure_reason=judgment.failure_reason,
        grounding=merge_grounding_coverage((final.coverage, judgment.grounding)),
        source_evidence=final.source_evidence,
    )


class ReviewUnit(Protocol):
    """A planned unit the scheduler identifies and attributes failures to."""

    @property
    def id(self) -> str:
        """The content bound unit plan id."""

    @property
    def paths(self) -> tuple[str, ...]:
        """The source paths the unit reviews."""


def run_review_units[U: ReviewUnit, T](
    units: list[U],
    *,
    execute: Callable[[U], ReviewCycle[T]],
    accumulator: FindingAccumulator[T],
    concurrency: int = 1,
    restore: Callable[[U], ReviewCycle[T] | None] | None = None,
    on_unit: Callable[[U, ReviewCycle[T], float], None] | None = None,
) -> ReviewOutcome[T]:
    """Review every open unit once, continue past failed units, and record each failure."""
    if not units:
        raise ValueError("at least one review unit is required")
    unit_ids = tuple(unit.id for unit in units)
    if any(not identity for identity in unit_ids):
        raise ValueError("review unit identities must be nonempty")
    if len(set(unit_ids)) != len(unit_ids):
        raise ValueError("review unit identities must be unique")
    earlier = {unit.id: cycle for unit in units if restore is not None and (cycle := restore(unit)) is not None}
    unit_lock = Lock()

    def invoke(unit: U) -> ReviewCycle[T]:
        started = perf_counter()
        try:
            with model_call_scope(unit_id=unit.id):
                cycle = execute(unit)
        except Exception as exc:
            cycle = ReviewCycle(findings=[], errors=1, failure_reason=_failure_reason(exc))
        if unit.id in earlier:
            cycle = replace(cycle, findings=[*earlier[unit.id].findings, *cycle.findings])
        if on_unit is not None:
            with unit_lock:
                on_unit(unit, cycle, round(perf_counter() - started, 1))
        return cycle

    open_units = [unit for unit in units if unit.id not in earlier or not earlier[unit.id].clean]
    if concurrency > 1 and len(open_units) > 1:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            executed = dict(zip((unit.id for unit in open_units), pool.map(invoke, open_units), strict=True))
    else:
        executed = {unit.id: invoke(unit) for unit in open_units}
    results = [executed[unit.id] if unit.id in executed else earlier[unit.id] for unit in units]

    for result in results:
        accumulator.add(result.findings)
    failures = tuple(
        ReviewUnitFailure(
            index=index,
            total=len(units),
            paths=unit.paths,
            reason=result.failure_reason or result.grounding.failure_reason or "review unit failed",
        )
        for index, (unit, result) in enumerate(zip(units, results, strict=True), 1)
        if not result.clean
    )
    incomplete = tuple(dict.fromkeys(item for result in results for item in result.incomplete))
    errors = sum(result.errors or int(not result.clean) for result in results)
    grounding = merge_grounding_coverage(tuple(result.grounding for result in results))
    return ReviewOutcome(
        findings=tuple(accumulator.findings),
        failures=failures,
        incomplete=incomplete,
        errors=errors,
        failure_reason=grounding.failure_reason,
        grounding=grounding,
    )
