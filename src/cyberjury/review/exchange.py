"""One bounded evidence exchange: model replies, evidence and source deliveries, and corrections."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass, field, replace

from cyberjury.providers.base import ProviderAccessError
from cyberjury.providers.metering import (
    model_call_context,
    record_model_exchange,
    record_model_parse,
)
from cyberjury.review.context import (
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
)
from cyberjury.review.failures import exception_reason
from cyberjury.review.finding import Finding
from cyberjury.review.navigation import (
    RepeatedSourceQueryError,
    SourceNavigationError,
    SourceNavigationResult,
    SourceNavigationSession,
    SourceQueryLimitError,
    UnknownDefinitionQueryError,
    parse_source_queries,
)
from cyberjury.review.replies import CorrectableRoleResponseError, RoleReply
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.union import MERGE_RULE, FindingAccumulator

_EXECUTION = DEFAULT_REVIEW_SETTINGS.execution
_CORRECTION_BUDGET = {
    "response": 1,
    "query_limit": 1,
    "repeated_query": 1,
    "delivered_request": 1,
    "evidence_budget": 2,
    "unknown_definition": 1,
    "unknown_evidence": 2,
}
_CORRECTED_RESPONSE = "Return the corrected response. Previously accepted findings are kept."
_REPEATED_QUERY_CORRECTION = (
    "The previous response repeated an already executed source query. "
    "Do not repeat it. Use the evidence already delivered and return the final judgment."
)


@dataclass(frozen=True, kw_only=True)
class EvidenceJudgment:
    """Findings and grounding receipt from one bounded evidence exchange."""

    findings: list[Finding]
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    failure_reason: str = ""
    source_evidence: tuple[SourceEvidence, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _ParsedEvidenceReply:
    findings: list[Finding]
    requested: list[str]
    source_queries: list[dict[str, object]]
    deferred: list[Finding]
    repeated_evidence_requests: tuple[str, ...] = ()


class _RejectedBatch(Exception):
    def __init__(
        self,
        kind: str,
        instruction: str,
        *,
        failure_reason: str,
        unresolved: tuple[str, ...],
    ) -> None:
        self.kind = kind
        self.instruction = instruction
        self.failure_reason = failure_reason
        self.unresolved = unresolved
        super().__init__(failure_reason)


class _MalformedEvidenceRequest(EvidenceRequestError):
    def __init__(self, failure: str, findings: tuple[object, ...], requested: tuple[str, ...]) -> None:
        self.findings = findings
        self.requested = requested
        super().__init__(failure)


class _EvidenceExchange:
    def __init__(
        self,
        context: GroundingContext,
        *,
        findings_from_reply: Callable[[RoleReply], list[Finding]],
        target_chars: int,
        max_followups: int,
        navigation: SourceNavigationSession | None,
    ) -> None:
        self.context = context
        self.navigation = navigation
        self.findings_from_reply = findings_from_reply
        self.target_chars = target_chars
        self.accumulator = FindingAccumulator()
        self.provisional = FindingAccumulator()
        self.correction_fallback = FindingAccumulator()
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

    def _retained_findings(self) -> list[Finding]:
        retained = FindingAccumulator()
        retained.add(self.correction_fallback.findings)
        retained.add(self.accumulator.findings)
        retained.add(self.provisional.findings)
        return retained.findings

    def _accepted_records(self) -> tuple[Mapping[str, object], ...]:
        accepted = FindingAccumulator()
        accepted.add(self.accumulator.findings)
        accepted.add(self.provisional.findings)
        return tuple(finding.reply_record() for finding in accepted.findings)

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
        findings: list[Finding] | None = None,
    ) -> EvidenceJudgment:
        return _evidence_judgment(
            findings=self._retained_findings() if findings is None else findings,
            coverage=self.coverage,
            unresolved=unresolved,
            failure_reason=failure_reason,
            source_evidence=self.source_evidence,
        )

    def read_reply(
        self, ask: Callable[[EvidencePromptContext], RoleReply], call_index: int
    ) -> _ParsedEvidenceReply | EvidenceJudgment:
        self.turn = _Turn()
        try:
            return _parse_evidence_reply(
                ask(self.prompt),
                findings_from_reply=self.findings_from_reply,
                available_refs=self.available_refs,
                evidence_ids={item.id for item in self.context.evidence},
                navigation=self.navigation,
            )
        except CorrectableRoleResponseError as exc:
            record_model_parse(exception_reason(exc))
            self.accumulator.add(exc.response_findings)
            self.correction_fallback.add(exc.fallback_findings)
            raise _RejectedBatch(
                "response",
                f"Response correction required. {exc.instruction} {_CORRECTED_RESPONSE} "
                "Do not repeat the invalid value.",
                failure_reason=exception_reason(exc),
                unresolved=("model response violates a deterministic response constraint",),
            ) from exc
        except _MalformedEvidenceRequest as exc:
            record_model_parse(exception_reason(exc))
            self.correction_fallback.add(exc.findings)
            unread = self._published_ids() - self.available_refs
            raise _RejectedBatch(
                "unknown_evidence",
                _malformed_request_correction(str(exc), tuple(item for item in exc.requested if item in unread)),
                failure_reason=exception_reason(exc),
                unresolved=("model requested an evidence id outside the published id format",),
            ) from exc
        except SourceQueryLimitError as exc:
            record_model_parse(exception_reason(exc))
            self.accumulator.add(exc.response_findings)
            raise _RejectedBatch(
                "query_limit",
                f"The previous response returned {exc.count} source queries, but one batch permits "
                f"at most {exc.limit}. No query in that batch was executed. Return at most {exc.limit} "
                "distinct queries, keeping only the searches needed to decide the current candidates.",
                failure_reason=exception_reason(exc),
                unresolved=("source query batch exceeds the published limit",),
            ) from exc
        except ProviderAccessError:
            raise
        except Exception as exc:
            record_model_parse(exception_reason(exc))
            if call_index == 0:
                raise
            return self.finish((f"model response {call_index + 1} failed",), exception_reason(exc))

    def accept(self, reply: _ParsedEvidenceReply) -> EvidenceJudgment | None:
        requested = _implicit_reference_requests(
            list(self.provisional.findings),
            available=self.available_refs,
            evidence_ids={item.id for item in self.context.evidence},
            navigation=self.navigation,
            evidence_requests=list(reply.requested),
        )
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
                "findings cite evidence that did not fit in the evidence budget before the follow-ups ran out",
            )
        if self.evidence_exchanges >= self.followup_budget:
            return self.finish(
                ("source navigation round limit reached",),
                self.unknown_evidence_failure_reason
                or f"finder requested evidence after {self.followup_budget} follow-ups",
            )
        return self._deliver(requested, source_queries)

    def _deliver(self, requested: list[str], source_queries: list[dict[str, object]]) -> EvidenceJudgment | None:
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
            durable=True,
        )
        return None

    def reject(self, rejected: _RejectedBatch) -> EvidenceJudgment | None:
        self.turn.correction = rejected.kind
        if self.corrections[rejected.kind] < 1:
            return self.finish(rejected.unresolved, rejected.failure_reason)
        self.corrections[rejected.kind] -= 1
        if rejected.kind == "unknown_evidence":
            self.unknown_evidence_failure_reason = rejected.failure_reason
        self.prompt = _continue_prompt(
            self.prompt,
            rejected.instruction,
            self._remaining(),
            accepted=self._accepted_records(),
        )
        return None


def run_evidence_judgment(
    context: GroundingContext,
    *,
    ask: Callable[[EvidencePromptContext], RoleReply],
    findings_from_reply: Callable[[RoleReply], list[Finding]],
    target_chars: int,
    max_followups: int,
    navigation: SourceNavigationSession | None,
) -> EvidenceJudgment:
    """Run bounded evidence and source navigation without losing earlier findings."""
    exchange = _EvidenceExchange(
        context,
        findings_from_reply=findings_from_reply,
        target_chars=target_chars,
        max_followups=max_followups,
        navigation=navigation,
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
                result = exchange.reject(rejected)
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


def _exchange_record(turn: _Turn, result: EvidenceJudgment | None) -> dict[str, object]:
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
        "transform ids. File paths, module names, and descriptions are not evidence ids, and source outside the "
        f"reviewed repository cannot be requested. {_CORRECTED_RESPONSE}"
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
    durable: bool = False,
) -> EvidencePromptContext:
    text = instruction.strip()
    return replace(
        prompt,
        delivered=(*prompt.delivered, text) if durable else prompt.delivered,
        correction="" if durable else text,
        provisional=_accepted_instruction(accepted),
        budget=_request_budget_instruction(remaining, navigation_available=prompt.navigation_available),
    )


def _evidence_judgment(
    *,
    findings: list[Finding],
    coverage: GroundingCoverage,
    source_evidence: list[SourceEvidence],
    unresolved: tuple[str, ...],
    failure_reason: str,
) -> EvidenceJudgment:
    grounding = (
        merge_grounding_coverage((coverage, GroundingCoverage(unresolved=unresolved))) if unresolved else coverage
    )
    return EvidenceJudgment(
        findings=findings,
        grounding=grounding,
        failure_reason=failure_reason,
        source_evidence=tuple(source_evidence),
    )


def _accepted_instruction(accepted: tuple[Mapping[str, object], ...]) -> str:
    if not accepted:
        return ""
    return (
        "Findings already accepted for this unit from your earlier responses:\n"
        f"{json.dumps(accepted, ensure_ascii=False, sort_keys=True)}\n"
        "They stay accepted whether or not you return them, and they cannot be edited or withdrawn. "
        f"{MERGE_RULE} Return only new findings."
    )


def _parse_evidence_reply(
    reply: RoleReply,
    *,
    findings_from_reply: Callable[[RoleReply], list[Finding]],
    available_refs: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
) -> _ParsedEvidenceReply:
    findings = findings_from_reply(reply)
    raw_requests = reply["evidence_requests"]
    try:
        requested_evidence_ids = evidence_request_ids(raw_requests)
    except EvidenceRequestError as exc:
        well_formed = tuple(item for item in raw_requests if is_evidence_id(item))
        raise _MalformedEvidenceRequest(str(exc), tuple(findings), tuple(dict.fromkeys(well_formed))) from exc
    repeated_evidence_requests = tuple(item for item in requested_evidence_ids if item in available_refs)
    unread_evidence_ids = tuple(item for item in requested_evidence_ids if item not in available_refs)
    try:
        source_queries = parse_source_queries(reply["source_queries"])
    except SourceQueryLimitError as exc:
        exc.response_findings = tuple(findings)
        raise
    requested = _implicit_reference_requests(
        findings,
        available=available_refs,
        evidence_ids=evidence_ids,
        navigation=navigation,
        evidence_requests=list(unread_evidence_ids),
    )
    ids = list(dict.fromkeys(requested))
    accepted, deferred = _partition_evidence_bound_findings(
        findings,
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


def _partition_evidence_bound_findings(
    findings: list[Finding],
    *,
    available: set[str],
    requested: set[str],
) -> tuple[list[Finding], list[Finding]]:
    accepted: list[Finding] = []
    deferred: list[Finding] = []
    invalid: list[int] = []
    for index, finding in enumerate(findings):
        unknown = tuple(ref for ref in finding.evidence_refs if ref not in available)
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
) -> SourceNavigationResult:
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
    return SourceNavigationResult(
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
) -> tuple[SourceNavigationResult, list[str], list[dict[str, object]]]:
    capped = requested[: _EXECUTION.max_evidence_requests_per_batch]
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
    requested: list[str],
    *,
    target_chars: int,
) -> SourceNavigationResult:
    ids = tuple(requested)
    published_by_id = {item.id: item for item in context.evidence}
    published_ids = tuple(item for item in ids if item in published_by_id)
    source_ids = tuple(
        item for item in ids if item not in published_by_id and navigation is not None and navigation.can_read(item)
    )
    known = {*published_ids, *source_ids}
    unknown = tuple(item for item in ids if item not in known)
    if unknown:
        raise UnknownEvidenceRequest(unknown)

    selected = select_evidence(context.evidence, published_ids)
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


def _implicit_reference_requests(
    findings: list[Finding],
    *,
    available: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
    evidence_requests: list[str],
) -> list[str]:
    cited: list[str] = []
    for finding in findings:
        for reference in finding.evidence_refs:
            if reference in available or reference in cited:
                continue
            if reference in evidence_ids or (navigation is not None and navigation.can_read(reference)):
                cited.append(reference)
    return [*cited, *(item for item in evidence_requests if item not in cited)]
