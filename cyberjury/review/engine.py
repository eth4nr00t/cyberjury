"""Shared judgment orchestration for every review target."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Hashable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field, replace
from threading import Lock
from time import perf_counter
from typing import Literal, NotRequired, TypedDict

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.metering import model_call_context, model_call_scope, record_model_parse
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
from cyberjury.review.scheduling import SchedulingReceipt, SchedulingRound
from cyberjury.review.trace import Trace, emit_trace
from cyberjury.severity import median


class RoleResponseError(RuntimeError):
    """A role reply cannot support a complete judgment."""


type RoleReply = dict[str, object]
AssessmentDecision = Literal["finding", "not_exploitable", "insufficient_evidence"]


@dataclass(frozen=True, kw_only=True)
class DecisionRuleAssessment:
    """One evidence bound conclusion for an expanded decision rule."""

    decision_rule_id: str
    decision: AssessmentDecision
    reason: str
    evidence_refs: tuple[str, ...]


class RebuttalRecord(TypedDict):
    """A Challenger objection to one finder candidate."""

    candidate_id: str
    disposition: Literal["dispute", "lower_severity"]
    reason: str
    evidence_refs: list[str]


class PendingWorkRecord(TypedDict):
    """A role request for dynamic or off-model investigation."""

    kind: Literal["missing_source", "runtime_check", "environment_check"]
    question: str
    required_evidence: list[str]
    id: NotRequired[str]
    candidate_id: NotRequired[str]
    owner_unit_id: NotRequired[str]


class PendingWorkSnapshot(dict[str, object]):
    """An immutable pending record that keeps the JSON mapping contract."""

    def __init__(self, record: Mapping[str, object]) -> None:
        """Copy one mutable role record into the stable outcome shape."""
        dict.__init__(self, record)

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("pending work snapshots are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __deepcopy__(self, _memo: dict[int, object]) -> dict[str, object]:
        """Return plain data so dataclass and JSON adapters stay compatible."""
        return dict(self)


def parse_role_response(
    text: str,
    *,
    role: str,
    required_keys: tuple[str, ...],
    optional_list_keys: tuple[str, ...] = (),
    object_list_keys: tuple[str, ...] = (),
) -> RoleReply:
    """Require the role contract so malformed output cannot become a clean result."""
    parsed = parse_json_object(text)
    source = parsed.source if parsed is not None else "none"
    obj = parsed.value if parsed is not None and parsed.complete else None

    def fail(message: str) -> None:
        record_model_parse(source, status="failed", failure_reason=message)
        raise RoleResponseError(message)

    missing = [key for key in required_keys if obj is None or key not in obj]
    if missing:
        fields = ", ".join(missing)
        fail(f"{role} reply had no usable JSON object with required fields: {fields}")
    invalid = [key for key in required_keys if not isinstance(obj[key], list)]
    if invalid:
        fields = ", ".join(invalid)
        fail(f"{role} reply had non-list required fields: {fields}")
    invalid_optional = [key for key in optional_list_keys if key in obj and not isinstance(obj[key], list)]
    if invalid_optional:
        fields = ", ".join(invalid_optional)
        fail(f"{role} reply had non-list optional fields: {fields}")
    for key in object_list_keys:
        value = obj.get(key, [])
        if not isinstance(value, list):
            fail(f"{role} reply had non-list object field: {key}")
        invalid_item = next((index for index, item in enumerate(value) if not isinstance(item, dict)), None)
        if invalid_item is not None:
            fail(f"{role} reply field {key}[{invalid_item}] must be an object")
    record_model_parse(source)
    return obj


def validate_rebuttal_records(
    value: object,
    *,
    role: str,
    candidate_ids: set[str],
    available_evidence_refs: set[str],
) -> list[RebuttalRecord]:
    """Require every Challenger objection to identify one actionable dispute."""
    if not isinstance(value, list):
        raise RoleResponseError(f"{role} rebuttals must be a list")
    records: list[RebuttalRecord] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise RoleResponseError(f"{role} rebuttals[{index}] must be an object")
        fields = {"candidate_id", "disposition", "reason", "evidence_refs"}
        if set(item) != fields:
            raise RoleResponseError(f"{role} rebuttals[{index}] must contain exactly: {', '.join(sorted(fields))}")
        candidate_id = item.get("candidate_id")
        disposition = item.get("disposition")
        reason = item.get("reason")
        evidence_refs = item.get("evidence_refs")
        if not isinstance(candidate_id, str) or candidate_id not in candidate_ids:
            raise RoleResponseError(f"{role} rebuttals[{index}].candidate_id is unknown")
        if disposition not in {"dispute", "lower_severity"}:
            raise RoleResponseError(f"{role} rebuttals[{index}].disposition is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise RoleResponseError(f"{role} rebuttals[{index}].reason must be a nonempty string")
        if (
            not isinstance(evidence_refs, list)
            or not evidence_refs
            or not all(isinstance(ref, str) and ref for ref in evidence_refs)
        ):
            raise RoleResponseError(f"{role} rebuttals[{index}].evidence_refs must be a nonempty string list")
        unknown_refs = set(evidence_refs).difference(available_evidence_refs)
        if unknown_refs:
            raise RoleResponseError(
                f"{role} rebuttals[{index}].evidence_refs contain unknown ids: {', '.join(sorted(unknown_refs))}"
            )
        records.append(item)
    return records


def validate_pending_records(
    value: object,
    *,
    role: str,
    candidate_ids: set[str],
) -> list[PendingWorkRecord]:
    """Require pending work to name the unresolved target and question."""
    if not isinstance(value, list):
        raise RoleResponseError(f"{role} pending work must be a list")
    records: list[PendingWorkRecord] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise RoleResponseError(f"{role} pending[{index}] must be an object")
        required = {"kind", "question", "required_evidence"}
        optional = {"id", "candidate_id"}
        if not required.issubset(item) or set(item).difference(required | optional):
            raise RoleResponseError(
                f"{role} pending[{index}] requires kind, question, and required_evidence "
                "with optional id and candidate_id"
            )
        kind = item.get("kind")
        question = item.get("question")
        required_evidence = item.get("required_evidence")
        if kind not in {"missing_source", "runtime_check", "environment_check"}:
            raise RoleResponseError(f"{role} pending[{index}].kind is invalid")
        if not isinstance(question, str) or not question.strip():
            raise RoleResponseError(f"{role} pending[{index}].question must be a nonempty string")
        if (
            not isinstance(required_evidence, list)
            or not required_evidence
            or not all(isinstance(entry, str) and entry for entry in required_evidence)
        ):
            raise RoleResponseError(f"{role} pending[{index}].required_evidence must be a nonempty string list")
        identity = item.get("id")
        if identity is not None and (not isinstance(identity, str) or not identity.strip()):
            raise RoleResponseError(f"{role} pending[{index}].id must be a nonempty string")
        candidate_id = item.get("candidate_id")
        if candidate_id is not None and (not isinstance(candidate_id, str) or candidate_id not in candidate_ids):
            raise RoleResponseError(f"{role} pending[{index}].candidate_id is unknown")
        records.append(item)
    return records


def validate_decision_rule_assessments(
    value: object,
    *,
    role: str,
    expanded_rule_ids: set[str],
    finding_rule_ids: set[str],
    provisional_rule_ids: set[str],
    require_complete: bool,
) -> tuple[DecisionRuleAssessment, ...]:
    """Require one conclusion for every rule whose full contract was delivered."""
    finding_rule_ids.discard("")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RoleResponseError(f"{role} decision_rule_assessments must be a list of objects")
    assessments: list[DecisionRuleAssessment] = []
    for index, item in enumerate(value):
        fields = {"decision_rule_id", "decision", "reason", "evidence_refs"}
        if set(item) != fields:
            raise RoleResponseError(
                f"{role} decision_rule_assessments[{index}] must contain exactly: {', '.join(sorted(fields))}"
            )
        rule_id = item["decision_rule_id"]
        decision = item["decision"]
        reason = item["reason"]
        refs = item["evidence_refs"]
        if not isinstance(rule_id, str) or rule_id not in expanded_rule_ids:
            raise RoleResponseError(f"{role} decision_rule_assessments[{index}].decision_rule_id is not expanded")
        if decision not in {"finding", "not_exploitable", "insufficient_evidence"}:
            raise RoleResponseError(f"{role} decision_rule_assessments[{index}].decision is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise RoleResponseError(f"{role} decision_rule_assessments[{index}].reason must be nonempty")
        if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref for ref in refs):
            raise RoleResponseError(
                f"{role} decision_rule_assessments[{index}].evidence_refs must be a nonempty string list"
            )
        if decision == "finding" and rule_id not in finding_rule_ids | provisional_rule_ids:
            raise RoleResponseError(f"{role} decision rule assessment for {rule_id} names no matching finding")
        if decision != "finding" and rule_id in finding_rule_ids:
            raise RoleResponseError(f"{role} decision rule assessment for {rule_id} contradicts a finding")
        assessments.append(
            DecisionRuleAssessment(
                decision_rule_id=rule_id,
                decision=decision,
                reason=reason.strip(),
                evidence_refs=tuple(refs),
            )
        )
    decided = [assessment.decision_rule_id for assessment in assessments]
    if len(decided) != len(set(decided)):
        raise RoleResponseError(f"{role} decision_rule_assessments must not repeat a rule")
    if require_complete and set(decided) != expanded_rule_ids:
        raise RoleResponseError(f"{role} decision_rule_assessments must decide every expanded rule exactly once")
    return tuple(assessments)


ReviewMode = Literal["standard", "adversarial"]
CompletionPolicy = Literal["single", "converge"]
JudgmentProgress = Callable[[int, int, str, float], None]
_FAILURE_REASON_LIMIT = 2000
_FAILURE_REASON_TRUNCATED = "... [failure reason truncated]"


@dataclass(frozen=True, kw_only=True)
class ReviewSchedule:
    """The coded round and stopping policy for one review run."""

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
        expected_completion = "single" if self.mode == "standard" else "converge"
        if completion != expected_completion:
            raise ValueError(f"review mode {self.mode!r} requires completion {expected_completion!r}")
        object.__setattr__(self, "completion", completion)
        values = {
            "max_rounds": self.max_rounds,
            "min_rounds": self.min_rounds,
            "converge_after": self.converge_after,
        }
        invalid = [
            name for name, value in values.items() if isinstance(value, bool) or not isinstance(value, int) or value < 1
        ]
        if invalid:
            raise ValueError(f"review schedule values must be positive integers: {', '.join(invalid)}")
        if self.min_rounds > self.max_rounds:
            raise ValueError("review schedule min_rounds cannot exceed max_rounds")
        if completion == "converge" and self.converge_after > self.max_rounds:
            raise ValueError("review schedule converge_after cannot exceed max_rounds")
        if completion == "single" and self.max_rounds != 1:
            raise ValueError("single completion requires max_rounds to equal 1")
        if completion == "single" and self.min_rounds != 1:
            raise ValueError("single completion requires min_rounds to equal 1")
        if not isinstance(self.stop_on_failure, bool):
            raise ValueError("review schedule stop_on_failure must be boolean")


def review_schedule(
    mode: str,
    *,
    max_rounds: int,
    min_rounds: int = 1,
    converge_after: int = 2,
    completion: CompletionPolicy | None = None,
    stop_on_failure: bool = True,
) -> ReviewSchedule:
    """Validate one target policy before any model work begins."""
    return ReviewSchedule(
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
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()
    evidence_exchanges: int = 0


@dataclass(frozen=True, kw_only=True)
class RoleJudgment[T]:
    """The Judge survivors and work that still needs investigation."""

    findings: list[T]
    pending: list[PendingWorkRecord] = field(default_factory=list)
    resolved_pending: tuple[str, ...] = ()
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    source_evidence: tuple[SourceEvidence, ...] = ()
    evidence_exchanges: int = 0

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
class _ParsedEvidenceReply[T]:
    """One validated model reply before its evidence is delivered."""

    findings: list[T]
    requested: list[str]
    decision_rule_requests: tuple[str, ...]
    source_queries: list[dict[str, object]]
    deferred: list[T]
    decision_rule_assessments: tuple[DecisionRuleAssessment, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _DeliveredEvidence:
    """One atomic evidence batch from every published source catalog."""

    text: str
    coverage: GroundingCoverage
    source_evidence: tuple[SourceEvidence, ...]


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
    judgment_role: str = "judgment",
    model_role: str = "",
    model_unit_id: str = "",
    review_brief_sha256: str = "",
    decision_rule_ids: tuple[str, ...] = (),
    available_decision_rule_ids: frozenset[str] = frozenset(),
    expand_decision_rule_requests: Callable[[tuple[str, ...]], tuple[str, ...]] | None = None,
    render_decision_rules: Callable[[tuple[str, ...]], str] | None = None,
    finding_decision_rule_id: Callable[[T], str] | None = None,
    finding_prompt_record: Callable[[T], Mapping[str, object]] | None = None,
) -> EvidenceJudgment[T]:
    """Run bounded evidence and source navigation without losing earlier findings."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    prompt = _with_request_budget(context.prompt, max_followups)
    coverage = context.coverage
    available_refs = {"seed", *coverage.references}
    findings: list[T] = []
    provisional = FindingAccumulator(
        key=accumulator.key,
        fold=accumulator.fold,
        grade=accumulator.grade,
        with_grade=accumulator.with_grade,
    )
    navigation = navigation_session
    if navigation is None and context.navigator is not None:
        navigation = context.navigator.session()
    source_evidence: list[SourceEvidence] = []
    evidence_exchanges = 0
    decision_rule_assessments: tuple[DecisionRuleAssessment, ...] = ()
    requested_rule_assessment_correction = False
    visible_rule_ids = set(decision_rule_ids)
    required_rule_ids: set[str] = set()
    for exchange in range(max_followups + 1):
        with model_call_context(
            role=model_role or judgment_role,
            trigger="initial_judgment" if exchange == 0 else "evidence_followup",
            unit_id=model_unit_id,
            evidence_revision=_prompt_revision(context, prompt),
            review_brief_sha256=review_brief_sha256,
            decision_rule_ids=tuple(sorted(visible_rule_ids)),
            round=judgment_id,
        ):
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
                    judgment_role=judgment_role,
                    available_decision_rule_ids=available_decision_rule_ids,
                    expand_decision_rule_requests=expand_decision_rule_requests,
                    expanded_decision_rule_ids=required_rule_ids,
                    visible_decision_rule_ids=visible_rule_ids,
                    finding_decision_rule_id=finding_decision_rule_id,
                    provisional_findings=provisional.findings,
                )
            except Exception as exc:
                record_model_parse("semantic", status="failed", failure_reason=_failure_reason(exc))
                if exchange == 0:
                    raise
                return _evidence_judgment(
                    findings=provisional.findings,
                    coverage=coverage,
                    unresolved=(f"evidence exchange {exchange + 1} failed",),
                    failure_reason=_failure_reason(exc),
                    prompt=prompt,
                    source_evidence=source_evidence,
                    evidence_exchanges=evidence_exchanges,
                )
        requested = parsed_reply.requested
        rule_requests = parsed_reply.decision_rule_requests
        source_queries = parsed_reply.source_queries
        decision_rule_assessments = parsed_reply.decision_rule_assessments
        if not requested and not source_queries and not rule_requests:
            insufficient_rules = [
                item.decision_rule_id for item in decision_rule_assessments if item.decision == "insufficient_evidence"
            ]
            can_request = navigation is not None or bool(context.evidence)
            if (
                insufficient_rules
                and can_request
                and exchange < max_followups
                and not requested_rule_assessment_correction
            ):
                provisional.add((*parsed_reply.findings, *parsed_reply.deferred))
                requested_rule_assessment_correction = True
                prompt = _decision_rule_request_continuation(
                    prompt,
                    rule_ids=tuple(insufficient_rules),
                    remaining=max_followups - exchange,
                    provisional=_provisional_records(provisional.findings, finding_prompt_record),
                )
                continue
            accumulator.add(parsed_reply.findings)
            findings = accumulator.findings
            emit_trace(
                trace,
                "decision_rule_assessments",
                judgment=judgment_id,
                role=judgment_role,
                assessments=[
                    {
                        "decision_rule_id": item.decision_rule_id,
                        "decision": item.decision,
                        "reason": item.reason[:500],
                        "evidence_refs": list(item.evidence_refs),
                    }
                    for item in decision_rule_assessments
                ],
            )
            return _evidence_judgment(
                findings=findings,
                coverage=coverage,
                unresolved=tuple(f"decision-rule:{rule_id}" for rule_id in insufficient_rules),
                failure_reason=(
                    f"{judgment_role} has insufficient evidence for decision rules: {', '.join(insufficient_rules)}"
                    if insufficient_rules
                    else ""
                ),
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
            )
        if exchange == max_followups:
            provisional.add((*parsed_reply.findings, *parsed_reply.deferred))
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
                findings=provisional.findings,
                coverage=coverage,
                unresolved=unresolved,
                failure_reason=f"finder requested evidence after {max_followups} follow ups",
                prompt=prompt,
                source_evidence=source_evidence,
                evidence_exchanges=evidence_exchanges,
            )
        provisional.add((*parsed_reply.findings, *parsed_reply.deferred))
        try:
            repeated_rules = visible_rule_ids.intersection(rule_requests)
            if repeated_rules:
                raise EvidenceRequestError(
                    f"decision rule request repeats delivered ids: {', '.join(sorted(repeated_rules))}"
                )
            if rule_requests and render_decision_rules is None:
                raise EvidenceRequestError("decision_rule_requests are unavailable for this judgment")
            rule_text = (
                render_decision_rules(rule_requests) if render_decision_rules is not None and rule_requests else ""
            )
            delivered = _deliver_evidence_exchange(
                context,
                navigation,
                requested=requested,
                source_queries=source_queries,
                target_chars=target_chars,
                trace=trace,
                judgment_id=judgment_id,
                exchange=exchange + 1,
                decision_rule_ids=rule_requests,
                decision_rule_text=rule_text,
            )
            coverage = merge_grounding_coverage((coverage, delivered.coverage))
            available_refs.update(delivered.coverage.references)
            source_evidence.extend(delivered.source_evidence)
            visible_rule_ids.update(rule_requests)
            required_rule_ids.update(rule_requests)
            evidence_exchanges += 1
        except (EvidenceRequestError, SourceNavigationError) as exc:
            unresolved = tuple(item for item in requested if isinstance(item, str))
            if not unresolved:
                unresolved = (f"source navigation exchange {exchange + 1}",)
            return _evidence_judgment(
                findings=provisional.findings,
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
            provisional=_provisional_records(provisional.findings, finding_prompt_record),
            decision_rule_ids=tuple(sorted(required_rule_ids)),
        )
    raise AssertionError("unreachable source navigation loop")


def _prompt_revision(context: GroundingContext, prompt: EvidencePromptContext) -> str:
    """Identify the exact source and controls visible to one model call."""
    snapshot_key = context.source_snapshot.snapshot_id if context.source_snapshot is not None else ""
    material = "\x00".join(("model-prompt-v1", snapshot_key, prompt.source, prompt.controls))
    return f"revision-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"


def _decision_rule_request_continuation(
    prompt: EvidencePromptContext,
    *,
    rule_ids: tuple[str, ...],
    remaining: int,
    provisional: tuple[Mapping[str, object], ...],
) -> EvidencePromptContext:
    """Require actionable evidence work before accepting an insufficient rule conclusion."""
    return EvidencePromptContext(
        source=prompt.source,
        revision=prompt.revision + 1,
        controls=(
            f"{prompt.controls}\n\nThe prior response marked these delivered decision rules as insufficient "
            f"without requesting the missing source: {', '.join(rule_ids)}. Use the published navigation "
            "contract now. Return concrete `evidence_requests` or `source_queries` for every retrievable "
            "controlling fact. If no specific missing fact can establish a concrete exploit, conclude "
            "`not_exploitable`. A final insufficient assessment leaves the judgment incomplete.\n\n"
            f"{_provisional_instruction(provisional)}"
            f"{_request_budget_instruction(remaining)}"
        ),
    )


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
    provisional: tuple[Mapping[str, object], ...],
    decision_rule_ids: tuple[str, ...] = (),
) -> EvidencePromptContext:
    """Render controls for the next judgment after one atomic delivery."""
    provisional_instruction = _provisional_instruction(provisional)
    assessment = (
        " Return exactly one `decision_rule_assessments` entry for each delivered rule id: "
        f"{', '.join(decision_rule_ids)}. A `finding` assessment must match a finding in this response or a "
        "provisional finding listed below."
        if decision_rule_ids
        else " Return `decision_rule_assessments` as an empty list."
    )
    return EvidencePromptContext(
        source=prompt.source,
        revision=prompt.revision + 1,
        controls=(
            f"{prompt.controls}\n\nSource navigation exchange {exchange}:\n{delivered}\n\n"
            f"{_request_budget_instruction(remaining)}{assessment}{provisional_instruction}"
        ),
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
        "\n\nProvisional findings from earlier responses are not accepted yet:\n"
        f"{json.dumps(provisional, ensure_ascii=False, sort_keys=True)}\n"
        "The engine retains these candidates. Return an updated finding when its report content changes. "
        "Otherwise decide its delivered rule as `finding` to preserve it or `not_exploitable` only when a "
        "controlling fact refutes it. Omission alone does not delete a provisional candidate.\n\n"
    )


def _parse_evidence_reply[T](
    reply: RoleReply,
    *,
    findings_from_reply: Callable[[RoleReply], list[T]],
    evidence_refs: Callable[[T], tuple[str, ...]] | None,
    available_refs: set[str],
    evidence_ids: set[str],
    navigation: SourceNavigationSession | None,
    judgment_role: str,
    available_decision_rule_ids: frozenset[str],
    expand_decision_rule_requests: Callable[[tuple[str, ...]], tuple[str, ...]] | None,
    expanded_decision_rule_ids: set[str],
    visible_decision_rule_ids: set[str],
    finding_decision_rule_id: Callable[[T], str] | None,
    provisional_findings: list[T],
) -> _ParsedEvidenceReply[T]:
    """Validate one reply before changing accumulated findings or coverage."""
    findings = findings_from_reply(reply)
    raw_requested = reply.get("evidence_requests", [])
    raw_queries = reply.get("source_queries", [])
    raw_rule_requests = reply.get("decision_rule_requests", [])
    if not isinstance(raw_requested, list):
        raise EvidenceRequestError("evidence_requests must be a list")
    if not isinstance(raw_queries, list):
        raise SourceNavigationError("source_queries must be a list")
    if not isinstance(raw_rule_requests, list) or not all(
        isinstance(value, str) and value for value in raw_rule_requests
    ):
        raise EvidenceRequestError("decision_rule_requests must be a list of nonempty strings")
    finding_rule_ids = (
        {finding_decision_rule_id(finding) for finding in findings} if finding_decision_rule_id is not None else set()
    )
    finding_rule_ids.discard("")
    provisional_rule_ids = (
        {finding_decision_rule_id(finding) for finding in provisional_findings}
        if finding_decision_rule_id is not None
        else set()
    )
    provisional_rule_ids.discard("")
    implicit_rule_requests = finding_rule_ids.difference(visible_decision_rule_ids, raw_rule_requests)
    requested_rule_or_category_ids = tuple(dict.fromkeys((*raw_rule_requests, *sorted(implicit_rule_requests))))
    if expand_decision_rule_requests is not None:
        try:
            decision_rule_requests = expand_decision_rule_requests(requested_rule_or_category_ids)
        except ValueError as exc:
            raise EvidenceRequestError(str(exc)) from exc
    else:
        unknown_rules = set(requested_rule_or_category_ids).difference(available_decision_rule_ids)
        if unknown_rules:
            raise EvidenceRequestError(
                f"decision rule request contains unknown ids: {', '.join(sorted(unknown_rules))}"
            )
        decision_rule_requests = requested_rule_or_category_ids
    source_queries = parse_source_queries(raw_queries)
    requested: list[object] = [*raw_requested]
    decision_rule_assessments = validate_decision_rule_assessments(
        reply.get("decision_rule_assessments", []),
        role=judgment_role,
        expanded_rule_ids=expanded_decision_rule_ids,
        finding_rule_ids=finding_rule_ids,
        provisional_rule_ids=provisional_rule_ids,
        require_complete=not raw_requested and not raw_queries and not decision_rule_requests,
    )
    confirmed_rules = {
        assessment.decision_rule_id for assessment in decision_rule_assessments if assessment.decision == "finding"
    }
    if finding_decision_rule_id is not None and confirmed_rules:
        findings.extend(
            finding for finding in provisional_findings if finding_decision_rule_id(finding) in confirmed_rules
        )
    requested_set = {item for item in requested if isinstance(item, str)}
    for assessment in decision_rule_assessments:
        for reference in assessment.evidence_refs:
            if reference not in available_refs and reference not in requested_set:
                requested.append(reference)
                requested_set.add(reference)
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
        decision_rule_requests=decision_rule_requests,
        source_queries=source_queries,
        deferred=deferred,
        decision_rule_assessments=decision_rule_assessments,
    )


def _with_request_budget(prompt: EvidencePromptContext, remaining: int) -> EvidencePromptContext:
    """Publish the bounded request budget outside the source evidence block."""
    instruction = _request_budget_instruction(remaining)
    controls = f"{prompt.controls}\n\n{instruction}" if prompt.controls else instruction
    return EvidencePromptContext(source=prompt.source, controls=controls, revision=prompt.revision)


def _request_budget_instruction(remaining: int) -> str:
    """Tell the model whether another evidence request can be fulfilled."""
    if remaining == 0:
        return (
            "No evidence or source request batches remain. Return the final judgment using only source "
            "already delivered. Empty `decision_rule_requests`, `evidence_requests`, and `source_queries`. "
            "A further request makes this judgment incomplete."
        )
    label = "batch remains" if remaining == 1 else "batches remain"
    return (
        f"Evidence request budget: {remaining} request {label}. Batch every independent request that can "
        "be named from the current evidence into one response. Return empty `decision_rule_requests`, "
        "`evidence_requests`, and `source_queries` as soon as the assigned judgment can be completed."
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
    decision_rule_ids: tuple[str, ...] = (),
    decision_rule_text: str = "",
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
    if decision_rule_text:
        blocks.append(f"Requested decision rule details:\n{decision_rule_text}")
    text = "\n\n".join(blocks)
    one_indivisible_item = len(requested) + len(source_queries) + len(decision_rule_ids) == 1
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
    if decision_rule_text:
        emit_trace(
            trace,
            "knowledge",
            stage="expanded",
            judgment=judgment_id,
            exchange=exchange,
            decision_rule_ids=list(decision_rule_ids),
            characters=len(decision_rule_text),
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
    resolved_pending: tuple[str, ...] = ()
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
    recovered_failures: list[ReviewUnitFailure] = field(default_factory=list)
    recovered_errors: int = 0
    pending: list[PendingWorkRecord] = field(default_factory=list)
    resolved_pending: tuple[str, ...] = ()
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


@dataclass(frozen=True, kw_only=True, init=False)
class ReviewOutcome[T]:
    """The shared completion contract for one review target."""

    findings: tuple[T, ...]
    failures: tuple[ReviewUnitFailure, ...] = ()
    recovered_failures: tuple[ReviewUnitFailure, ...] = ()
    incomplete: tuple[T, ...] = ()
    pending: tuple[PendingWorkSnapshot, ...] = ()
    errors: int = 0
    converged: bool = False
    requires_convergence: bool = True
    rounds: int = 0
    failure_reason: str = ""
    grounding: GroundingCoverage = field(default_factory=GroundingCoverage)
    scheduling: SchedulingReceipt | None = None

    def __init__(
        self,
        *,
        findings: Iterable[T],
        failures: Iterable[ReviewUnitFailure] = (),
        recovered_failures: Iterable[ReviewUnitFailure] = (),
        incomplete: Iterable[T] = (),
        pending: Iterable[Mapping[str, object]] = (),
        errors: int = 0,
        converged: bool = False,
        requires_convergence: bool = True,
        rounds: int = 0,
        failure_reason: str = "",
        grounding: GroundingCoverage | None = None,
        scheduling: SchedulingReceipt | None = None,
    ) -> None:
        """Accept iterable inputs while exposing immutable result collections."""
        object.__setattr__(self, "findings", tuple(findings))
        object.__setattr__(self, "failures", tuple(failures))
        object.__setattr__(self, "recovered_failures", tuple(recovered_failures))
        object.__setattr__(self, "incomplete", tuple(incomplete))
        object.__setattr__(self, "pending", tuple(PendingWorkSnapshot(item) for item in pending))
        object.__setattr__(self, "errors", errors)
        object.__setattr__(self, "converged", converged)
        object.__setattr__(self, "requires_convergence", requires_convergence)
        object.__setattr__(self, "rounds", rounds)
        object.__setattr__(self, "failure_reason", failure_reason)
        object.__setattr__(self, "grounding", grounding if grounding is not None else GroundingCoverage())
        object.__setattr__(self, "scheduling", scheduling)
        self.__post_init__()

    def __post_init__(self) -> None:
        """Validate completion counters after immutable construction."""
        if isinstance(self.errors, bool) or not isinstance(self.errors, int) or self.errors < 0:
            raise ValueError("review outcome errors must be a nonnegative integer")
        if isinstance(self.rounds, bool) or not isinstance(self.rounds, int) or self.rounds < 0:
            raise ValueError("review outcome rounds must be a nonnegative integer")
        if not isinstance(self.converged, bool) or not isinstance(self.requires_convergence, bool):
            raise ValueError("review outcome convergence fields must be boolean")
        if not isinstance(self.failure_reason, str):
            raise ValueError("review outcome failure_reason must be a string")
        if self.scheduling is not None and not isinstance(self.scheduling, SchedulingReceipt):
            raise ValueError("review outcome scheduling must be a scheduling receipt or null")
        if len(self.failure_reason) > _FAILURE_REASON_LIMIT:
            end = _FAILURE_REASON_LIMIT - len(_FAILURE_REASON_TRUNCATED)
            object.__setattr__(self, "failure_reason", self.failure_reason[:end] + _FAILURE_REASON_TRUNCATED)

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
    def investigate(self) -> tuple[PendingWorkSnapshot, ...]:
        """Expose pending dynamic checks under the result API name."""
        return self.pending


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
        recovered_failures=outcome.recovered_failures,
        incomplete=_unique_values((*outcome.incomplete, *incomplete)),
        pending=outcome.pending,
        errors=outcome.errors + errors,
        converged=outcome.converged,
        requires_convergence=outcome.requires_convergence,
        rounds=outcome.rounds,
        failure_reason=". ".join(reason for reason in (outcome.failure_reason, failure_reason) if reason),
        grounding=merge_grounding_coverage(
            (outcome.grounding, grounding) if grounding is not None else (outcome.grounding,)
        ),
        scheduling=outcome.scheduling,
    )


def _failure_reason(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def run_role_round[T](
    *,
    find: Callable[[], list[T] | EvidenceJudgment[T]],
    finder_label: str,
    key: Callable[[T], Hashable],
    fold: Callable[[T, T], T],
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
        grounding = merge_grounding_coverage((grounding, challenged.grounding))
        role_source_evidence = tuple(
            dict.fromkeys(
                (
                    *(finder_result.source_evidence if isinstance(finder_result, EvidenceJudgment) else ()),
                    *challenged.source_evidence,
                )
            )
        )
        evidence_exchanges = (
            finder_result.evidence_exchanges if isinstance(finder_result, EvidenceJudgment) else 0
        ) + challenged.evidence_exchanges
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
            source_evidence=role_source_evidence,
            evidence_exchanges=evidence_exchanges,
        )

    grounding = merge_grounding_coverage((grounding, judged.grounding))
    role_source_evidence = tuple(dict.fromkeys((*role_source_evidence, *judged.source_evidence)))
    evidence_exchanges += judged.evidence_exchanges
    judged_findings = label_judged(
        judged.findings,
        finder_findings,
        challenger_findings,
        key=key,
        title=title,
        finder_label=finder_label,
        challenger_label=challenger_label,
        judge_label=judge_label,
    )
    by_key: dict[Hashable, T] = {}
    order: list[Hashable] = []
    for finding in fallback:
        identity = key(finding)
        if identity not in by_key:
            order.append(identity)
            by_key[identity] = finding
        else:
            by_key[identity] = fold(by_key[identity], finding)
    for finding in judged_findings:
        identity = key(finding)
        if identity not in by_key:
            order.append(identity)
            by_key[identity] = finding
        else:
            by_key[identity] = fold(finding, by_key[identity])
    findings = [by_key[identity] for identity in order]
    return RoleRound(
        findings=findings,
        pending=judged.pending,
        resolved_pending=judged.resolved_pending,
        grounding=grounding,
        source_evidence=role_source_evidence,
        evidence_exchanges=evidence_exchanges,
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
            fold=accumulator.fold,
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
            failures.append(f"{role_round.failure_reason} [review judgment {index}/{len(planned)} for {description}]")
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
    known: tuple[object, ...] = ()


@dataclass(frozen=True, kw_only=True)
class _RevisionJudgment[T]:
    """One judgment result bound to the evidence revision it reviewed."""

    revision: str
    role_round: RoleRound[T]
    seconds: float


@dataclass
class _GroundedStandardState[T]:
    """Mutable state for one unit's revisioned standard judgments."""

    context: GroundingContext
    navigation: SourceNavigationSession | None
    remaining: int
    accumulator: FindingAccumulator[T]
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


def _evidence_revision(context: GroundingContext) -> str:
    return context.revision.id


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
    execute_judgment: Callable[[GroundedJudgmentTask[K]], RoleRound[T]],
    describe_judgment: Callable[[K], str],
    trace: Trace | None,
) -> None:
    """Replace one stale result with a judgment on the current evidence."""
    state.judgment_count += 1
    started = perf_counter()
    description = describe_judgment(judgment)
    emit_trace(
        trace,
        "judgment",
        stage="selected",
        judgment=state.judgment_count,
        evidence_revision=state.context.revision.id,
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
        known=tuple(state.accumulator.findings),
    )
    role_round = execute_judgment(task)
    state.accumulator.add(role_round.findings)
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
        evidence_revision=state.context.revision.id,
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
    execute_judgment: Callable[[GroundedJudgmentTask[K]], RoleRound[T]],
    describe_judgment: Callable[[K], str],
    trace: Trace | None,
) -> tuple[K, ...]:
    """Run missing or stale judgments until every result shares one revision."""
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
    """Finish every judgment on one final evidence revision without losing candidates."""
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
        accumulator=accumulator,
    )

    def execute_role(task: GroundedJudgmentTask[K]) -> RoleRound[T]:
        return run_role_round(
            find=lambda: execute_judgment(task),
            finder_label=finder_label,
            key=key,
            fold=accumulator.fold,
            title=title,
        )

    planned = _stabilize_revisioned_judgments(
        state,
        plan_judgments=plan_judgments,
        execute_judgment=execute_role,
        describe_judgment=describe_judgment,
        trace=trace,
    )
    failures: list[str] = [preparation_failure_reason] if preparation_failure_reason else []
    grounding = [state.context.coverage]
    for index, judgment in enumerate(planned, 1):
        description = describe_judgment(judgment)
        result = state.results[_judgment_identity(judgment, describe_judgment)]
        role_round = result.role_round
        grounding.append(role_round.grounding)
        if on_judgment is not None:
            on_judgment(index, len(planned), description, round(result.seconds, 1))
        if not role_round.clean:
            failures.append(f"{role_round.failure_reason} [review judgment {index}/{len(planned)} for {description}]")
    return ReviewCycle(
        findings=state.accumulator.findings,
        errors=len(failures),
        failure_reason=". ".join(failures),
        grounding=merge_grounding_coverage(tuple(grounding)),
        source_evidence=state.context.source_evidence,
    )


def run_grounded_role_judgments[T, K](
    context: GroundingContext,
    *,
    plan_judgments: Callable[[GroundingContext], Iterable[K]],
    execute_judgment: Callable[[GroundedJudgmentTask[K]], RoleRound[T]],
    describe_judgment: Callable[[K], str],
    accumulator: FindingAccumulator[T],
    max_followups: int,
    navigation_session: SourceNavigationSession | None = None,
    on_judgment: JudgmentProgress | None = None,
    trace: Trace | None = None,
) -> ReviewCycle[T]:
    """Run revision-aware role sequences under the shared judgment plan."""
    if max_followups < 0:
        raise ValueError("max_followups must be nonnegative")
    state = _GroundedStandardState[T](
        context=context,
        navigation=(
            navigation_session
            if navigation_session is not None
            else context.navigator.session()
            if context.navigator is not None
            else None
        ),
        remaining=max_followups,
        accumulator=accumulator,
    )
    planned = _stabilize_revisioned_judgments(
        state,
        plan_judgments=plan_judgments,
        execute_judgment=execute_judgment,
        describe_judgment=describe_judgment,
        trace=trace,
    )
    failures: list[str] = []
    grounding = [state.context.coverage]
    pending: list[PendingWorkRecord] = []
    resolved: list[str] = []
    for index, judgment in enumerate(planned, 1):
        description = describe_judgment(judgment)
        result = state.results[_judgment_identity(judgment, describe_judgment)]
        role_round = result.role_round
        grounding.append(role_round.grounding)
        pending.extend(role_round.pending)
        resolved.extend(role_round.resolved_pending)
        if on_judgment is not None:
            on_judgment(index, len(planned), description, round(result.seconds, 1))
        if not role_round.clean:
            failures.append(f"{role_round.failure_reason} [review judgment {index}/{len(planned)} for {description}]")
    return ReviewCycle(
        findings=accumulator.findings,
        pending=pending,
        resolved_pending=tuple(dict.fromkeys(resolved)),
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

    @property
    def clean_streak(self) -> int:
        """Count trailing clean rounds that add no identity and leave no pending work."""
        streak = 0
        for new, clean, pending in zip(
            reversed(self.new_per_round),
            reversed(self.clean_per_round),
            reversed(self.pending_per_round),
            strict=True,
        ):
            if new or not clean or pending:
                break
            streak += 1
        return streak


def _schedule_dict(plan: ReviewSchedule) -> dict[str, object]:
    """Return the exact generic schedule semantics used by persistence adapters."""
    return {
        "mode": plan.mode,
        "max_rounds": plan.max_rounds,
        "min_rounds": plan.min_rounds,
        "converge_after": plan.converge_after if plan.completion == "converge" else None,
        "completion": plan.completion,
        "stop_on_failure": plan.stop_on_failure,
    }


def empty_scheduling_receipt(plan: ReviewSchedule, *, stop_reason: str) -> SchedulingReceipt:
    """Record a run action that correctly scheduled no unit execution."""
    return SchedulingReceipt.create(
        schedule=_schedule_dict(plan),
        unit_ids=(),
        rounds=(),
        stop_reason=stop_reason,
    )


def _pending_record(record: PendingWorkRecord) -> PendingWorkRecord:
    value = dict(record)
    value.pop("id", None)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    identity = f"pending-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"
    return {"id": identity, **value}


def run_review_cycles[T](
    *,
    plan: ReviewSchedule,
    execute: Callable[[int, list[T]], ReviewCycle[T]],
    execute_pending: Callable[[int, list[T], tuple[PendingWorkRecord, ...]], ReviewCycle[T]] | None = None,
    accumulator: FindingAccumulator[T],
    convergence: ConvergenceState | None = None,
    initial_pending: Iterable[PendingWorkRecord] = (),
    checkpoint_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
    on_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
    planned_unit_ids: tuple[str, ...] = (),
) -> ReviewOutcome[T]:
    """Run target supplied cycles through one accumulation and completion contract."""
    state = convergence or ConvergenceState(converge_after=plan.converge_after)
    failures_by_unit: dict[tuple[int, int, tuple[str, ...]], ReviewUnitFailure] = {}
    recovered_failures: list[ReviewUnitFailure] = []
    incomplete: list[T] = []
    pending_by_id = {record["id"]: record for record in (_pending_record(item) for item in initial_pending)}
    errors = 0
    failure_reasons: list[str] = []
    grounding: list[GroundingCoverage] = []
    rounds = 0
    converged = False
    round_records: list[SchedulingRound] = []
    stop_reason = "round_limit"

    for rounds in range(1, plan.max_rounds + 1):
        round_started = perf_counter()
        prior_pending = tuple(pending_by_id.values())
        cycle = (
            execute_pending(rounds, accumulator.findings, prior_pending)
            if execute_pending is not None
            else execute(rounds, accumulator.findings)
        )
        new_count = accumulator.add(cycle.findings)
        for identity in cycle.resolved_pending:
            pending_by_id.pop(identity, None)
        for record in cycle.pending:
            normalized = _pending_record(record)
            pending_by_id[normalized["id"]] = normalized
        pending = tuple(pending_by_id.values())
        state.record(new_count, clean=cycle.clean, pending=bool(pending))
        for failure in cycle.failures:
            failures_by_unit[(failure.index, failure.total, failure.paths)] = failure
        for failure in cycle.recovered_failures:
            failures_by_unit.pop((failure.index, failure.total, failure.paths), None)
            if failure not in recovered_failures:
                recovered_failures.append(failure)
        errors = max(0, errors + cycle.errors - cycle.recovered_errors)
        grounding.append(cycle.grounding)
        incomplete = [item for item in incomplete if item not in cycle.findings]
        incomplete.extend(item for item in cycle.incomplete if item not in incomplete)
        if cycle.failure_reason:
            failure_reasons.append(cycle.failure_reason)
        callback_cycle = replace(cycle, pending=list(pending))
        checkpoint_failed = False
        if checkpoint_round is not None:
            try:
                checkpoint_round(rounds, new_count, len(accumulator.findings), callback_cycle)
            except Exception as exc:
                checkpoint_failed = True
                errors += 1
                failure_reasons.append(f"round checkpoint failed: {_failure_reason(exc)}")
                state.clean_per_round[-1] = False
        if on_round is not None:
            with suppress(Exception):
                on_round(rounds, new_count, len(accumulator.findings), callback_cycle)

        if planned_unit_ids:
            round_records.append(
                SchedulingRound(
                    round=rounds,
                    unit_ids=planned_unit_ids,
                    new_findings=new_count,
                    union_size=len(accumulator.findings),
                    errors=cycle.errors,
                    failures=len(cycle.failures),
                    recovered_failures=len(cycle.recovered_failures),
                    incomplete=len(cycle.incomplete),
                    pending=len(pending),
                    convergence_streak=state.clean_streak if plan.completion == "converge" else 0,
                    clean=cycle.clean and not checkpoint_failed,
                    converged=(plan.completion == "converge" and state.converged and rounds >= plan.min_rounds),
                    duration_seconds=round(perf_counter() - round_started, 3),
                )
            )

        if checkpoint_failed:
            stop_reason = "checkpoint_failure"
            break
        if not cycle.clean and plan.stop_on_failure:
            stop_reason = "failure"
            break
        if rounds < plan.min_rounds:
            continue
        if plan.completion == "single":
            stop_reason = "single_complete" if cycle.clean and not pending else "incomplete"
            break
        if state.converged:
            converged = True
            stop_reason = "converged"
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
        findings=tuple(accumulator.findings),
        failures=tuple(failures_by_unit.values()),
        recovered_failures=recovered_failures,
        incomplete=incomplete,
        pending=pending,
        errors=errors,
        converged=converged,
        requires_convergence=plan.completion == "converge",
        rounds=rounds,
        failure_reason=". ".join(failure_reasons),
        grounding=merged_grounding,
        scheduling=(
            SchedulingReceipt.create(
                schedule=_schedule_dict(plan),
                unit_ids=planned_unit_ids,
                rounds=tuple(round_records),
                stop_reason=stop_reason,
            )
            if planned_unit_ids
            else None
        ),
    )


def run_review_units[U, T](
    units: list[U],
    *,
    plan: ReviewSchedule,
    execute: Callable[[int, U, list[T]], ReviewCycle[T]],
    execute_pending: Callable[[int, U, list[T], tuple[PendingWorkRecord, ...]], ReviewCycle[T]] | None = None,
    accumulator: FindingAccumulator[T],
    unit_identity: Callable[[U], str],
    failure_for: Callable[[int, int, U, str], ReviewUnitFailure],
    convergence: ConvergenceState | None = None,
    initial_pending: Iterable[PendingWorkRecord] = (),
    concurrency: int = 1,
    on_unit: Callable[[U, float], None] | None = None,
    checkpoint_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
    on_round: Callable[[int, int, int, ReviewCycle[T]], None] | None = None,
) -> ReviewOutcome[T]:
    """Fan out every target unit inside each shared review cycle."""
    if not units:
        raise ValueError("at least one review unit is required")
    if concurrency < 1:
        raise ValueError("review concurrency must be positive")
    unit_lock = Lock()
    unit_ids = tuple(unit_identity(unit) for unit in units)
    if any(not identity for identity in unit_ids):
        raise ValueError("review unit identities must be nonempty")
    if len(set(unit_ids)) != len(unit_ids):
        raise ValueError("review unit identities must be unique")
    owned_initial_pending: list[PendingWorkRecord] = []
    active_unit_failures: dict[str, tuple[ReviewUnitFailure, int]] = {}
    for record in initial_pending:
        value = dict(record)
        owner = value.get("owner_unit_id")
        if not isinstance(owner, str) or owner not in unit_ids:
            if len(unit_ids) != 1:
                raise ValueError("pending work must name its owner unit before multi-unit review")
            value["owner_unit_id"] = unit_ids[0]
        owned_initial_pending.append(value)

    def execute_round_pending(
        round_no: int,
        known: list[T],
        pending: tuple[PendingWorkRecord, ...],
    ) -> ReviewCycle[T]:
        def invoke(owned: tuple[str, U]) -> ReviewCycle[T]:
            owner_unit_id, unit = owned
            started = perf_counter()
            try:
                with model_call_scope(unit_id=owner_unit_id, round=round_no):
                    owned_pending = tuple(item for item in pending if item.get("owner_unit_id") == owner_unit_id)
                    if execute_pending is not None:
                        result = execute_pending(round_no, unit, known, owned_pending)
                    else:
                        result = execute(round_no, unit, known)
                return replace(
                    result,
                    pending=[{**item, "owner_unit_id": owner_unit_id} for item in result.pending],
                )
            except Exception as exc:
                return ReviewCycle(
                    findings=[],
                    errors=1,
                    failure_reason=f"{type(exc).__name__}: {exc}",
                )
            finally:
                if on_unit is not None:
                    with unit_lock, suppress(Exception):
                        on_unit(unit, round(perf_counter() - started, 1))

        owned_units = list(zip(unit_ids, units, strict=True))

        if concurrency > 1 and len(units) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                results = list(pool.map(invoke, owned_units))
        else:
            results = [invoke(owned) for owned in owned_units]

        findings = [finding for result in results for finding in result.findings]
        incomplete = [finding for result in results for finding in result.incomplete]
        pending = [item for result in results for item in result.pending]
        current_failures: dict[str, tuple[ReviewUnitFailure, int]] = {}
        for index, (unit_id, unit, result) in enumerate(zip(unit_ids, units, results, strict=True), 1):
            if result.clean:
                continue
            failure = failure_for(
                index,
                len(units),
                unit,
                result.failure_reason or result.grounding.failure_reason or "review unit failed",
            )
            prior_errors = active_unit_failures.get(unit_id, (failure, 0))[1]
            current_failures[unit_id] = (failure, prior_errors + (result.errors or 1))
        recovered_ids = set(active_unit_failures).difference(current_failures)
        recovered = [active_unit_failures[unit_id][0] for unit_id in sorted(recovered_ids)]
        recovered_errors = sum(active_unit_failures[unit_id][1] for unit_id in recovered_ids)
        active_unit_failures.clear()
        active_unit_failures.update(current_failures)
        return ReviewCycle(
            findings=findings,
            incomplete=incomplete,
            failures=[failure for failure, _errors in current_failures.values()],
            recovered_failures=recovered,
            recovered_errors=recovered_errors,
            pending=pending,
            resolved_pending=tuple(
                dict.fromkeys(identity for result in results for identity in result.resolved_pending)
            ),
            errors=sum(result.errors or int(not result.clean) for result in results),
            grounding=merge_grounding_coverage(tuple(result.grounding for result in results)),
            source_evidence=tuple(dict.fromkeys(evidence for result in results for evidence in result.source_evidence)),
        )

    return run_review_cycles(
        plan=plan,
        execute=lambda round_no, known: execute_round_pending(round_no, known, ()),
        execute_pending=execute_round_pending,
        accumulator=accumulator,
        convergence=convergence,
        initial_pending=owned_initial_pending,
        checkpoint_round=checkpoint_round,
        on_round=on_round,
        planned_unit_ids=unit_ids,
    )
