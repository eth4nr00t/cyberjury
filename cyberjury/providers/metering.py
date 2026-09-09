"""Model call context and token accounting across a review run.

Review paths can report where calls and tokens went without threading observability data
through every reviewer and verifier return value.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from time import perf_counter

from cyberjury.providers.base import CompletionResult, Message, Provider, ProviderFingerprint, ResponseSchema

MODEL_CALLS_SCHEMA = "cyberjury.model-calls/v4"
_V3_MODEL_CALLS_SCHEMA = "cyberjury.model-calls/v3"
_V2_MODEL_CALLS_SCHEMA = "cyberjury.model-calls/v2"
_LEGACY_MODEL_CALLS_SCHEMA = "cyberjury.model-calls/v1"
_MODEL_CALL_TRIGGERS = {
    "coverage_analysis",
    "evidence_followup",
    "initial_judgment",
    "proof_generation",
    "provider_request",
    "refutation_confirmation",
    "verification",
}

type ParseUpdate = Callable[[str, str, str], None]
type NavigationUpdate = Callable[[str, tuple[str, ...], str, int, int, str], None]


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _content_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(kw_only=True)
class _ModelCallContext:
    """Metadata and parse callback for one provider request."""

    role: str
    trigger: str = "provider_request"
    unit_id: str = ""
    evidence_revision: str = ""
    review_brief_sha256: str = ""
    decision_rule_ids: tuple[str, ...] = ()
    round: int | None = None
    record_parse: ParseUpdate | None = None
    record_navigation: NavigationUpdate | None = None

    def navigation(
        self,
        status: str,
        *,
        delta_ids: tuple[str, ...] = (),
        delta_text: str = "",
        source_query_count: int = 0,
        evidence_request_count: int = 0,
        failure_reason: str = "",
    ) -> None:
        """Record the evidence work caused by this model response."""
        if self.record_navigation is not None:
            self.record_navigation(
                status,
                delta_ids,
                delta_text,
                source_query_count,
                evidence_request_count,
                failure_reason,
            )


_CURRENT_CALL: ContextVar[_ModelCallContext | None] = ContextVar("model_call_context", default=None)


@dataclass(frozen=True, kw_only=True)
class _ModelCallScope:
    """Scheduler identity inherited by model calls inside one unit execution."""

    unit_id: str
    round: int


_CURRENT_SCOPE: ContextVar[_ModelCallScope | None] = ContextVar("model_call_scope", default=None)


@contextmanager
def model_call_scope(*, unit_id: str, round: int) -> Iterator[None]:
    """Bind one planned unit and scheduler round around its model calls."""
    if not unit_id:
        raise ValueError("model call scope unit_id must be nonempty")
    if isinstance(round, bool) or not isinstance(round, int) or round < 1:
        raise ValueError("model call scope round must be a positive integer")
    token = _CURRENT_SCOPE.set(_ModelCallScope(unit_id=unit_id, round=round))
    try:
        yield
    finally:
        _CURRENT_SCOPE.reset(token)


@contextmanager
def model_call_context(
    *,
    role: str,
    trigger: str = "provider_request",
    unit_id: str = "",
    evidence_revision: str = "",
    review_brief_sha256: str = "",
    decision_rule_ids: tuple[str, ...] = (),
    round: int | None = None,
) -> Iterator[_ModelCallContext]:
    """Publish one role context until provider response validation completes."""
    scope = _CURRENT_SCOPE.get()
    context = _ModelCallContext(
        role=role,
        trigger=trigger,
        unit_id=unit_id or (scope.unit_id if scope is not None else ""),
        evidence_revision=evidence_revision,
        review_brief_sha256=review_brief_sha256,
        decision_rule_ids=decision_rule_ids,
        round=round if round is not None else scope.round if scope is not None else None,
    )
    token = _CURRENT_CALL.set(context)
    try:
        yield context
    finally:
        _CURRENT_CALL.reset(token)


def record_model_parse(source: str, *, status: str = "ok", failure_reason: str = "") -> None:
    """Complete the current metered record with strict parse provenance."""
    context = _CURRENT_CALL.get()
    if context is not None and context.record_parse is not None:
        context.record_parse(source, status, failure_reason)


@dataclass
class UsageMeter:
    """Running token totals for one run.

    Guarded by a lock since the fan-out records concurrently.
    """

    model_requests: int = 0
    uncached_input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    calls: list[dict[str, object]] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def add(self, result: CompletionResult) -> None:
        """Add one completion usage record to the shared meter."""
        u = result.usage
        with self._lock:
            self.model_requests += 1
            self.uncached_input_tokens += u.input_tokens
            self.output_tokens += u.output_tokens
            self.cache_read_tokens += u.cache_read_tokens
            self.cache_write_tokens += u.cache_write_tokens

    def snapshot(self) -> dict[str, int]:
        """The totals as plain data, so a run can persist them and not only print them.

        `total_input_tokens` is derived because comparing two runs on the uncached count alone
        reads a cache hit as a saving the request never made.
        """
        with self._lock:
            return {
                "model_requests": self.model_requests,
                "total_input_tokens": self.uncached_input_tokens + self.cache_read_tokens + self.cache_write_tokens,
                "uncached_input_tokens": self.uncached_input_tokens,
                "cache_read_tokens": self.cache_read_tokens,
                "cache_write_tokens": self.cache_write_tokens,
                "output_tokens": self.output_tokens,
            }

    def summary(self) -> str:
        """Return aggregate token usage for the run."""
        s = self.snapshot()
        return (
            f"tokens over {s['model_requests']} model requests: "
            f"total_input={s['total_input_tokens']} uncached={s['uncached_input_tokens']} "
            f"cache_read={s['cache_read_tokens']} cache_write={s['cache_write_tokens']} "
            f"output={s['output_tokens']}"
        )

    def call_snapshot(self) -> list[dict[str, object]]:
        """Return per request records in completion order."""
        with self._lock:
            return [dict(record) for record in self.calls]

    def document(self) -> dict[str, object]:
        """Return the strict attempt artifact for every model call."""
        calls = [{"sequence": index, **record} for index, record in enumerate(self.call_snapshot(), 1)]
        semantic: dict[str, object] = {"calls": calls, "usage": self.snapshot()}
        return {
            "schema": MODEL_CALLS_SCHEMA,
            **semantic,
            "content_sha256": _content_sha256(semantic),
        }

    def record_call(self, record: dict[str, object]) -> tuple[ParseUpdate, NavigationUpdate]:
        """Persist one call and return parse and navigation updaters."""
        with self._lock:
            index = len(self.calls)
            self.calls.append(record)

        def update(source: str, status: str, failure_reason: str) -> None:
            with self._lock:
                self.calls[index].update(
                    parse_source=source,
                    status=status,
                    failure_reason=failure_reason,
                )

        def update_navigation(
            status: str,
            delta_ids: tuple[str, ...],
            delta_text: str,
            source_query_count: int,
            evidence_request_count: int,
            failure_reason: str,
        ) -> None:
            with self._lock:
                self.calls[index].update(
                    navigation_status=status,
                    navigation_delta_ids=list(delta_ids),
                    navigation_delta_chars=len(delta_text),
                    navigation_delta_sha256=_content_sha256(delta_text) if delta_text else "",
                    source_query_count=source_query_count,
                    evidence_request_count=evidence_request_count,
                    navigation_failure_reason=failure_reason,
                )

        return update, update_navigation


class MeteringProvider(Provider):
    """Record each wrapped call's usage into the shared meter.

    A backend that reports no usage adds zeros, so the
    total reflects the metered seats and never blocks.
    """

    def __init__(self, inner: Provider, meter: UsageMeter) -> None:
        """Wrap one provider and share its usage totals with the run meter."""
        self._inner = inner
        self._meter = meter

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
        cache_prefix: str = "",
        response_schema: ResponseSchema | None = None,
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        started = perf_counter()
        context = _CURRENT_CALL.get()
        prompt_sha256 = _prompt_sha256(system, messages)
        response_schema_sha256 = (
            _content_sha256({"name": response_schema.name, "schema": response_schema.schema})
            if response_schema is not None
            else ""
        )
        try:
            result = self._inner.complete(
                system=system,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                cache=cache,
                cache_prefix=cache_prefix,
                response_schema=response_schema,
            )
        except Exception as exc:
            record = {
                "role": context.role if context is not None else "",
                "trigger": context.trigger if context is not None else "provider_request",
                "unit_id": context.unit_id if context is not None else "",
                "evidence_revision": context.evidence_revision if context is not None else "",
                "review_brief_sha256": context.review_brief_sha256 if context is not None else "",
                "decision_rule_ids": list(context.decision_rule_ids) if context is not None else [],
                "round": context.round if context is not None else None,
                "attempt": getattr(exc, "cyberjury_attempts", 1),
                "provider": self._inner.checkpoint_fingerprint().backend,
                "model": model,
                "prompt_chars": len(system) + sum(len(message.content) for message in messages),
                "prompt_sha256": prompt_sha256,
                "cache_enabled": cache,
                "cache_prefix_chars": len(cache_prefix),
                "cache_prefix_sha256": _content_sha256(cache_prefix) if cache_prefix else "",
                "response_schema_sha256": response_schema_sha256,
                "response_chars": 0,
                "response_sha256": "",
                "duration_seconds": round(perf_counter() - started, 3),
                "status": "failed",
                "parse_source": "",
                "failure_reason": f"{type(exc).__name__}: {exc}",
                "navigation_status": "not_applicable",
                "navigation_delta_ids": [],
                "navigation_delta_chars": 0,
                "navigation_delta_sha256": "",
                "source_query_count": 0,
                "evidence_request_count": 0,
                "navigation_failure_reason": "",
            }
            record["call_id"] = _model_call_id(record)
            parse_update, navigation_update = self._meter.record_call(record)
            if context is not None:
                context.record_parse = parse_update
                context.record_navigation = navigation_update
            raise
        self._meter.add(result)
        record = {
            "role": context.role if context is not None else "",
            "trigger": context.trigger if context is not None else "provider_request",
            "unit_id": context.unit_id if context is not None else "",
            "evidence_revision": context.evidence_revision if context is not None else "",
            "review_brief_sha256": context.review_brief_sha256 if context is not None else "",
            "decision_rule_ids": list(context.decision_rule_ids) if context is not None else [],
            "round": context.round if context is not None else None,
            "attempt": result.attempts,
            "provider": self._inner.checkpoint_fingerprint().backend,
            "model": model,
            "prompt_chars": len(system) + sum(len(message.content) for message in messages),
            "prompt_sha256": prompt_sha256,
            "cache_enabled": cache,
            "cache_prefix_chars": len(cache_prefix),
            "cache_prefix_sha256": _content_sha256(cache_prefix) if cache_prefix else "",
            "response_schema_sha256": response_schema_sha256,
            "response_chars": len(result.text),
            "response_sha256": _content_sha256(result.text) if result.text else "",
            "input_tokens": result.usage.input_tokens,
            "cache_read_tokens": result.usage.cache_read_tokens,
            "cache_write_tokens": result.usage.cache_write_tokens,
            "output_tokens": result.usage.output_tokens,
            "duration_seconds": round(perf_counter() - started, 3),
            "status": "unvalidated",
            "parse_source": "",
            "failure_reason": "",
            "navigation_status": "not_applicable",
            "navigation_delta_ids": [],
            "navigation_delta_chars": 0,
            "navigation_delta_sha256": "",
            "source_query_count": 0,
            "evidence_request_count": 0,
            "navigation_failure_reason": "",
        }
        record["call_id"] = _model_call_id(record)
        parse_update, navigation_update = self._meter.record_call(record)
        if context is not None:
            context.record_parse = parse_update
            context.record_navigation = navigation_update
        return result

    def checkpoint_fingerprint(self) -> ProviderFingerprint:
        """Ignore metering state while preserving the wrapped provider identity."""
        return ProviderFingerprint(
            backend=f"{type(self).__module__}.{type(self).__qualname__}",
            inner=self._inner.checkpoint_fingerprint(),
        )

    def close(self) -> None:
        """Close the wrapped provider when it exposes a close hook."""
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()


def _prompt_sha256(system: str, messages: list[Message]) -> str:
    """Identify the exact model visible system and message input."""
    value = {
        "system": system,
        "messages": [{"role": message.role, "content": message.content} for message in messages],
    }
    return _content_sha256(value)


def _model_call_id(record: dict[str, object]) -> str:
    """Identify one logical model input independently from concurrent completion order."""
    identity = {
        "schema": "cyberjury.model-call-identity/v1",
        "input": {
            key: record[key]
            for key in (
                "role",
                "trigger",
                "unit_id",
                "evidence_revision",
                "review_brief_sha256",
                "decision_rule_ids",
                "round",
                "provider",
                "model",
                "prompt_sha256",
                "response_schema_sha256",
            )
        },
    }
    return f"call-{_content_sha256(identity)[:24]}"


def validate_model_calls_document(value: object) -> dict[str, object]:
    """Validate one persisted model call artifact and return it unchanged."""
    if not isinstance(value, dict) or set(value) != {"schema", "calls", "usage", "content_sha256"}:
        raise ValueError("model calls artifact has an invalid shape")
    schema = value["schema"]
    if schema not in {
        MODEL_CALLS_SCHEMA,
        _V3_MODEL_CALLS_SCHEMA,
        _V2_MODEL_CALLS_SCHEMA,
        _LEGACY_MODEL_CALLS_SCHEMA,
    }:
        raise ValueError("model calls artifact schema is unsupported")
    calls = value["calls"]
    usage = value["usage"]
    if not isinstance(calls, list) or not all(isinstance(call, dict) for call in calls):
        raise ValueError("model calls artifact calls must be an object list")
    if [call.get("sequence") for call in calls] != list(range(1, len(calls) + 1)):
        raise ValueError("model calls artifact sequence is invalid")
    common_fields = {
        "sequence",
        "role",
        "unit_id",
        "evidence_revision",
        "review_brief_sha256",
        "decision_rule_ids",
        "round",
        "attempt",
        "provider",
        "model",
        "prompt_chars",
        "prompt_sha256",
        "response_schema_sha256",
        "duration_seconds",
        "status",
        "parse_source",
        "failure_reason",
    }
    if schema in {MODEL_CALLS_SCHEMA, _V3_MODEL_CALLS_SCHEMA, _V2_MODEL_CALLS_SCHEMA}:
        common_fields.update({"call_id", "trigger"})
    if schema in {MODEL_CALLS_SCHEMA, _V3_MODEL_CALLS_SCHEMA}:
        common_fields.update(
            {
                "navigation_status",
                "navigation_delta_ids",
                "navigation_delta_chars",
                "navigation_delta_sha256",
                "source_query_count",
                "evidence_request_count",
                "navigation_failure_reason",
            }
        )
    if schema == MODEL_CALLS_SCHEMA:
        common_fields.update(
            {
                "cache_prefix_chars",
                "cache_prefix_sha256",
                "cache_enabled",
                "response_chars",
                "response_sha256",
            }
        )
    token_fields = {
        "input_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "output_tokens",
    }
    for call in calls:
        fields = set(call)
        if fields != common_fields and fields != common_fields | token_fields:
            raise ValueError("model call record has an invalid shape")
        if not all(isinstance(call[field], str) for field in ("role", "unit_id", "evidence_revision")):
            raise ValueError("model call identity fields are invalid")
        if schema in {MODEL_CALLS_SCHEMA, _V3_MODEL_CALLS_SCHEMA, _V2_MODEL_CALLS_SCHEMA}:
            if not isinstance(call["trigger"], str) or call["trigger"] not in _MODEL_CALL_TRIGGERS:
                raise ValueError("model call trigger is invalid")
            if call["call_id"] != _model_call_id(call):
                raise ValueError("model call id does not match its logical input")
        if schema in {MODEL_CALLS_SCHEMA, _V3_MODEL_CALLS_SCHEMA}:
            if not isinstance(call["navigation_status"], str) or call["navigation_status"] not in {
                "not_applicable",
                "not_evaluated",
                "not_requested",
                "delivered",
                "failed",
                "limit_reached",
            }:
                raise ValueError("model call navigation_status is invalid")
            delta_ids = call["navigation_delta_ids"]
            if not isinstance(delta_ids, list) or not all(isinstance(item, str) and item for item in delta_ids):
                raise ValueError("model call navigation_delta_ids are invalid")
            if len(delta_ids) != len(set(delta_ids)):
                raise ValueError("model call navigation_delta_ids must be unique")
            for field in ("navigation_delta_chars", "source_query_count", "evidence_request_count"):
                if isinstance(call[field], bool) or not isinstance(call[field], int) or call[field] < 0:
                    raise ValueError(f"model call {field} is invalid")
            delta_sha256 = call["navigation_delta_sha256"]
            if not isinstance(delta_sha256, str) or (
                delta_sha256
                and (len(delta_sha256) != 64 or any(character not in "0123456789abcdef" for character in delta_sha256))
            ):
                raise ValueError("model call navigation_delta_sha256 is invalid")
            if not isinstance(call["navigation_failure_reason"], str):
                raise ValueError("model call navigation_failure_reason is invalid")
            has_delta = bool(delta_ids or call["navigation_delta_chars"] or delta_sha256)
            if call["navigation_status"] == "delivered" and (not call["navigation_delta_chars"] or not delta_sha256):
                raise ValueError("delivered model call navigation must contain a text delta")
            if call["navigation_status"] != "delivered" and has_delta:
                raise ValueError("model call navigation delta requires delivered status")
            if call["navigation_status"] == "failed" and not call["navigation_failure_reason"]:
                raise ValueError("failed model call navigation needs a failure reason")
            if call["navigation_status"] != "failed" and call["navigation_failure_reason"]:
                raise ValueError("model call navigation failure reason requires failed status")
            if call["navigation_status"] in {"not_applicable", "not_evaluated", "not_requested"} and (
                call["source_query_count"] or call["evidence_request_count"]
            ):
                raise ValueError("model call without navigation cannot contain request counts")
            judgment_call = call["trigger"] in {"initial_judgment", "evidence_followup"}
            if judgment_call and call["navigation_status"] == "not_applicable":
                raise ValueError("judgment model call has no navigation outcome")
            if call["navigation_status"] == "not_evaluated" and call["status"] != "failed":
                raise ValueError("unevaluated navigation requires a failed model call")
            if not judgment_call and call["navigation_status"] != "not_applicable":
                raise ValueError("nonjudgment model call cannot contain a navigation outcome")
        if schema == MODEL_CALLS_SCHEMA:
            if not isinstance(call["cache_enabled"], bool):
                raise ValueError("model call cache_enabled is invalid")
            for field in ("cache_prefix_chars", "response_chars"):
                if isinstance(call[field], bool) or not isinstance(call[field], int) or call[field] < 0:
                    raise ValueError(f"model call {field} is invalid")
            for chars_field, digest_field in (
                ("cache_prefix_chars", "cache_prefix_sha256"),
                ("response_chars", "response_sha256"),
            ):
                digest = call[digest_field]
                if not isinstance(digest, str):
                    raise ValueError(f"model call {digest_field} is invalid")
                malformed = len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
                if bool(call[chars_field]) != bool(digest) or (digest and malformed):
                    raise ValueError(f"model call {digest_field} does not match {chars_field}")
        if not all(isinstance(call[field], str) and call[field] for field in ("provider", "model")):
            raise ValueError("model call provider fields are invalid")
        for digest_field in ("prompt_sha256", "response_schema_sha256", "review_brief_sha256"):
            digest = call[digest_field]
            if not isinstance(digest, str):
                raise ValueError(f"model call {digest_field} is invalid")
            malformed_digest = len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
            if digest and malformed_digest:
                raise ValueError(f"model call {digest_field} is invalid")
        rule_ids = call["decision_rule_ids"]
        if not isinstance(rule_ids, list) or not all(isinstance(rule_id, str) and rule_id for rule_id in rule_ids):
            raise ValueError("model call decision_rule_ids are invalid")
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("model call decision_rule_ids must be unique")
        if call["status"] not in {"unvalidated", "ok", "failed"}:
            raise ValueError("model call status is invalid")
        if not isinstance(call["parse_source"], str) or not isinstance(call["failure_reason"], str):
            raise ValueError("model call parse result is invalid")
        if isinstance(call["attempt"], bool) or not isinstance(call["attempt"], int) or call["attempt"] < 1:
            raise ValueError("model call attempt is invalid")
        if call["round"] is not None and (
            isinstance(call["round"], bool) or not isinstance(call["round"], int) or call["round"] < 0
        ):
            raise ValueError("model call round is invalid")
        if (
            isinstance(call["prompt_chars"], bool)
            or not isinstance(call["prompt_chars"], int)
            or call["prompt_chars"] < 0
        ):
            raise ValueError("model call prompt_chars is invalid")
        if (
            isinstance(call["duration_seconds"], bool)
            or not isinstance(call["duration_seconds"], int | float)
            or call["duration_seconds"] < 0
        ):
            raise ValueError("model call duration is invalid")
        if token_fields <= fields and any(
            isinstance(call[field], bool) or not isinstance(call[field], int) or call[field] < 0
            for field in token_fields
        ):
            raise ValueError("model call token values are invalid")
    usage_fields = {
        "model_requests",
        "total_input_tokens",
        "uncached_input_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "output_tokens",
    }
    if not isinstance(usage, dict) or set(usage) != usage_fields:
        raise ValueError("model calls artifact usage is invalid")
    if not all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in usage.values()):
        raise ValueError("model calls artifact usage values are invalid")
    metered = [call for call in calls if token_fields <= set(call)]
    expected_usage = {
        "model_requests": len(metered),
        "uncached_input_tokens": sum(call["input_tokens"] for call in metered),
        "cache_read_tokens": sum(call["cache_read_tokens"] for call in metered),
        "cache_write_tokens": sum(call["cache_write_tokens"] for call in metered),
        "output_tokens": sum(call["output_tokens"] for call in metered),
    }
    expected_usage["total_input_tokens"] = (
        expected_usage["uncached_input_tokens"]
        + expected_usage["cache_read_tokens"]
        + expected_usage["cache_write_tokens"]
    )
    if usage != expected_usage:
        raise ValueError("model calls artifact usage does not equal its call records")
    digest = value["content_sha256"]
    semantic = {"calls": calls, "usage": usage}
    if not isinstance(digest, str) or digest != _content_sha256(semantic):
        raise ValueError("model calls artifact hash does not match its content")
    return value
