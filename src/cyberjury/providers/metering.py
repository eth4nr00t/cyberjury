"""Model call context and token accounting across a review run.

Review paths can report where calls and tokens went without threading observability data
through every finder and issue judge return value.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from time import perf_counter

from cyberjury.canonical import canonical_sha256
from cyberjury.providers.base import CompletionResult, Message, Provider, ResponseSchema

MODEL_CALLS_SCHEMA = "cyberjury.model-calls/v1"

type ParseUpdate = Callable[[str], None]


@dataclass(kw_only=True)
class _ModelCallContext:
    role: str
    trigger: str = "provider_request"
    unit_id: str = ""
    candidate_id: str = ""
    record_parse: ParseUpdate | None = None


_CURRENT_CALL: ContextVar[_ModelCallContext | None] = ContextVar("model_call_context", default=None)
_CURRENT_UNIT: ContextVar[str] = ContextVar("model_call_unit", default="")


@contextmanager
def model_call_scope(*, unit_id: str) -> Iterator[None]:
    """Bind one planned unit around its model calls."""
    if not unit_id:
        raise ValueError("model call scope unit_id must be nonempty")
    token = _CURRENT_UNIT.set(unit_id)
    try:
        yield
    finally:
        _CURRENT_UNIT.reset(token)


@contextmanager
def model_call_context(
    *,
    role: str,
    trigger: str = "provider_request",
    candidate_id: str = "",
) -> Iterator[None]:
    """Publish one role context until provider response validation completes."""
    context = _ModelCallContext(
        role=role,
        trigger=trigger,
        unit_id=_CURRENT_UNIT.get(),
        candidate_id=candidate_id,
    )
    token = _CURRENT_CALL.set(context)
    try:
        yield
    finally:
        _CURRENT_CALL.reset(token)


def record_model_parse(failure_reason: str = "") -> None:
    """Complete the current metered record with its validation result."""
    context = _CURRENT_CALL.get()
    if context is not None and context.record_parse is not None:
        context.record_parse(failure_reason)


@dataclass
class UsageMeter:
    """Per-call model records for one run, with token totals derived from them.

    Guarded by a lock since the fan-out records concurrently.
    """

    calls: list[dict[str, object]] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def snapshot(self) -> dict[str, int]:
        """Return the token totals of every completed call as plain data.

        `total_input_tokens` is derived because comparing two runs on the uncached count alone
        reads a cache hit as a saving the request never made.
        """
        return _usage_from_calls(self.call_snapshot())

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
        return self.document_from(0)

    def document_from(self, completed_calls: int) -> dict[str, object]:
        """Return the model call artifact for calls after a run boundary."""
        with self._lock:
            records = [dict(record) for record in self.calls[completed_calls:]]
        calls = [{"sequence": index, **record} for index, record in enumerate(records, 1)]
        semantic: dict[str, object] = {"calls": calls, "usage": _usage_from_calls(records)}
        return {"schema": MODEL_CALLS_SCHEMA, **semantic, "content_sha256": canonical_sha256(semantic)}

    def record_call(self, record: dict[str, object]) -> ParseUpdate:
        """Persist one call and return its validation updater."""
        with self._lock:
            index = len(self.calls)
            self.calls.append(record)

        def update(failure_reason: str) -> None:
            with self._lock:
                self.calls[index].update(status="failed" if failure_reason else "ok", failure_reason=failure_reason)

        return update


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
        cache_segments: tuple[str, ...] = (),
        response_schema: ResponseSchema | None = None,
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        started = perf_counter()
        context = _CURRENT_CALL.get()
        record: dict[str, object] = {
            "role": context.role if context is not None else "",
            "trigger": context.trigger if context is not None else "provider_request",
            "unit_id": context.unit_id if context is not None else "",
            "candidate_id": context.candidate_id if context is not None else "",
            "attempt": 1,
            "model": model,
            "prompt_chars": len(system) + sum(len(message.content) for message in messages),
        }
        try:
            result = self._inner.complete(
                system=system,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                cache=cache,
                cache_prefix=cache_prefix,
                cache_segments=cache_segments,
                response_schema=response_schema,
            )
        except Exception as exc:
            record.update(
                attempt=getattr(exc, "cyberjury_attempts", 1),
                status="failed",
                failure_reason=f"{type(exc).__name__}: {exc}",
            )
            self._record(record, started, context)
            raise
        record.update(
            attempt=result.attempts,
            input_tokens=result.usage.input_tokens,
            cache_read_tokens=result.usage.cache_read_tokens,
            cache_write_tokens=result.usage.cache_write_tokens,
            output_tokens=result.usage.output_tokens,
            status="unvalidated",
            failure_reason="",
        )
        self._record(record, started, context)
        return result

    def _record(self, record: dict[str, object], started: float, context: _ModelCallContext | None) -> None:
        record["duration_seconds"] = round(perf_counter() - started, 3)
        parse_update = self._meter.record_call(record)
        if context is not None:
            context.record_parse = parse_update


def _usage_from_calls(calls: list[dict[str, object]]) -> dict[str, int]:
    metered = [call for call in calls if "input_tokens" in call]
    usage = {
        "model_requests": len(metered),
        "uncached_input_tokens": sum(call["input_tokens"] for call in metered),
        "cache_read_tokens": sum(call["cache_read_tokens"] for call in metered),
        "cache_write_tokens": sum(call["cache_write_tokens"] for call in metered),
        "output_tokens": sum(call["output_tokens"] for call in metered),
    }
    usage["total_input_tokens"] = (
        usage["uncached_input_tokens"] + usage["cache_read_tokens"] + usage["cache_write_tokens"]
    )
    return usage


def validate_model_calls_document(value: object) -> dict[str, object]:
    """Validate one model call artifact read from disk and return it unchanged."""
    if not isinstance(value, dict) or set(value) != {"schema", "calls", "usage", "content_sha256"}:
        raise ValueError("model calls artifact has an invalid shape")
    if value["schema"] != MODEL_CALLS_SCHEMA:
        raise ValueError("model calls artifact schema is unsupported")
    calls = value["calls"]
    if not isinstance(calls, list) or not all(
        isinstance(call, dict) and {"role", "trigger", "status"} <= set(call) for call in calls
    ):
        raise ValueError("model calls artifact calls are invalid")
    if [call.get("sequence") for call in calls] != list(range(1, len(calls) + 1)):
        raise ValueError("model calls artifact sequence is invalid")
    semantic = {"calls": calls, "usage": value["usage"]}
    if value["content_sha256"] != canonical_sha256(semantic):
        raise ValueError("model calls artifact hash does not match its content")
    if value["usage"] != _usage_from_calls(calls):
        raise ValueError("model calls artifact usage does not equal its call records")
    return value
