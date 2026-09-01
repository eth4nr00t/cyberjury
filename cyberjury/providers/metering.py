"""Model call context and token accounting across a review run.

Review paths can report where calls and tokens went without threading observability data
through every reviewer and verifier return value.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock
from time import perf_counter

from cyberjury.providers.base import CompletionResult, Message, Provider, ProviderFingerprint


@dataclass(kw_only=True)
class _ModelCallContext:
    """Metadata and parse callback for one provider request."""

    role: str
    unit_id: str = ""
    evidence_revision: str = ""
    round: int | None = None
    record_parse: Callable[[str, str, str], None] | None = None


_CURRENT_CALL: ContextVar[_ModelCallContext | None] = ContextVar("model_call_context", default=None)


@contextmanager
def model_call_context(
    *,
    role: str,
    unit_id: str = "",
    evidence_revision: str = "",
    round: int | None = None,
) -> Iterator[None]:
    """Publish one role context until provider response validation completes."""
    token = _CURRENT_CALL.set(
        _ModelCallContext(
            role=role,
            unit_id=unit_id,
            evidence_revision=evidence_revision,
            round=round,
        )
    )
    try:
        yield
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

    def record_call(
        self,
        record: dict[str, object],
    ) -> Callable[[str, str, str], None]:
        """Persist one call and return its parse result updater."""
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
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        started = perf_counter()
        context = _CURRENT_CALL.get()
        try:
            result = self._inner.complete(
                system=system,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                cache=cache,
                cache_prefix=cache_prefix,
            )
        except Exception as exc:
            self._meter.record_call(
                {
                    "role": context.role if context is not None else "",
                    "unit_id": context.unit_id if context is not None else "",
                    "evidence_revision": context.evidence_revision if context is not None else "",
                    "round": context.round if context is not None else None,
                    "attempt": getattr(exc, "cyberjury_attempts", 1),
                    "provider": self._inner.checkpoint_fingerprint().backend,
                    "model": model,
                    "prompt_chars": len(system) + sum(len(message.content) for message in messages),
                    "duration_seconds": round(perf_counter() - started, 3),
                    "status": "failed",
                    "parse_source": "",
                    "failure_reason": f"{type(exc).__name__}: {exc}",
                }
            )
            raise
        self._meter.add(result)
        updater = self._meter.record_call(
            {
                "role": context.role if context is not None else "",
                "unit_id": context.unit_id if context is not None else "",
                "evidence_revision": context.evidence_revision if context is not None else "",
                "round": context.round if context is not None else None,
                "attempt": result.attempts,
                "provider": self._inner.checkpoint_fingerprint().backend,
                "model": model,
                "prompt_chars": len(system) + sum(len(message.content) for message in messages),
                "input_tokens": result.usage.input_tokens,
                "cache_read_tokens": result.usage.cache_read_tokens,
                "cache_write_tokens": result.usage.cache_write_tokens,
                "output_tokens": result.usage.output_tokens,
                "duration_seconds": round(perf_counter() - started, 3),
                "status": "unvalidated",
                "parse_source": "",
                "failure_reason": "",
            }
        )
        if context is not None:
            context.record_parse = updater
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
