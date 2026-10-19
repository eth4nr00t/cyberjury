"""RetryProvider: wrap any Provider, retrying `complete` on transient failure.

Timeouts, rate limits, blank bodies, and incomplete structured JSON are retried; the last
error is re-raised once attempts are exhausted. The last non-blank response still reaches the
strict downstream schema validator, so retry never turns malformed output into a clean review.
An optional hard deadline bounds each call from outside the SDK. ``sleep`` and ``rand`` are
injectable so tests stay deterministic.
"""

from __future__ import annotations

import contextlib
import queue
import random
import threading
import time
from collections.abc import Callable
from dataclasses import replace

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.base import CompletionResult, Message, Provider, ResponseSchema, Usage


class EmptyResponseError(RuntimeError):
    """The provider returned a blank body on every attempt."""


def _add_usage(left: Usage, right: Usage) -> Usage:
    """Accumulate completed response attempts on a successful return path."""
    return Usage(
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        cache_read_tokens=left.cache_read_tokens + right.cache_read_tokens,
        cache_write_tokens=left.cache_write_tokens + right.cache_write_tokens,
    )


def _call_with_deadline(fn: Callable[[], CompletionResult], timeout: float) -> CompletionResult:
    """Run fn in a daemon thread and return its result.

    Raise TimeoutError after `timeout` seconds. This is the bound the SDK timeout fails to
    enforce against a proxy that never closes the connection. The thread is a daemon, so an
    abandoned hung call cannot keep the process alive.
    """
    out: queue.Queue = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            out.put((True, fn()))
        except BaseException as exc:
            out.put((False, exc))

    threading.Thread(target=run, daemon=True).start()
    try:
        ok, value = out.get(timeout=timeout)
    except queue.Empty:
        raise TimeoutError(f"call exceeded the {timeout}s hard deadline") from None
    if ok:
        return value
    raise value


def _is_rate_limit(exc: BaseException) -> bool:
    """Return whether the error is a rate limit, matched on the SDK status code or message.

    Matching does not depend on a provider name, so a new backend needs no change.
    """
    if getattr(exc, "status_code", None) == 429:
        return True
    if "ratelimit" in type(exc).__name__.lower():
        return True
    msg = str(exc).lower()
    return "rate limit" in msg or "429" in msg or "too many requests" in msg


def _retry_after(exc: BaseException) -> float | None:
    """Return the server's requested wait in seconds, or None when the error carries none.

    The wait is read from the Retry-After response header, a retry_after attribute, or the error body.
    """
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is not None and hasattr(headers, "get"):
        raw = headers.get("retry-after") or headers.get("Retry-After")
        if raw is not None:
            try:
                return float(raw)
            except (TypeError, ValueError):
                pass
    raw = getattr(exc, "retry_after", None)
    body = getattr(exc, "body", None)
    if raw is None and isinstance(body, dict):
        raw = body.get("retry_after")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


class RetryProvider(Provider):
    """Provider wrapper that retries transient backend failures."""

    def __init__(
        self,
        inner: Provider,
        *,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        hard_timeout: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[float, float], float] = random.uniform,
    ) -> None:
        """Bind retry limits, delay policy, and timeout wrapping around one provider."""
        self._inner = inner
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._hard_timeout = hard_timeout
        self._sleep = sleep
        self._rand = rand

    def _call_inner(self, **kwargs) -> CompletionResult:
        """Invoke the wrapped provider, bounded by the hard deadline when one is set."""
        if self._hard_timeout is None:
            return self._inner.complete(**kwargs)
        return _call_with_deadline(lambda: self._inner.complete(**kwargs), self._hard_timeout)

    def _backoff(self, exc: BaseException, attempt: int) -> float:
        """Seconds to wait before the next attempt.

        A rate limit honors the server's Retry-After, else backs off exponentially with full
        jitter so a fan-out's retries spread out instead of colliding again. A provider
        supplied delay takes precedence for any error. Other errors keep linear backoff.
        """
        after = _retry_after(exc)
        if after is not None:
            return min(after, self._max_delay)
        if _is_rate_limit(exc):
            ceiling = min(self._base_delay * (2 ** (attempt - 1)), self._max_delay)
            return self._rand(0.0, ceiling)
        return self._base_delay * attempt

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
        """Return one provider completion with successful response usage accounting."""
        usage = Usage()
        for attempt in range(1, self._max_attempts + 1):
            try:
                result = self._call_inner(
                    system=system,
                    messages=messages,
                    model=model,
                    max_tokens=max_tokens,
                    cache=cache,
                    cache_prefix=cache_prefix,
                    response_schema=response_schema,
                )
            except Exception as exc:
                if attempt == self._max_attempts:
                    with contextlib.suppress(Exception):
                        exc.cyberjury_attempts = attempt
                    raise
                self._sleep(self._backoff(exc, attempt))
                continue
            usage = _add_usage(usage, result.usage)
            blank = not result.text.strip()
            complete = not blank and (response_schema is None or parse_json_object(result.text) is not None)
            last = attempt == self._max_attempts
            if complete or (last and not blank):
                return replace(result, usage=usage, attempts=attempt)
            if last:
                error = EmptyResponseError("provider returned a blank response after all attempts")
                error.cyberjury_attempts = attempt
                raise error
            self._sleep(self._base_delay * attempt)
