"""A provider wrapper that retries `complete` on transient failure."""

from __future__ import annotations

import contextlib
import queue
import random
import threading
import time
from collections.abc import Callable
from dataclasses import replace

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.base import (
    CompletionResult,
    Message,
    Provider,
    ProviderAccessError,
    ResponseSchema,
    Usage,
)

_BASE_DELAY_SECONDS = 1.0
_MAX_DELAY_SECONDS = 60.0
_ACCESS_STATUS_CODES = frozenset({401, 403, 404})


class EmptyResponseError(RuntimeError):
    """The provider's final attempt returned a blank body."""


def _add_usage(left: Usage, right: Usage) -> Usage:
    return Usage(
        input_tokens=left.input_tokens + right.input_tokens,
        output_tokens=left.output_tokens + right.output_tokens,
        cache_read_tokens=left.cache_read_tokens + right.cache_read_tokens,
        cache_write_tokens=left.cache_write_tokens + right.cache_write_tokens,
    )


def _call_with_deadline(fn: Callable[[], CompletionResult], timeout: float) -> CompletionResult:
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
    if getattr(exc, "status_code", None) == 429:
        return True
    if "ratelimit" in type(exc).__name__.lower():
        return True
    msg = str(exc).lower()
    return "rate limit" in msg or "429" in msg or "too many requests" in msg


def _retry_after(exc: BaseException) -> float | None:
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
        max_attempts: int,
        hard_timeout: float,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[float, float], float] = random.uniform,
    ) -> None:
        """Bind the attempt limit, the per call deadline, and the delay functions around one provider."""
        self._inner = inner
        self._max_attempts = max_attempts
        self._hard_timeout = hard_timeout
        self._sleep = sleep
        self._rand = rand

    def _backoff(self, exc: BaseException, attempt: int) -> float:
        after = _retry_after(exc)
        if after is not None:
            return min(after, _MAX_DELAY_SECONDS)
        if _is_rate_limit(exc):
            return self._rand(0.0, min(_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), _MAX_DELAY_SECONDS))
        return _BASE_DELAY_SECONDS * attempt

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        response_schema: ResponseSchema,
        cache_prefix: str = "",
        cache_segments: tuple[str, ...] = (),
    ) -> CompletionResult:
        """Retry transient failures and blank or incomplete replies, and return usage summed over every attempt."""
        usage = Usage()
        for attempt in range(1, self._max_attempts + 1):
            try:
                result = _call_with_deadline(
                    lambda: self._inner.complete(
                        system=system,
                        messages=messages,
                        model=model,
                        max_tokens=max_tokens,
                        response_schema=response_schema,
                        cache_prefix=cache_prefix,
                        cache_segments=cache_segments,
                    ),
                    self._hard_timeout,
                )
            except Exception as exc:
                if getattr(exc, "status_code", None) in _ACCESS_STATUS_CODES:
                    raise ProviderAccessError(f"provider rejected the request: {exc}") from exc
                if attempt == self._max_attempts:
                    with contextlib.suppress(Exception):
                        exc.cyberjury_attempts = attempt
                    raise
                self._sleep(self._backoff(exc, attempt))
                continue
            usage = _add_usage(usage, result.usage)
            blank = not result.text.strip()
            complete = not blank and parse_json_object(result.text) is not None
            last = attempt == self._max_attempts
            if complete or (last and not blank):
                return replace(result, usage=usage, attempts=attempt)
            if last:
                error = EmptyResponseError("provider returned a blank response after all attempts")
                error.cyberjury_attempts = attempt
                raise error
            self._sleep(_BASE_DELAY_SECONDS * attempt)
