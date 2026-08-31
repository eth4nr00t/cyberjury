"""RetryProvider: wrap any Provider, retrying `complete` on transient failure.

Real model calls fail intermittently, on timeouts, blank bodies, or rate limits. This
decorator retries and re-raises the last error once attempts are exhausted. A rate limit
is handled specially: it honors the server's Retry-After when present, else backs off
exponentially with full jitter, since a large fan-out hammers the provider and a flat
linear retry just collides again at the same moment. Any error that supplies a recovery
delay receives the same respect. Other errors keep the simple linear backoff. A 200
response with a blank body is a transient failure and is retried
too, since an empty reply is unusable and must not pass downstream as a clean no-
findings result. A hard deadline bounds each call from outside the SDK: an SDK request
timeout does not fire when a proxy holds the connection open and trickles bytes, so a
single stalled call can hang a fan-out for hours. The call runs in a daemon thread
the provider waits on for ``hard_timeout`` seconds, then abandons as a TimeoutError the
retry path treats like any other failure. ``None`` leaves the inner call unbounded. The
abandoned thread is a daemon, so a hung call never blocks process exit. ``sleep`` and
``rand`` are injectable so tests stay deterministic and do not actually wait.
"""

from __future__ import annotations

import queue
import random
import threading
import time
from collections.abc import Callable

from cyberjury.providers.base import CompletionResult, Message, Provider, ProviderFingerprint
from cyberjury.providers.settings import DEFAULT_PROVIDER_SETTINGS


class EmptyResponseError(RuntimeError):
    """The provider returned a blank body on every attempt."""


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
    """Whether the error is a provider rate limit.

    matched on the SDK status code or the message rather than a provider name, so a new
    backend needs no code change.
    """
    if getattr(exc, "status_code", None) == 429:
        return True
    if "ratelimit" in type(exc).__name__.lower():
        return True
    msg = str(exc).lower()
    return "rate limit" in msg or "429" in msg or "too many requests" in msg


def _retry_after(exc: BaseException) -> float | None:
    """The server's Retry-After in seconds when the exception carries one, the wait it asks for.

    else None. Read from an SDK error's response headers or a retry_after attribute.
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
        max_attempts: int = DEFAULT_PROVIDER_SETTINGS.retries_after_failure + 1,
        base_delay: float = DEFAULT_PROVIDER_SETTINGS.retry_initial_delay_seconds,
        max_delay: float = DEFAULT_PROVIDER_SETTINGS.retry_max_delay_seconds,
        hard_timeout: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[float, float], float] = random.uniform,
        retryable: tuple[type[BaseException], ...] = (Exception,),
    ) -> None:
        """Bind retry limits, delay policy, and timeout wrapping around one provider."""
        self._inner = inner
        self._max_attempts = max_attempts
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._hard_timeout = hard_timeout
        self._sleep = sleep
        self._rand = rand
        self._retryable = retryable

    def _call_inner(self, **kwargs) -> CompletionResult:
        """Invoke the wrapped provider, bounded by the hard deadline when one is set."""
        if self._hard_timeout is None:
            return self._inner.complete(**kwargs)
        return _call_with_deadline(lambda: self._inner.complete(**kwargs), self._hard_timeout)

    def checkpoint_fingerprint(self) -> ProviderFingerprint:
        """Identify the retry policy and wrapped response provider."""
        return ProviderFingerprint(
            backend=f"{type(self).__module__}.{type(self).__qualname__}",
            settings=(
                ("base_delay", str(self._base_delay)),
                ("hard_timeout", "none" if self._hard_timeout is None else str(self._hard_timeout)),
                ("max_attempts", str(self._max_attempts)),
                ("max_delay", str(self._max_delay)),
                (
                    "retryable",
                    ",".join(f"{item.__module__}.{item.__qualname__}" for item in self._retryable),
                ),
            ),
            inner=self._inner.checkpoint_fingerprint(),
        )

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
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        for attempt in range(1, self._max_attempts + 1):
            try:
                result = self._call_inner(
                    system=system,
                    messages=messages,
                    model=model,
                    max_tokens=max_tokens,
                    cache=cache,
                    cache_prefix=cache_prefix,
                )
            except self._retryable as exc:
                if attempt == self._max_attempts:
                    raise
                self._sleep(self._backoff(exc, attempt))
                continue
            if result.text.strip():
                return result
            if attempt == self._max_attempts:
                raise EmptyResponseError("provider returned a blank response after all attempts")
            self._sleep(self._base_delay * attempt)
        raise EmptyResponseError("retry provider was configured with no attempts")
