"""RetryProvider tests inject sleep and randomness for deterministic retry behavior."""

import threading
from typing import ClassVar

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider, ResponseSchema, Usage
from cyberjury.providers.retry import EmptyResponseError, RetryProvider


class _Flaky(Provider):
    def __init__(self, fail_times):
        self._fail_times = fail_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("transient")
        return CompletionResult(text="ok")


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)


def _structured_call(provider):
    schema = ResponseSchema(
        name="reply",
        schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    )
    return provider.complete(
        system="s",
        messages=[Message(role="user", content="x")],
        model="m",
        max_tokens=8,
        response_schema=schema,
    )


def test_retries_then_succeeds():
    """Two transient failures under max_attempts=3 return "ok" on attempt 3 after sleeping 1.0 then 2.0."""
    slept = []
    inner = _Flaky(fail_times=2)
    provider = RetryProvider(inner, max_attempts=3, sleep=slept.append)
    result = _call(provider)
    assert result.text == "ok"
    assert result.attempts == 3
    assert inner.calls == 3
    assert slept == [1.0, 2.0]


def test_reraises_after_exhausting_attempts():
    """Five failures with max_attempts=3 re-raise the RuntimeError tagged with cyberjury_attempts=3."""
    inner = _Flaky(fail_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="transient") as caught:
        _call(provider)
    assert caught.value.cyberjury_attempts == 3
    assert inner.calls == 3


def test_no_retry_on_first_success():
    """An immediate success makes one inner call and never sleeps."""
    inner = _Flaky(fail_times=0)
    slept = []
    RetryProvider(inner, sleep=slept.append).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert inner.calls == 1
    assert slept == []


class _Blank(Provider):
    def __init__(self, blank_times):
        self._blank_times = blank_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        return CompletionResult(text="" if self.calls <= self._blank_times else "ok")


def test_retries_blank_body_then_succeeds():
    """One empty-text response is retried and the second call returns "ok"."""
    inner = _Blank(blank_times=1)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    assert _call(provider).text == "ok"
    assert inner.calls == 2


def test_raises_when_body_blank_every_attempt():
    """Empty text on all three attempts raises EmptyResponseError after exactly three calls."""
    inner = _Blank(blank_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(EmptyResponseError):
        _call(provider)
    assert inner.calls == 3


class _Structured(Provider):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        text, usage = self.responses.pop(0)
        return CompletionResult(text=text, usage=usage)


def test_retries_an_incomplete_structured_response_and_accumulates_usage():
    """Truncated JSON then valid JSON returns the second reply with token usage summed over both attempts."""
    inner = _Structured(
        [
            ('{"value":', Usage(input_tokens=10, output_tokens=2)),
            ('{"value":"ok"}', Usage(input_tokens=11, output_tokens=3)),
        ]
    )
    provider = RetryProvider(inner, max_attempts=2, sleep=lambda _: None)

    result = _structured_call(provider)

    assert result.text == '{"value":"ok"}'
    assert result.attempts == 2
    assert result.usage == Usage(input_tokens=21, output_tokens=5)
    assert inner.calls == 2


def test_returns_the_last_incomplete_response_for_fail_loud_downstream_validation():
    """Truncated JSON on both attempts is returned as-is with summed usage so the caller's parser can fail."""
    inner = _Structured(
        [
            ('{"value":', Usage(input_tokens=10, output_tokens=2)),
            ('{"value":', Usage(input_tokens=11, output_tokens=3)),
        ]
    )
    provider = RetryProvider(inner, max_attempts=2, sleep=lambda _: None)

    result = _structured_call(provider)

    assert result.text == '{"value":'
    assert result.attempts == 2
    assert result.usage == Usage(input_tokens=21, output_tokens=5)


def test_does_not_parse_non_structured_provider_responses():
    """Plain text without a response schema is returned after one call, not retried as invalid JSON."""
    inner = _Structured([("plain text", Usage(input_tokens=4, output_tokens=2))])

    result = _call(RetryProvider(inner, max_attempts=2, sleep=lambda _: None))

    assert result.text == "plain text"
    assert inner.calls == 1


class _RateLimited(Provider):
    def __init__(self, fail_times, exc):
        self._fail_times = fail_times
        self._exc = exc
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return CompletionResult(text="ok")


def _rate_limit_exc():
    exc = RuntimeError("429 too many requests")
    exc.status_code = 429
    return exc


def test_rate_limit_backs_off_exponentially_with_jitter():
    """Three 429 errors with jitter at its upper bound sleep 1.0, 2.0, then 4.0 seconds."""
    slept = []
    inner = _RateLimited(fail_times=3, exc=_rate_limit_exc())
    provider = RetryProvider(inner, max_attempts=4, base_delay=1.0, sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == "ok"
    assert slept == [1.0, 2.0, 4.0]


def test_rate_limit_honors_retry_after_header():
    """A retry-after: 5 response header makes the single retry sleep exactly 5.0 seconds."""

    class _Resp:
        headers: ClassVar = {"retry-after": "5"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0, sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == "ok"
    assert slept == [5.0]


def test_rate_limit_caps_at_max_delay():
    """A retry-after of 9000 seconds is clamped to the 30.0 second max_delay."""

    class _Resp:
        headers: ClassVar = {"retry-after": "9000"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0, max_delay=30.0, sleep=slept.append)
    assert _call(provider).text == "ok"
    assert slept == [30.0]


def test_non_rate_limit_keeps_linear_backoff():
    """Two generic network errors sleep 1.0 then 2.0 seconds rather than doubling."""
    slept = []
    inner = _RateLimited(fail_times=2, exc=RuntimeError("transient network blip"))
    provider = RetryProvider(inner, max_attempts=3, base_delay=1.0, sleep=slept.append)
    assert _call(provider).text == "ok"
    assert slept == [1.0, 2.0]


def test_is_rate_limit_matches_by_status_class_name_and_message():
    """Rate limit detection checks status, class name, and message."""
    from cyberjury.providers.retry import _is_rate_limit

    class RateLimitError(Exception):
        pass

    assert _is_rate_limit(RateLimitError("boom"))
    assert _is_rate_limit(RuntimeError("429 Too Many Requests"))
    assert _is_rate_limit(RuntimeError("hit the rate limit"))
    assert not _is_rate_limit(RuntimeError("connection reset by peer"))


def test_retry_after_reads_the_exception_attribute_and_tolerates_garbage():
    """A retry_after attribute of "7" parses to 7.0, while "soon" or a missing attribute yield None."""
    from cyberjury.providers.retry import _retry_after

    exc = RuntimeError("x")
    exc.retry_after = "7"
    assert _retry_after(exc) == 7.0
    bad = RuntimeError("y")
    bad.retry_after = "soon"
    assert _retry_after(bad) is None
    assert _retry_after(RuntimeError("no attr")) is None


def test_retry_after_reads_a_structured_provider_error_body():
    """An overloaded gateway can put its required delay in the error body."""
    from cyberjury.providers.retry import _retry_after

    exc = RuntimeError("origin overloaded")
    exc.body = {"retryable": True, "retry_after": 60}

    assert _retry_after(exc) == 60.0


def test_a_non_rate_limit_error_honors_its_structured_retry_delay():
    """Provider supplied recovery timing takes precedence over linear backoff."""
    exc = RuntimeError("502 bad gateway")
    exc.body = {"retryable": True, "retry_after": 60}
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = RetryProvider(inner, max_attempts=2, max_delay=90.0, sleep=slept.append)

    assert _call(provider).text == "ok"
    assert slept == [60.0]


class _Hang(Provider):
    def __init__(self):
        self.release = threading.Event()
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        self.release.wait()
        return CompletionResult(text="late")


def test_hard_timeout_aborts_a_hung_call():
    """A call blocked past the 0.2 second hard_timeout raises TimeoutError after one attempt."""
    inner = _Hang()
    provider = RetryProvider(inner, max_attempts=1, hard_timeout=0.2, sleep=lambda _: None)
    try:
        with pytest.raises(TimeoutError):
            _call(provider)
        assert inner.calls == 1
    finally:
        inner.release.set()


class _HangOnce(Provider):
    def __init__(self):
        self.release = threading.Event()
        self.calls = 0
        self.threads = []

    def complete(self, **kwargs):
        self.calls += 1
        self.threads.append(threading.current_thread())
        if self.calls == 1:
            self.release.wait()
        return CompletionResult(text=f"call {self.calls}")


def test_hard_timeout_retries_then_recovers():
    """A first call hung past the 0.2 second limit is abandoned and the second attempt returns "call 2"."""
    inner = _HangOnce()
    provider = RetryProvider(inner, max_attempts=2, hard_timeout=0.2, sleep=lambda _: None)
    try:
        result = _call(provider)
    finally:
        inner.release.set()

    assert result.text == "call 2"
    assert result.attempts == 2
    assert inner.calls == 2


def test_no_hard_timeout_leaves_call_unbounded():
    """Without a hard timeout the call runs in the caller's thread and is never abandoned."""
    inner = _HangOnce()
    threading.Timer(0.3, inner.release.set).start()

    result = _call(RetryProvider(inner, max_attempts=1))

    assert result.text == "call 1"
    assert inner.threads == [threading.current_thread()]
