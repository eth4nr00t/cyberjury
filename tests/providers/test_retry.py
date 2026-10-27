"""RetryProvider tests inject sleep and randomness for deterministic retry behavior."""

import threading
from typing import ClassVar

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider, ProviderAccessError, ResponseSchema, Usage
from cyberjury.providers.retry import EmptyResponseError, RetryProvider

_OK = '{"value":"ok"}'
_SCHEMA = ResponseSchema(
    name="reply",
    schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"value": {"type": "string"}},
        "required": ["value"],
    },
)


def _retry(inner, *, max_attempts=3, hard_timeout=10.0, **values):
    return RetryProvider(inner, max_attempts=max_attempts, hard_timeout=hard_timeout, **values)


class _Flaky(Provider):
    def __init__(self, fail_times):
        self._fail_times = fail_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("transient")
        return CompletionResult(text=_OK)


def _call(provider):
    return provider.complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8, response_schema=_SCHEMA
    )


def test_retries_then_succeeds():
    """Two transient failures under max_attempts=3 return the reply on attempt 3 after sleeping 1.0 then 2.0."""
    slept = []
    inner = _Flaky(fail_times=2)
    provider = _retry(inner, max_attempts=3, sleep=slept.append)
    result = _call(provider)
    assert result.text == _OK
    assert result.attempts == 3
    assert inner.calls == 3
    assert slept == [1.0, 2.0]


def test_reraises_after_exhausting_attempts():
    """Five failures with max_attempts=3 re-raise the RuntimeError tagged with cyberjury_attempts=3."""
    inner = _Flaky(fail_times=5)
    provider = _retry(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="transient") as caught:
        _call(provider)
    assert caught.value.cyberjury_attempts == 3
    assert inner.calls == 3


def test_no_retry_on_first_success():
    """An immediate success makes one inner call and never sleeps."""
    inner = _Flaky(fail_times=0)
    slept = []
    _call(_retry(inner, sleep=slept.append))
    assert inner.calls == 1
    assert slept == []


class _Blank(Provider):
    def __init__(self, blank_times):
        self._blank_times = blank_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        return CompletionResult(text="" if self.calls <= self._blank_times else _OK)


def test_retries_blank_body_then_succeeds():
    """One empty-text response is retried and the second call returns the reply."""
    inner = _Blank(blank_times=1)
    provider = _retry(inner, max_attempts=3, sleep=lambda _: None)
    assert _call(provider).text == _OK
    assert inner.calls == 2


def test_raises_when_body_blank_every_attempt():
    """Empty text on all three attempts raises EmptyResponseError after exactly three calls."""
    inner = _Blank(blank_times=5)
    provider = _retry(inner, max_attempts=3, sleep=lambda _: None)
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
    provider = _retry(inner, max_attempts=2, sleep=lambda _: None)

    result = _call(provider)

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
    provider = _retry(inner, max_attempts=2, sleep=lambda _: None)

    result = _call(provider)

    assert result.text == '{"value":'
    assert result.attempts == 2
    assert result.usage == Usage(input_tokens=21, output_tokens=5)


class _RateLimited(Provider):
    def __init__(self, fail_times, exc):
        self._fail_times = fail_times
        self._exc = exc
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._exc
        return CompletionResult(text=_OK)


def _rate_limit_exc():
    exc = RuntimeError("429 too many requests")
    exc.status_code = 429
    return exc


def test_rate_limit_backs_off_exponentially_with_jitter():
    """Three 429 errors with jitter at its upper bound sleep 1.0, 2.0, then 4.0 seconds."""
    slept = []
    inner = _RateLimited(fail_times=3, exc=_rate_limit_exc())
    provider = _retry(inner, max_attempts=4, sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == _OK
    assert slept == [1.0, 2.0, 4.0]


def test_rate_limit_honors_retry_after_header():
    """A retry-after: 5 response header makes the single retry sleep exactly 5.0 seconds."""

    class _Resp:
        headers: ClassVar = {"retry-after": "5"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = _retry(inner, max_attempts=3, sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == _OK
    assert slept == [5.0]


def test_rate_limit_caps_at_max_delay():
    """A retry-after of 9000 seconds is clamped to the 60.0 second maximum delay."""

    class _Resp:
        headers: ClassVar = {"retry-after": "9000"}

    exc = RuntimeError("rate limit")
    exc.response = _Resp()
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = _retry(inner, max_attempts=3, sleep=slept.append)
    assert _call(provider).text == _OK
    assert slept == [60.0]


class _RateLimitError(Exception):
    pass


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (_RateLimitError("boom"), [0.0]),
        (RuntimeError("429 Too Many Requests"), [0.0]),
        (RuntimeError("hit the rate limit"), [0.0]),
        (RuntimeError("connection reset by peer"), [1.0]),
    ],
)
def test_rate_limits_are_recognized_by_class_name_and_message(exc, expected):
    """A RateLimitError class or a 429 or rate limit message takes jittered backoff, and a reset takes 1.0 second."""
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = _retry(inner, max_attempts=2, sleep=slept.append, rand=lambda lo, _hi: lo)
    assert _call(provider).text == _OK
    assert slept == expected


@pytest.mark.parametrize(("raw", "expected"), [("7", [7.0]), ("soon", [1.0])])
def test_retry_after_attribute_sets_the_delay_unless_it_is_not_a_number(raw, expected):
    """A retry_after attribute of "7" sleeps 7.0 seconds, while "soon" falls back to the 1.0 second linear delay."""
    exc = RuntimeError("transient")
    exc.retry_after = raw
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = _retry(inner, max_attempts=2, sleep=slept.append)
    assert _call(provider).text == _OK
    assert slept == expected


def test_a_non_rate_limit_error_honors_its_structured_retry_delay():
    """Provider supplied recovery timing takes precedence over linear backoff."""
    exc = RuntimeError("502 bad gateway")
    exc.body = {"retryable": True, "retry_after": 60}
    slept = []
    inner = _RateLimited(fail_times=1, exc=exc)
    provider = _retry(inner, max_attempts=2, sleep=slept.append)

    assert _call(provider).text == _OK
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
    provider = _retry(inner, max_attempts=1, hard_timeout=0.2, sleep=lambda _: None)
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
    provider = _retry(inner, max_attempts=2, hard_timeout=0.2, sleep=lambda _: None)
    try:
        result = _call(provider)
    finally:
        inner.release.set()

    assert result.text == "call 2"
    assert result.attempts == 2
    assert inner.calls == 2


def test_a_rejected_key_is_not_retried():
    """A 401 response raises ProviderAccessError after one call and never sleeps."""
    exc = RuntimeError("invalid x-api-key")
    exc.status_code = 401
    slept = []
    inner = _RateLimited(fail_times=5, exc=exc)

    with pytest.raises(ProviderAccessError, match="invalid x-api-key"):
        _call(_retry(inner, max_attempts=3, sleep=slept.append))

    assert (inner.calls, slept) == (1, [])
