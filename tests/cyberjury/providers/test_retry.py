"""RetryProvider tests inject sleep and randomness for deterministic retry behavior."""

import threading
from typing import ClassVar

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider
from cyberjury.providers.retry import EmptyResponseError, RetryProvider


class _Flaky(Provider):
    """Fails `fail_times` times, then succeeds."""

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


def test_retries_then_succeeds():
    slept = []
    inner = _Flaky(fail_times=2)
    provider = RetryProvider(inner, max_attempts=3, sleep=slept.append)
    result = _call(provider)
    assert result.text == "ok"
    assert result.attempts == 3
    assert inner.calls == 3
    assert slept == [1.0, 2.0]


def test_reraises_after_exhausting_attempts():
    inner = _Flaky(fail_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="transient") as caught:
        _call(provider)
    assert caught.value.cyberjury_attempts == 3
    assert inner.calls == 3


def test_no_retry_on_first_success():
    inner = _Flaky(fail_times=0)
    slept = []
    RetryProvider(inner, sleep=slept.append).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert inner.calls == 1
    assert slept == []


class _Blank(Provider):
    """Returns a blank body `blank_times` times, then a real reply."""

    def __init__(self, blank_times):
        self._blank_times = blank_times
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        return CompletionResult(text="" if self.calls <= self._blank_times else "ok")


def test_retries_blank_body_then_succeeds():
    inner = _Blank(blank_times=1)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    assert _call(provider).text == "ok"
    assert inner.calls == 2


def test_raises_when_body_blank_every_attempt():
    inner = _Blank(blank_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(EmptyResponseError):
        _call(provider)
    assert inner.calls == 3


class _RateLimited(Provider):
    """Fails with a given exception `fail_times` times, then succeeds."""

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
    slept = []
    inner = _RateLimited(fail_times=3, exc=_rate_limit_exc())
    provider = RetryProvider(inner, max_attempts=4, base_delay=1.0, sleep=slept.append, rand=lambda _lo, hi: hi)
    assert _call(provider).text == "ok"
    assert slept == [1.0, 2.0, 4.0]


def test_rate_limit_honors_retry_after_header():

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
    """Blocks on `complete` until released."""

    def __init__(self):
        self.release = threading.Event()
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        self.release.wait()
        return CompletionResult(text="late")


def test_hard_timeout_aborts_a_hung_call():
    inner = _Hang()
    provider = RetryProvider(inner, max_attempts=1, hard_timeout=0.2, sleep=lambda _: None)
    try:
        with pytest.raises(TimeoutError):
            _call(provider)
        assert inner.calls == 1
    finally:
        inner.release.set()


def test_hard_timeout_retries_then_recovers():
    inner = _Hang()
    inner.release.set()
    provider = RetryProvider(inner, max_attempts=2, hard_timeout=5.0, sleep=lambda _: None)
    assert _call(provider).text == "late"


def test_no_hard_timeout_leaves_call_unbounded():
    """Disabling the hard timeout leaves the provider call unbounded."""
    inner = _Flaky(fail_times=0)
    provider = RetryProvider(inner)
    assert _call(provider).text == "ok"
