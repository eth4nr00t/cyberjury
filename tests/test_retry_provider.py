"""RetryProvider with injected sleep and rand, so backoff and rate-limit handling are
deterministic and do not actually sleep."""

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
    assert _call(provider).text == "ok"
    assert inner.calls == 3
    assert slept == [1.0, 2.0]


def test_reraises_after_exhausting_attempts():
    inner = _Flaky(fail_times=5)
    provider = RetryProvider(inner, max_attempts=3, sleep=lambda _: None)
    with pytest.raises(RuntimeError, match="transient"):
        _call(provider)
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
    # rand returns its upper bound, so the jittered wait equals the exponential ceiling: a
    # rate limit must grow the delay 1, 2, 4 instead of the linear 1, 2, 3 a flat retry gives
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
    # a server Retry-After longer than max_delay is clamped, so one bad header cannot stall
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


class _Hang(Provider):
    """Blocks on `complete` until released, the proxy-holds-the-connection failure an SDK
    timeout does not catch."""

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
    inner = _Flaky(fail_times=0)
    provider = RetryProvider(inner)
    assert _call(provider).text == "ok"
