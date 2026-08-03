from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.metering import MeteringProvider, UsageMeter


class _Fake(Provider):
    def __init__(self, usage):
        self._usage = usage
        self.closed = False

    def complete(self, *, system, messages, model, max_tokens, cache=False, cache_prefix=""):
        return CompletionResult(text="ok", usage=self._usage)

    def close(self):
        self.closed = True


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=8)


def test_metering_records_each_calls_usage_and_returns_the_inner_result():
    meter = UsageMeter()
    inner = _Fake(Usage(input_tokens=100, output_tokens=20, cache_read_tokens=80, cache_write_tokens=0))
    metered = MeteringProvider(inner, meter)
    result = _call(metered)
    assert result.text == "ok"
    assert (meter.calls, meter.input_tokens, meter.output_tokens, meter.cache_read_tokens) == (1, 100, 20, 80)


def test_meter_accumulates_across_calls():
    meter = UsageMeter()
    metered = MeteringProvider(_Fake(Usage(input_tokens=10, output_tokens=5, cache_write_tokens=10)), meter)
    _call(metered)
    _call(metered)
    assert meter.calls == 2
    assert meter.input_tokens == 20
    assert meter.output_tokens == 10
    assert meter.cache_write_tokens == 20


def test_summary_names_every_bucket():
    meter = UsageMeter(calls=3, input_tokens=1, output_tokens=2, cache_read_tokens=3, cache_write_tokens=4)
    s = meter.summary()
    assert "3 model calls" in s
    assert "input=1" in s
    assert "output=2" in s
    assert "cache_read=3" in s
    assert "cache_write=4" in s


def test_close_delegates_to_the_inner_provider():
    inner = _Fake(Usage())
    MeteringProvider(inner, UsageMeter()).close()
    assert inner.closed is True
