"""Metering tests cover per-call records, usage aggregation, and provider delegation."""

import json

import pytest

from cyberjury.canonical import canonical_sha256
from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.metering import (
    MeteringProvider,
    UsageMeter,
    model_call_context,
    model_call_scope,
    record_model_parse,
    usage_from_calls,
    validate_model_calls_document,
)


class _Fake(Provider):
    def __init__(self, usage):
        self._usage = usage

    def complete(
        self,
        *,
        system,
        messages,
        model,
        max_tokens,
        cache=False,
        cache_prefix="",
        cache_segments=(),
        response_schema=None,
    ):
        return CompletionResult(text="ok", usage=self._usage)


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=8)


def test_metering_records_each_calls_usage_and_returns_the_inner_result():
    """One call with 100 uncached and 80 cache-read tokens returns "ok" and totals 180 input tokens."""
    meter = UsageMeter()
    inner = _Fake(Usage(input_tokens=100, output_tokens=20, cache_read_tokens=80, cache_write_tokens=0))
    result = _call(MeteringProvider(inner, meter))
    assert result.text == "ok"
    assert usage_from_calls(meter.call_snapshot()) == {
        "model_requests": 1,
        "total_input_tokens": 180,
        "uncached_input_tokens": 100,
        "cache_read_tokens": 80,
        "cache_write_tokens": 0,
        "output_tokens": 20,
    }


def test_meter_accumulates_across_calls():
    """Two identical calls double model_requests, uncached input, output, and cache-write counts."""
    meter = UsageMeter()
    metered = MeteringProvider(_Fake(Usage(input_tokens=10, output_tokens=5, cache_write_tokens=10)), meter)
    _call(metered)
    _call(metered)
    usage = usage_from_calls(meter.call_snapshot())
    assert usage["model_requests"] == 2
    assert usage["uncached_input_tokens"] == 20
    assert usage["output_tokens"] == 10
    assert usage["cache_write_tokens"] == 20


def test_call_snapshot_is_a_copy_so_a_later_call_cannot_change_it():
    """Call records taken after a 5-token call still hold one call of 5 tokens after a later 7-token call."""
    meter = UsageMeter()
    _call(MeteringProvider(_Fake(Usage(input_tokens=5)), meter))
    before = meter.call_snapshot()
    _call(MeteringProvider(_Fake(Usage(input_tokens=7)), meter))
    assert [call["input_tokens"] for call in before] == [5]


def test_a_failed_call_is_recorded_but_adds_no_usage():
    """A provider raising "down" leaves model_requests at 0 but logs one call with status "failed"."""

    class _Down(Provider):
        def complete(self, **_kwargs):
            raise RuntimeError("down")

    meter = UsageMeter()
    with pytest.raises(RuntimeError, match="down"):
        _call(MeteringProvider(_Down(), meter))

    assert usage_from_calls(meter.call_snapshot())["model_requests"] == 0
    assert meter.call_snapshot()[0]["status"] == "failed"


def test_meter_records_role_unit_prompt_size_usage_duration_and_status():
    """A finder call in unit-a records the exact field set, including prompt_chars of system plus prompt."""
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage(input_tokens=3, output_tokens=2)), meter)

    with model_call_scope(unit_id="unit-a"), model_call_context(role="finder"):
        provider.complete(
            system="system",
            messages=[Message(role="user", content="prompt")],
            model="model-a",
            max_tokens=100,
        )
        record_model_parse()

    record = meter.call_snapshot()[0]
    assert record == {
        "role": "finder",
        "trigger": "provider_request",
        "unit_id": "unit-a",
        "candidate_id": "",
        "attempt": 1,
        "model": "model-a",
        "prompt_chars": len("systemprompt"),
        "input_tokens": 3,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 2,
        "status": "ok",
        "failure_reason": "",
        "duration_seconds": record["duration_seconds"],
    }
    assert record["duration_seconds"] >= 0


def test_a_validation_failure_marks_the_same_call_failed():
    """Recording an "invalid response" parse flips the just-made call to failed with that reason."""
    meter = UsageMeter()
    with model_call_context(role="finder", trigger="initial_judgment"):
        _call(MeteringProvider(_Fake(Usage()), meter))
        record_model_parse("invalid response")

    call = meter.document()["calls"][0]
    assert (call["status"], call["failure_reason"]) == ("failed", "invalid response")


def test_scheduler_scope_supplies_unit_to_nested_model_calls():
    """A call inside model_call_scope(unit_id="unit-a") records that unit and the initial_judgment trigger."""
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    with model_call_scope(unit_id="unit-a"), model_call_context(role="finder", trigger="initial_judgment"):
        _call(provider)
        record_model_parse()

    record = meter.call_snapshot()[0]
    assert record["unit_id"] == "unit-a"
    assert record["trigger"] == "initial_judgment"


def test_a_candidate_model_call_binds_the_candidate_instead_of_a_scheduler_unit():
    """An issue_link call with candidate_id="candidate-a" records that candidate and an empty unit_id."""
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    with model_call_context(role="issue linker", trigger="issue_link", candidate_id="candidate-a"):
        _call(provider)
        record_model_parse()

    record = meter.call_snapshot()[0]
    assert record["candidate_id"] == "candidate-a"
    assert record["unit_id"] == ""


def test_model_calls_document_binds_ordered_calls_and_usage():
    """The v1 document validates, and a forged hash or rehashed edited usage raises ValueError."""
    meter = UsageMeter()
    _call(MeteringProvider(_Fake(Usage(input_tokens=3, output_tokens=2)), meter))

    document = meter.document()

    assert validate_model_calls_document(document) == document
    assert document["schema"] == "cyberjury.model-calls/v1"
    assert document["calls"][0]["sequence"] == 1
    assert document["usage"]["model_requests"] == 1
    changed = {**document, "content_sha256": "0" * 64}
    with pytest.raises(ValueError, match="hash"):
        validate_model_calls_document(changed)

    changed = json.loads(json.dumps(document))
    changed["usage"]["output_tokens"] = 9
    changed["content_sha256"] = canonical_sha256({"calls": changed["calls"], "usage": changed["usage"]})
    with pytest.raises(ValueError, match="usage"):
        validate_model_calls_document(changed)
