"""Metering tests cover usage aggregation, snapshots, and provider delegation."""

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
        response_schema=None,
    ):
        return CompletionResult(text="ok", usage=self._usage)


def _call(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="u")], model="m", max_tokens=8)


def test_metering_records_each_calls_usage_and_returns_the_inner_result():
    meter = UsageMeter()
    inner = _Fake(Usage(input_tokens=100, output_tokens=20, cache_read_tokens=80, cache_write_tokens=0))
    metered = MeteringProvider(inner, meter)
    result = _call(metered)
    assert result.text == "ok"
    assert (meter.model_requests, meter.uncached_input_tokens, meter.output_tokens, meter.cache_read_tokens) == (
        1,
        100,
        20,
        80,
    )


def test_meter_accumulates_across_calls():
    meter = UsageMeter()
    metered = MeteringProvider(_Fake(Usage(input_tokens=10, output_tokens=5, cache_write_tokens=10)), meter)
    _call(metered)
    _call(metered)
    assert meter.model_requests == 2
    assert meter.uncached_input_tokens == 20
    assert meter.output_tokens == 10
    assert meter.cache_write_tokens == 20


def test_summary_names_every_bucket_and_leads_with_the_whole_prompt():
    meter = UsageMeter(
        model_requests=3, uncached_input_tokens=1, output_tokens=2, cache_read_tokens=3, cache_write_tokens=4
    )
    s = meter.summary()
    assert "3 model requests" in s
    assert "total_input=8" in s
    assert "uncached=1" in s
    assert "cache_read=3" in s
    assert "cache_write=4" in s
    assert "output=2" in s


def test_snapshot_derives_the_whole_prompt_so_a_cache_hit_is_not_read_as_a_saving():
    meter = UsageMeter()
    meter.add(CompletionResult(text="x", usage=Usage(input_tokens=10, cache_read_tokens=90, output_tokens=2)))
    snap = meter.snapshot()
    assert snap["model_requests"] == 1
    assert snap["uncached_input_tokens"] == 10
    assert snap["cache_read_tokens"] == 90
    assert snap["total_input_tokens"] == 100


def test_snapshot_is_a_copy_so_a_later_call_cannot_mutate_a_recorded_delta():
    meter = UsageMeter()
    meter.add(CompletionResult(text="x", usage=Usage(input_tokens=5)))
    before = meter.snapshot()
    meter.add(CompletionResult(text="y", usage=Usage(input_tokens=7)))
    assert before["uncached_input_tokens"] == 5


def test_meter_documents_one_run_after_a_call_boundary():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage(input_tokens=7, cache_read_tokens=5, output_tokens=3)), meter)
    with model_call_context(role="finder", trigger="provider_request"):
        _call(provider)
        record_model_parse()
    boundary = len(meter.call_snapshot())
    with model_call_context(role="finder", trigger="provider_request"):
        _call(provider)
        record_model_parse()

    complete = validate_model_calls_document(meter.document())
    second = validate_model_calls_document(meter.document_from(boundary))

    assert complete["usage"]["model_requests"] == 2
    assert second["usage"]["model_requests"] == 1
    assert second["usage"]["total_input_tokens"] == 12
    assert [call["sequence"] for call in second["calls"]] == [1]


def test_meter_records_role_unit_prompt_size_usage_duration_and_status():
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
    meter = UsageMeter()
    with model_call_context(role="finder", trigger="initial_judgment"):
        _call(MeteringProvider(_Fake(Usage()), meter))
        record_model_parse("invalid response")

    call = meter.document()["calls"][0]
    assert (call["status"], call["failure_reason"]) == ("failed", "invalid response")


def test_scheduler_scope_supplies_unit_to_nested_model_calls():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    with model_call_scope(unit_id="unit-a"), model_call_context(role="finder", trigger="initial_judgment"):
        _call(provider)
        record_model_parse()

    record = meter.call_snapshot()[0]
    assert record["unit_id"] == "unit-a"
    assert record["trigger"] == "initial_judgment"


def test_verification_model_call_binds_the_candidate_instead_of_a_scheduler_unit():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    with model_call_context(role="skeptic", trigger="verification", candidate_id="candidate-a"):
        _call(provider)
        record_model_parse()

    record = meter.call_snapshot()[0]
    assert record["candidate_id"] == "candidate-a"
    assert record["unit_id"] == ""


def test_model_calls_document_binds_ordered_calls_and_usage():
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
