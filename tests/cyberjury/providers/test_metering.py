"""Metering tests cover usage aggregation, snapshots, and provider delegation."""

import hashlib
import json

import pytest

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
        self.closed = False

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


def test_close_delegates_to_the_inner_provider():
    inner = _Fake(Usage())
    MeteringProvider(inner, UsageMeter()).close()
    assert inner.closed is True


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


def test_meter_records_role_revision_prompt_usage_duration_and_parse_source():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage(input_tokens=3, output_tokens=2)), meter)

    with model_call_context(
        role="finder",
        unit_id="unit-a",
        evidence_revision="revision-a",
        review_brief_sha256="a" * 64,
        decision_rule_ids=("authorization",),
        round=2,
    ):
        provider.complete(
            system="system",
            messages=[Message(role="user", content="prompt")],
            model="model-a",
            max_tokens=100,
        )
        record_model_parse("direct")

    record = meter.call_snapshot()[0]
    assert record["call_id"].startswith("call-")
    assert record["role"] == "finder"
    assert record["trigger"] == "provider_request"
    assert record["unit_id"] == "unit-a"
    assert record["evidence_revision"] == "revision-a"
    assert record["review_brief_sha256"] == "a" * 64
    assert record["decision_rule_ids"] == ["authorization"]
    assert record["round"] == 2
    assert record["model"] == "model-a"
    assert record["prompt_chars"] == len("systemprompt")
    assert len(record["prompt_sha256"]) == 64
    assert record["input_tokens"] == 3
    assert record["output_tokens"] == 2
    assert record["duration_seconds"] >= 0
    assert record["parse_source"] == "direct"
    assert record["status"] == "ok"


def test_scheduler_scope_supplies_unit_and_round_to_nested_model_calls():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    with model_call_scope(unit_id="unit-a", round=3), model_call_context(role="finder", trigger="initial_judgment"):
        _call(provider)
        record_model_parse("direct")

    record = meter.call_snapshot()[0]
    assert record["unit_id"] == "unit-a"
    assert record["round"] == 3
    assert record["trigger"] == "initial_judgment"


def test_model_call_id_is_stable_when_completion_sequence_changes():
    first = UsageMeter()
    second = UsageMeter()

    with model_call_context(role="finder", trigger="initial_judgment", unit_id="unit-a", round=1):
        _call(MeteringProvider(_Fake(Usage()), first))
    with model_call_context(role="finder", trigger="initial_judgment", unit_id="unit-a", round=1):
        _call(MeteringProvider(_Fake(Usage()), second))

    assert first.call_snapshot()[0]["call_id"] == second.call_snapshot()[0]["call_id"]


def test_meter_prompt_hash_identifies_exact_model_visible_input():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(Usage()), meter)

    _call(provider)
    _call(provider)
    provider.complete(
        system="s",
        messages=[Message(role="user", content="different")],
        model="m",
        max_tokens=8,
    )

    records = meter.call_snapshot()
    assert records[0]["prompt_sha256"] == records[1]["prompt_sha256"]
    assert records[0]["prompt_sha256"] != records[2]["prompt_sha256"]


def test_model_calls_document_binds_ordered_calls_and_usage():
    meter = UsageMeter()
    _call(MeteringProvider(_Fake(Usage(input_tokens=3, output_tokens=2)), meter))

    document = meter.document()

    assert validate_model_calls_document(document) == document
    assert document["schema"] == "cyberjury.model-calls/v2"
    assert document["calls"][0]["sequence"] == 1
    assert document["usage"]["model_requests"] == 1
    changed = {**document, "content_sha256": "0" * 64}
    with pytest.raises(ValueError, match="hash"):
        validate_model_calls_document(changed)

    changed = json.loads(json.dumps(document))
    changed["calls"][0]["trigger"] = "typo"
    with pytest.raises(ValueError, match="trigger"):
        validate_model_calls_document(changed)


def test_model_calls_validator_accepts_the_persisted_v1_shape():
    meter = UsageMeter()
    _call(MeteringProvider(_Fake(Usage()), meter))
    legacy = json.loads(json.dumps(meter.document()))
    legacy["schema"] = "cyberjury.model-calls/v1"
    for call in legacy["calls"]:
        call.pop("call_id")
        call.pop("trigger")
    semantic = {"calls": legacy["calls"], "usage": legacy["usage"]}
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    legacy["content_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()

    assert validate_model_calls_document(legacy) == legacy
