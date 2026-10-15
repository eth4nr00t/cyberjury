"""Model-call stage summaries retain provider receipts and token accounting."""

import json

import pytest

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.metering import MeteringProvider, UsageMeter, model_call_context, record_model_parse
from evals.backtest.calls import compare_model_call_summaries, load_model_call_summary, summarize_model_calls


class _Fake(Provider):
    def complete(self, *, system, messages, model, max_tokens, cache=False, cache_prefix="", response_schema=None):
        return CompletionResult(text="{}", usage=Usage(input_tokens=7, cache_read_tokens=5, output_tokens=3))


def _call_document(*, include_verification: bool) -> dict:
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(), meter)
    with model_call_context(role="finder", trigger="initial_judgment", unit_id="unit-one") as context:
        provider.complete(
            system="system", messages=[Message(role="user", content="source")], model="test", max_tokens=100
        )
        record_model_parse("direct")
        context.navigation("not_requested")
    if include_verification:
        with model_call_context(role="verifier", trigger="verification", candidate_id="candidate-one"):
            provider.complete(
                system="system", messages=[Message(role="user", content="candidate")], model="test", max_tokens=100
            )
            record_model_parse("direct")
    return meter.document()


def test_model_call_summary_groups_roles_and_reconciles_tokens(tmp_path):
    artifact = _call_document(include_verification=True)
    path = tmp_path / "model-calls.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")

    result = load_model_call_summary(path)

    assert result["source_sha256"] == artifact["content_sha256"]
    assert result["models"] == ["test"]
    assert result["usage"]["model_requests"] == 2
    assert [(stage["trigger"], stage["role"]) for stage in result["stages"]] == [
        ("initial_judgment", "finder"),
        ("verification", "verifier"),
    ]
    for stage in result["stages"]:
        assert stage["requests"] == stage["metered_requests"] == 1
        assert stage["max_prompt_chars"] == stage["prompt_chars"]
        assert stage["total_input_tokens"] == 12
        assert stage["output_tokens"] == 3


def test_model_call_comparison_counts_an_added_stage():
    before = summarize_model_calls(_call_document(include_verification=False))
    after = summarize_model_calls(_call_document(include_verification=True))

    changed = compare_model_call_summaries(before, after)

    assert changed["stages"][0]["delta_requests"] == 0
    assert changed["stages"][1]["delta_requests"] == 1
    assert changed["stages"][1]["before_max_prompt_chars"] == 0
    assert changed["stages"][1]["after_max_prompt_chars"] > 0
    assert changed["stages"][1]["delta_input_tokens"] == 12
    assert changed["stages"][1]["delta_output_tokens"] == 3
    assert changed["stages"][1]["delta_cache_read_tokens"] == 5
    assert changed["comparable_models"] is True


def test_model_call_summary_rejects_tampered_usage():
    artifact = _call_document(include_verification=False)
    artifact["usage"]["model_requests"] += 1

    with pytest.raises(ValueError, match="usage does not equal"):
        summarize_model_calls(artifact)


def test_model_call_summary_keeps_peak_separate_from_total():
    meter = UsageMeter()
    provider = MeteringProvider(_Fake(), meter)
    for source in ("short", "longer source"):
        with model_call_context(role="finder", trigger="initial_judgment", unit_id="unit-one") as context:
            provider.complete(
                system="system", messages=[Message(role="user", content=source)], model="test", max_tokens=100
            )
            record_model_parse("direct")
            context.navigation("not_requested")

    stage = summarize_model_calls(meter.document())["stages"][0]

    assert stage["requests"] == 2
    assert stage["max_prompt_chars"] == len("system") + len("longer source")
    assert stage["prompt_chars"] == 2 * len("system") + len("short") + len("longer source")
