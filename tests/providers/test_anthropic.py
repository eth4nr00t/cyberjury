"""AnthropicProvider tests use a faked SDK client and no key."""

import sys
from types import SimpleNamespace

import pytest

from cyberjury.providers.anthropic import AnthropicProvider, _usage
from cyberjury.providers.base import ResponseSchema, Usage

_SCHEMA = ResponseSchema(
    name="review_reply",
    schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"findings": {"type": "array", "items": {"type": "string"}}},
        "required": ["findings"],
    },
)


class _FakeClient:
    def __init__(self, stop_reason: str = "end_turn"):
        self.create_kwargs = {}
        self.stop_reason = stop_reason
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(text="he"), SimpleNamespace(text="llo")],
            stop_reason=self.stop_reason,
        )


def _sent(content: str, **values) -> dict:
    client = _FakeClient()
    AnthropicProvider(client=client).complete(
        system="sys",
        prompt=content,
        model="m",
        max_tokens=64,
        response_schema=_SCHEMA,
        **values,
    )
    return client.create_kwargs


def test_maps_the_request_and_joins_text_blocks():
    """Text blocks he and llo join to hello, and the SDK gets messages, max_tokens 64, and no temperature."""
    client = _FakeClient()
    result = AnthropicProvider(client=client).complete(
        system="sys", prompt="hi", model="m", max_tokens=64, response_schema=_SCHEMA
    )

    assert result.text == "hello"
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "hi"}]
    assert client.create_kwargs["max_tokens"] == 64
    assert "temperature" not in client.create_kwargs


def test_caches_the_system_and_sends_the_strict_output_schema():
    """The system prompt is one cached text block, and the schema goes out unchanged as output_config."""
    request = _sent("x")

    assert request["system"] == [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]
    assert request["output_config"] == {"format": {"type": "json_schema", "schema": _SCHEMA.schema}}


def test_cache_prefix_splits_the_stable_message_prefix_into_a_cached_block():
    """A STABLE prefix splits STABLEvariable into a cached STABLE block and a plain variable block."""
    assert _sent("STABLEvariable", cache_prefix="STABLE")["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "variable"},
    ]


def test_cache_segments_become_blocks_with_a_breakpoint_on_the_last_one():
    """Segments ONE and TWO after the STABLE prefix are separate blocks, and TWO carries the third breakpoint."""
    assert _sent("STABLEONETWOtail", cache_prefix="STABLE", cache_segments=("ONE", "TWO"))["messages"][0][
        "content"
    ] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "ONE"},
        {"type": "text", "text": "TWO", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "tail"},
    ]


def test_cache_prefix_equal_to_the_message_marks_a_single_block():
    """A message equal to the STABLE prefix is sent as one cached text block with no empty remainder."""
    assert _sent("STABLE", cache_prefix="STABLE")["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
    ]


def test_usage_maps_cache_read_and_write_separately():
    """Usage cache_creation_input_tokens 2600 maps to cache_write_tokens, and cache_read_input_tokens 700 to reads."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=30, output_tokens=12, cache_creation_input_tokens=2600, cache_read_input_tokens=700
        )
    )
    assert _usage(response) == Usage(input_tokens=30, output_tokens=12, cache_write_tokens=2600, cache_read_tokens=700)


def test_unreported_usage_is_zero():
    """A response without a usage attribute yields an all-zero Usage."""
    assert _usage(SimpleNamespace(model="m")) == Usage()


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
def test_a_refused_or_truncated_reply_raises_instead_of_returning_partial_output(stop_reason):
    """A refusal or max_tokens stop raises 'response did not complete' with the stop reason."""
    with pytest.raises(RuntimeError, match=f"response did not complete: {stop_reason}"):
        AnthropicProvider(client=_FakeClient(stop_reason)).complete(
            system="s", prompt="x", model="m", max_tokens=64, response_schema=_SCHEMA
        )


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [({"base_url": "https://gateway.example.test"}, "https://gateway.example.test"), ({}, "https://api.anthropic.com")],
)
def test_the_client_gets_the_key_and_the_configured_or_official_endpoint(monkeypatch, endpoint, expected):
    """The SDK gets the key, the gateway or else the official Anthropic API, and max_retries=0."""
    captured = {}

    class _Anthropic:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=_Anthropic))

    AnthropicProvider(api_key="k", **endpoint)._get_client()

    assert captured == {"api_key": "k", "base_url": expected, "max_retries": 0}
