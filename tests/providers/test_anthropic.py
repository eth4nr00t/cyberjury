"""AnthropicProvider tests use a faked SDK client and no key."""

import sys
from types import SimpleNamespace

import pytest

from cyberjury.providers.anthropic import AnthropicProvider, _extract_usage
from cyberjury.providers.base import Message, ResponseSchema, Usage


class _FakeClient:
    def __init__(self):
        self.create_kwargs = {}
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(text="he"), SimpleNamespace(text="llo")],
            model="claude-real",
        )


def _provider():
    client = _FakeClient()
    return AnthropicProvider(client=client), client


def test_maps_messages_and_joins_text_blocks():
    """Text blocks he and llo join to hello, and the SDK gets role/content dicts, max_tokens 64, temperature 0."""
    provider, client = _provider()
    result = provider.complete(
        system="be careful",
        messages=[Message(role="user", content="hi")],
        model="claude-x",
        max_tokens=64,
    )
    assert result.text == "hello"
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "hi"}]
    assert client.create_kwargs["max_tokens"] == 64
    assert client.create_kwargs["temperature"] == 0


def test_no_cache_keeps_system_as_plain_string():
    """Without cache=True the system prompt is sent as the bare string sys."""
    provider, client = _provider()
    provider.complete(system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8)
    assert client.create_kwargs["system"] == "sys"


def test_maps_the_strict_output_schema():
    """A response schema is sent as output_config format json_schema carrying the schema unchanged."""
    provider, client = _provider()
    schema = ResponseSchema(
        name="review_reply",
        schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {"findings": {"type": "array", "items": {"type": "string"}}},
            "required": ["findings"],
        },
    )

    provider.complete(
        system="sys",
        messages=[Message(role="user", content="source")],
        model="m",
        max_tokens=8,
        response_schema=schema,
    )

    assert client.create_kwargs["output_config"] == {"format": {"type": "json_schema", "schema": schema.schema}}


def test_cache_marks_system_with_ephemeral_cache_control():
    """With cache=True the system prompt becomes one text block with ephemeral cache_control."""
    provider, client = _provider()
    provider.complete(system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8, cache=True)
    assert client.create_kwargs["system"] == [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]


def test_cache_prefix_marks_the_system_and_the_stable_message_prefix():
    """A STABLE prefix splits STABLEvariable into a cached STABLE block and a plain variable block."""
    provider, client = _provider()
    provider.complete(
        system="sys",
        messages=[Message(role="user", content="STABLEvariable")],
        model="m",
        max_tokens=8,
        cache=True,
        cache_prefix="STABLE",
    )
    assert client.create_kwargs["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "variable"},
    ]
    assert client.create_kwargs["system"] == [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]


def test_cache_segments_become_blocks_with_a_breakpoint_on_the_last_one():
    """Segments ONE and TWO after the STABLE prefix are separate blocks, and TWO carries the third breakpoint."""
    provider, client = _provider()
    provider.complete(
        system="sys",
        messages=[Message(role="user", content="STABLEONETWOtail")],
        model="m",
        max_tokens=8,
        cache=True,
        cache_prefix="STABLE",
        cache_segments=("ONE", "TWO"),
    )
    assert client.create_kwargs["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "ONE"},
        {"type": "text", "text": "TWO", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "tail"},
    ]


def test_cache_segments_that_do_not_follow_the_prefix_mark_only_the_prefix():
    """Segments absent from the message leave the STABLE breakpoint and one plain remainder block."""
    provider, client = _provider()
    provider.complete(
        system="sys",
        messages=[Message(role="user", content="STABLEtail")],
        model="m",
        max_tokens=8,
        cache=True,
        cache_prefix="STABLE",
        cache_segments=("ONE",),
    )
    assert client.create_kwargs["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "tail"},
    ]


def test_cache_prefix_equal_to_the_message_marks_a_single_block():
    """A message equal to the STABLE prefix is sent as one cached text block with no empty remainder."""
    provider, client = _provider()
    provider.complete(
        system="sys",
        messages=[Message(role="user", content="STABLE")],
        model="m",
        max_tokens=8,
        cache=True,
        cache_prefix="STABLE",
    )
    assert client.create_kwargs["messages"][0]["content"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}},
    ]


def test_cache_prefix_that_does_not_lead_the_message_marks_only_the_system():
    """A STABLE prefix absent from the message other leaves it a plain string and caches only the system."""
    provider, client = _provider()
    provider.complete(
        system="sys",
        messages=[Message(role="user", content="other")],
        model="m",
        max_tokens=8,
        cache=True,
        cache_prefix="STABLE",
    )
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "other"}]
    assert client.create_kwargs["system"] == [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]


def test_extract_usage_maps_cache_read_and_write_separately():
    """Usage cache_creation_input_tokens 2600 maps to cache_write_tokens, and cache reads map separately."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=30, output_tokens=12, cache_creation_input_tokens=2600, cache_read_input_tokens=0
        )
    )
    assert _extract_usage(response) == Usage(
        input_tokens=30, output_tokens=12, cache_write_tokens=2600, cache_read_tokens=0
    )


def test_extract_usage_defaults_to_zero_when_unreported():
    """A response without a usage attribute yields an all-zero Usage."""
    assert _extract_usage(SimpleNamespace(model="m")) == Usage()


class _BadRequest(Exception):
    status_code = 400


class _RecordingClient:
    def __init__(self, reject_temperature: bool):
        self.reject_temperature = reject_temperature
        self.calls: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.reject_temperature and "temperature" in kwargs:
            raise _BadRequest("Error code: 400 - 'temperature' is deprecated for this model.")
        return SimpleNamespace(content=[SimpleNamespace(text="ok")], model="m")


def _run(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="x")], model="opus", max_tokens=8)


def test_drops_temperature_when_model_rejects_it_then_skips_it():
    """A 400 rejecting temperature is retried without it, and later calls omit temperature from the start."""
    client = _RecordingClient(reject_temperature=True)
    provider = AnthropicProvider(client=client)
    assert _run(provider).text == "ok"
    assert "temperature" in client.calls[0]
    assert "temperature" not in client.calls[1]
    _run(provider)
    assert len(client.calls) == 3
    assert "temperature" not in client.calls[2]


def test_non_temperature_bad_request_still_fails_loud():
    """A 400 about max_tokens propagates after one call instead of triggering the temperature retry."""

    class _OtherBadRequest(_RecordingClient):
        def _create(self, **kwargs):
            self.calls.append(kwargs)
            raise _BadRequest("Error code: 400 - max_tokens exceeds the model limit.")

    client = _OtherBadRequest(reject_temperature=False)
    provider = AnthropicProvider(client=client)
    with pytest.raises(_BadRequest):
        _run(provider)
    assert len(client.calls) == 1


def test_sdk_retries_are_disabled_when_the_outer_provider_owns_retry(monkeypatch):
    """One retry owner keeps configured attempts from multiplying."""
    captured = {}

    class _Anthropic:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(Anthropic=_Anthropic))

    AnthropicProvider(api_key="k", api_base="https://gateway.example.test")._get_client()

    assert captured["max_retries"] == 0
