"""AnthropicProvider with a faked SDK client, no key. Covers text extraction and the retry
that drops temperature when the model rejects a fixed one."""

from types import SimpleNamespace

import pytest

from cyberjury.providers.anthropic import AnthropicProvider, _extract_usage
from cyberjury.providers.base import Message, Usage


class _FakeClient:
    """Records the kwargs passed to messages.create and returns a canned reply."""

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
    provider, client = _provider()
    provider.complete(system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8)
    assert client.create_kwargs["system"] == "sys"


def test_cache_marks_system_with_ephemeral_cache_control():
    provider, client = _provider()
    provider.complete(system="sys", messages=[Message(role="user", content="x")], model="m", max_tokens=8, cache=True)
    assert client.create_kwargs["system"] == [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}]


def test_cache_prefix_splits_the_first_user_message_and_marks_the_prefix():
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
    assert client.create_kwargs["system"] == "sys"


def test_cache_prefix_equal_to_the_message_marks_a_single_block():
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


def test_cache_prefix_that_does_not_lead_the_message_falls_back_to_system():
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
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=30, output_tokens=12, cache_creation_input_tokens=2600, cache_read_input_tokens=0
        )
    )
    assert _extract_usage(response) == Usage(
        input_tokens=30, output_tokens=12, cache_write_tokens=2600, cache_read_tokens=0
    )


def test_extract_usage_defaults_to_zero_when_unreported():
    assert _extract_usage(SimpleNamespace(model="m")) == Usage()


class _BadRequest(Exception):
    status_code = 400


class _RecordingClient:
    """Records every messages.create call. Raises a temperature error on the calls that
    send temperature when ``reject_temperature`` is set, to model a reasoning backend."""

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
    client = _RecordingClient(reject_temperature=True)
    provider = AnthropicProvider(client=client)
    assert _run(provider).text == "ok"
    assert "temperature" in client.calls[0]
    assert "temperature" not in client.calls[1]
    _run(provider)
    assert len(client.calls) == 3
    assert "temperature" not in client.calls[2]


def test_non_temperature_bad_request_still_fails_loud():
    class _OtherBadRequest(_RecordingClient):
        def _create(self, **kwargs):
            self.calls.append(kwargs)
            raise _BadRequest("Error code: 400 - max_tokens exceeds the model limit.")

    client = _OtherBadRequest(reject_temperature=False)
    provider = AnthropicProvider(client=client)
    with pytest.raises(_BadRequest):
        _run(provider)
    assert len(client.calls) == 1
