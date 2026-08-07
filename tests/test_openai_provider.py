"""OpenAIProvider with a faked SDK client, no key.

Covers both wires: Chat Completions and the Responses API path the GPT-5 reasoning
models use.
"""

import sys
from types import SimpleNamespace

import pytest

from cyberjury.providers.base import Message, Usage
from cyberjury.providers.openai import OpenAIProvider, _chat_usage, _responses_usage


class _FakeClient:
    def __init__(self, reply="ok", model="gpt-4o"):
        self.create_kwargs = {}
        self._reply = reply
        self._model = model
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self._reply))], model=self._model
        )


def test_prepends_system_and_maps_messages():
    """Prepends system and maps messages."""
    client = _FakeClient(reply="hello", model="gpt-4o-mini")
    result = OpenAIProvider(client=client).complete(
        system="be careful",
        messages=[Message(role="user", content="hi")],
        model="gpt-4o",
        max_tokens=64,
    )
    assert result.text == "hello"
    assert client.create_kwargs["messages"] == [
        {"role": "system", "content": "be careful"},
        {"role": "user", "content": "hi"},
    ]
    assert client.create_kwargs["max_tokens"] == 64
    assert client.create_kwargs["temperature"] == 0


def test_omits_system_message_when_empty():
    """Omits system message when empty."""
    client = _FakeClient()
    OpenAIProvider(client=client).complete(
        system="", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "x"}]


def test_sdk_exception_propagates():
    """SDK exception propagates."""

    class _Boom:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        def _create(self, **kwargs):
            raise RuntimeError("rate limited")

    with pytest.raises(RuntimeError, match="rate limited"):
        OpenAIProvider(client=_Boom()).complete(
            system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
        )


def test_chat_usage_subtracts_the_cached_read_from_the_prompt_total():
    """Chat usage subtracts the cached read from the prompt total."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=2700, completion_tokens=40, prompt_tokens_details=SimpleNamespace(cached_tokens=2600)
        )
    )
    assert _chat_usage(response) == Usage(input_tokens=100, output_tokens=40, cache_read_tokens=2600)


def test_responses_usage_reads_the_cached_tokens_detail():
    """Responses usage reads the cached tokens detail."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=2700, output_tokens=40, input_tokens_details=SimpleNamespace(cached_tokens=2600)
        )
    )
    assert _responses_usage(response) == Usage(input_tokens=100, output_tokens=40, cache_read_tokens=2600)


def test_usage_defaults_to_zero_when_unreported():
    """Usage defaults to zero when unreported."""
    assert _chat_usage(SimpleNamespace(model="m")) == Usage()
    assert _responses_usage(SimpleNamespace(model="m")) == Usage()


def _sent(content: str, *, wire: str = "chat", **kw) -> dict:
    client = _FakeResponsesClient() if wire == "responses" else _FakeClient()
    OpenAIProvider(client=client, wire_api=wire).complete(
        system="s", messages=[Message(role="user", content=content)], model="m", max_tokens=8, **kw
    )
    return client.kwargs if wire == "responses" else client.create_kwargs


def test_a_cached_prefix_becomes_a_stable_routing_key_on_both_wires():
    """Cached prefix becomes a stable routing key on both wires."""
    key = _sent("STABLE tail", cache=True, cache_prefix="STABLE")["prompt_cache_key"]
    assert key
    assert _sent("STABLE a different tail", cache=True, cache_prefix="STABLE")["prompt_cache_key"] == key
    assert _sent("STABLE tail", wire="responses", cache=True, cache_prefix="STABLE")["prompt_cache_key"] == key
    assert _sent("OTHER tail", cache=True, cache_prefix="OTHER")["prompt_cache_key"] != key


def test_no_routing_key_without_cache_or_a_prefix():
    """No routing key without cache or a prefix."""
    assert "prompt_cache_key" not in _sent("x", cache_prefix="STABLE")
    assert "prompt_cache_key" not in _sent("x", cache=True)


def test_empty_content_yields_empty_text():
    """Empty content yields empty text."""

    class _Blank:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        def _create(self, **kwargs):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None))])

    result = OpenAIProvider(client=_Blank()).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert result.text == ""


def test_missing_sdk_raises_a_clear_error(monkeypatch):
    """Missing SDK raises a clear error."""
    monkeypatch.setitem(sys.modules, "openai", None)
    with pytest.raises(RuntimeError, match="pip install"):
        OpenAIProvider().complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)


class _FakeResponsesClient:
    def __init__(self, output_text="{}"):
        self.kwargs = {}
        self._out = output_text
        self.responses = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(output_text=self._out)


def test_responses_wire_api_maps_system_to_instructions_and_returns_output_text():
    """Responses wire API maps system to instructions and returns output text."""
    client = _FakeResponsesClient(output_text='{"holds": true}')
    result = OpenAIProvider(client=client, wire_api="responses").complete(
        system="be skeptical",
        messages=[Message(role="user", content="audit this")],
        model="gpt-5.5",
        max_tokens=1024,
    )
    assert result.text == '{"holds": true}'
    assert client.kwargs["instructions"] == "be skeptical"
    assert client.kwargs["input"] == "audit this"
    assert client.kwargs["max_output_tokens"] >= 8000
    assert "temperature" not in client.kwargs


def test_responses_empty_output_comes_back_as_an_empty_string_not_an_error():
    """Responses empty output comes back as an empty string not an error."""
    result = OpenAIProvider(client=_FakeResponsesClient(output_text=""), wire_api="responses").complete(
        system="s",
        messages=[Message(role="user", content="c")],
        model="gpt-5.5",
        max_tokens=1024,
    )
    assert result.text == ""
