"""OpenAIProvider with a faked SDK client, no key. Covers both wires: Chat Completions and
the Responses API path the GPT-5 reasoning models use."""

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
    client = _FakeClient()
    OpenAIProvider(client=client).complete(
        system="", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert client.create_kwargs["messages"] == [{"role": "user", "content": "x"}]


def test_sdk_exception_propagates():
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
    response = SimpleNamespace(
        usage=SimpleNamespace(
            prompt_tokens=2700, completion_tokens=40, prompt_tokens_details=SimpleNamespace(cached_tokens=2600)
        )
    )
    assert _chat_usage(response) == Usage(input_tokens=100, output_tokens=40, cache_read_tokens=2600)


def test_responses_usage_reads_the_cached_tokens_detail():
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=2700, output_tokens=40, input_tokens_details=SimpleNamespace(cached_tokens=2600)
        )
    )
    assert _responses_usage(response) == Usage(input_tokens=100, output_tokens=40, cache_read_tokens=2600)


def test_usage_defaults_to_zero_when_unreported():
    assert _chat_usage(SimpleNamespace(model="m")) == Usage()
    assert _responses_usage(SimpleNamespace(model="m")) == Usage()


def test_empty_content_yields_empty_text():
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
    # the budget covers reasoning plus output, so a small request still leaves room to answer
    assert client.kwargs["max_output_tokens"] >= 8000
    # a reasoning model rejects a fixed temperature, so the responses path must not send one
    assert "temperature" not in client.kwargs


def test_responses_empty_output_comes_back_as_an_empty_string_not_an_error():
    # too small a budget yields empty output, which must return "" so the retry and JSON layers
    # read it as an unusable reply, rather than raising here on a missing output_text
    result = OpenAIProvider(client=_FakeResponsesClient(output_text=""), wire_api="responses").complete(
        system="s",
        messages=[Message(role="user", content="c")],
        model="gpt-5.5",
        max_tokens=1024,
    )
    assert result.text == ""
