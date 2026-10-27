"""OpenAIProvider tests cover the Responses API with a faked client."""

import sys
from types import SimpleNamespace

import pytest

from cyberjury.providers.base import Message, ResponseSchema, Usage
from cyberjury.providers.openai import OpenAIProvider, _responses_usage

_SCHEMA = ResponseSchema(
    name="review_reply",
    schema={
        "type": "object",
        "additionalProperties": False,
        "properties": {"findings": {"type": "array", "items": {"type": "string"}}},
        "required": ["findings"],
    },
)


class _FakeResponsesClient:
    def __init__(self, output_text="{}", status="completed", error=None):
        self.kwargs = {}
        self._out = output_text
        self._status = status
        self._error = error
        self.responses = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.kwargs = kwargs
        if self._error is not None:
            raise self._error
        return SimpleNamespace(output_text=self._out, status=self._status)


def _complete(client, content="c", *, system="s", **kw):
    return OpenAIProvider(client=client).complete(
        system=system,
        messages=[Message(role="user", content=content)],
        model="m",
        max_tokens=8,
        response_schema=_SCHEMA,
        **kw,
    )


def _sent(content: str, **kw) -> dict:
    client = _FakeResponsesClient()
    _complete(client, content, **kw)
    return client.kwargs


def test_sdk_exception_propagates():
    """A RuntimeError('rate limited') raised by responses.create reaches the caller unchanged."""
    with pytest.raises(RuntimeError, match="rate limited"):
        _complete(_FakeResponsesClient(error=RuntimeError("rate limited")))


def test_sdk_retries_are_disabled_when_the_outer_provider_owns_retry(monkeypatch):
    """A client built with a gateway api_base gets max_retries=0 and the gateway base_url."""
    captured = {}

    class _OpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_OpenAI))

    OpenAIProvider(api_base="https://gateway.example.test")._get_client()

    assert captured == {"max_retries": 0, "base_url": "https://gateway.example.test"}


def test_responses_usage_reads_the_cached_tokens_detail():
    """Of 2700 input tokens with 2600 cached, 100 count as input and 2600 as cache reads."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=2700, output_tokens=40, input_tokens_details=SimpleNamespace(cached_tokens=2600)
        )
    )
    assert _responses_usage(response) == Usage(input_tokens=100, output_tokens=40, cache_read_tokens=2600)


def test_responses_usage_separates_cache_writes_from_uncached_input():
    """Of 2700 input tokens, 500 cached reads and 2000 cache writes leave 200 uncached input."""
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=2700,
            output_tokens=40,
            input_tokens_details=SimpleNamespace(cached_tokens=500, cache_write_tokens=2000),
        )
    )
    assert _responses_usage(response) == Usage(
        input_tokens=200,
        output_tokens=40,
        cache_read_tokens=500,
        cache_write_tokens=2000,
    )


def test_usage_defaults_to_zero_when_unreported():
    """A response object with no usage attribute yields an all-zero Usage."""
    assert _responses_usage(SimpleNamespace(model="m")) == Usage()


def test_a_cached_prefix_becomes_a_stable_routing_key():
    """The system prompt plus the cached message prefix becomes one routing key."""
    key = _sent("STABLE tail", cache_prefix="STABLE")["prompt_cache_key"]
    assert key
    assert _sent("STABLE a different tail", cache_prefix="STABLE")["prompt_cache_key"] == key
    assert _sent("OTHER tail", cache_prefix="OTHER")["prompt_cache_key"] != key


def test_the_routing_key_covers_the_system_prompt():
    """Identical cache prefixes under different system prompts produce different prompt_cache_key values."""
    client = _FakeResponsesClient()
    _complete(client, "STABLE", system="other", cache_prefix="STABLE")
    assert client.kwargs["prompt_cache_key"] != _sent("STABLE", cache_prefix="STABLE")["prompt_cache_key"]


def test_a_repeated_system_prompt_alone_gets_a_routing_key():
    """Without a cache_prefix, messages x and y share one key from the system prompt."""
    assert _sent("x")["prompt_cache_key"] == _sent("y")["prompt_cache_key"]


def test_caching_uses_only_portable_routing_fields():
    """A cached request keeps the whole message as input content and sends no prompt_cache_options field."""
    request = _sent("STABLE changing judgment", cache_prefix="STABLE")

    assert request["input"][-1]["content"] == "STABLE changing judgment"
    assert "prompt_cache_options" not in request


def test_responses_maps_system_to_instructions_and_returns_output_text():
    """System goes to instructions, messages to input, output_text is returned, and no temperature is sent."""
    client = _FakeResponsesClient(output_text='{"holds": true}')
    result = _complete(client, "audit this", system="review carefully")
    assert result.text == '{"holds": true}'
    assert client.kwargs["instructions"] == "review carefully"
    assert client.kwargs["input"] == [{"role": "user", "content": "audit this"}]
    assert client.kwargs["max_output_tokens"] >= 8000
    assert "temperature" not in client.kwargs


def test_responses_maps_the_strict_output_schema():
    """A ResponseSchema becomes text.format of type json_schema with strict=True and its name."""
    assert _sent("source")["text"] == {
        "format": {
            "type": "json_schema",
            "name": "review_reply",
            "strict": True,
            "schema": _SCHEMA.schema,
        }
    }


def test_responses_preserves_message_role_boundaries():
    """User and assistant messages stay as two separate input entries with their original roles."""
    client = _FakeResponsesClient(output_text="ok")
    OpenAIProvider(client=client).complete(
        system="s",
        messages=[Message(role="user", content="first"), Message(role="assistant", content="second")],
        model="gpt-5.6",
        max_tokens=1024,
        response_schema=_SCHEMA,
    )
    assert client.kwargs["input"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "second"},
    ]


def test_responses_empty_output_comes_back_as_an_empty_string_not_an_error():
    """A completed response with output_text '' returns text '' without raising."""
    assert _complete(_FakeResponsesClient(output_text="")).text == ""


def test_an_incomplete_response_raises_instead_of_returning_partial_output():
    """A truncated JSON body with status incomplete raises 'response did not complete: incomplete'."""
    with pytest.raises(RuntimeError, match="response did not complete: incomplete"):
        _complete(_FakeResponsesClient(output_text='{"findings": [', status="incomplete"))
