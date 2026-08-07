"""LiteLLMProvider with an injected completion callable, no network.

Covers text extraction across the response shapes litellm returns.
"""

import sys
from types import SimpleNamespace

import pytest

from cyberjury.providers.base import Message
from cyberjury.providers.litellm import LiteLLMProvider


def _fake(reply="ok", model="gpt-x"):
    captured = {}

    def completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=reply))], model=model)

    return completion, captured


def test_prepends_system_and_maps_messages():
    """Exercise the prepends system and maps messages case."""
    completion, captured = _fake()
    provider = LiteLLMProvider(completion=completion)
    result = provider.complete(
        system="sys",
        messages=[Message(role="user", content="hi"), Message(role="assistant", content="prev")],
        model="gpt-4o",
        max_tokens=128,
    )
    assert result.text == "ok"
    assert captured["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "prev"},
    ]
    assert captured["max_tokens"] == 128
    assert captured["temperature"] == 0.0


def test_omits_system_message_when_empty():
    """Exercise the omits system message when empty case."""
    completion, captured = _fake()
    LiteLLMProvider(completion=completion).complete(
        system="", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert captured["messages"] == [{"role": "user", "content": "x"}]


def test_passes_api_key_and_base_only_when_set():
    """Exercise the passes api key and base only when set case."""
    completion, captured = _fake()
    LiteLLMProvider(completion=completion, api_key="k", api_base="http://proxy").complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert captured["api_key"] == "k"
    assert captured["api_base"] == "http://proxy"

    completion2, captured2 = _fake()
    LiteLLMProvider(completion=completion2).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert "api_key" not in captured2
    assert "api_base" not in captured2


def test_extracts_text_from_content_block_list():
    """Exercise the extracts text from content block list case."""

    def completion(**kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message={"content": [{"text": "a"}, {"text": "b"}]})], model="m"
        )

    result = LiteLLMProvider(completion=completion).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert result.text == "ab"


def test_sdk_exception_propagates():
    """Exercise the sdk exception propagates case."""

    def completion(**kwargs):
        raise RuntimeError("upstream timeout")

    with pytest.raises(RuntimeError, match="upstream timeout"):
        LiteLLMProvider(completion=completion).complete(
            system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
        )


def test_empty_content_yields_empty_text():
    """Exercise the empty content yields empty text case."""

    def completion(**kwargs):
        return SimpleNamespace(choices=[])

    result = LiteLLMProvider(completion=completion).complete(
        system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8
    )
    assert result.text == ""


def test_missing_sdk_raises_a_clear_error(monkeypatch):
    """Exercise the missing sdk raises a clear error case."""
    monkeypatch.setitem(sys.modules, "litellm", None)
    with pytest.raises(RuntimeError, match="pip install"):
        LiteLLMProvider().complete(system="s", messages=[Message(role="user", content="x")], model="m", max_tokens=8)
