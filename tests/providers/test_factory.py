"""Provider factory selects lazy backends and applies retry wrapping."""

import sys
from types import SimpleNamespace
from typing import ClassVar

import pytest

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Message
from cyberjury.providers.factory import default_model_for_provider, make_provider
from cyberjury.providers.openai import OpenAIProvider


def test_selects_provider_by_name():
    assert isinstance(make_provider("openai"), OpenAIProvider)
    assert isinstance(make_provider("anthropic"), AnthropicProvider)


def test_default_model_is_provider_specific():
    """Cross vendor role defaults come from the selected provider."""
    assert default_model_for_provider("openai") == "gpt-5.6"
    assert default_model_for_provider("anthropic") == "claude-opus-5"


def test_unknown_name_fails_loud():
    with pytest.raises(ValueError, match="unknown provider"):
        make_provider("something-else")


def test_no_retries_leaves_the_provider_unwrapped():
    provider = make_provider("openai", retries=0)
    assert isinstance(provider, OpenAIProvider)


class _RateLimited(Exception):
    retry_after = 0


class _ScriptedOpenAI:
    """An OpenAI SDK stand-in that records which wire each call used and fails a set number of times."""

    calls: ClassVar[list[str]] = []
    failures: ClassVar[int] = 0

    def __init__(self, **_kwargs):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **_: self._reply("chat")))
        self.responses = SimpleNamespace(create=lambda **_: self._reply("responses"))

    def _reply(self, wire):
        type(self).calls.append(wire)
        if len(type(self).calls) <= type(self).failures:
            raise _RateLimited("rate limited")
        if wire == "chat":
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=wire))])
        return SimpleNamespace(output_text=wire)


@pytest.fixture
def scripted_openai(monkeypatch):
    _ScriptedOpenAI.calls = []
    _ScriptedOpenAI.failures = 0
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_ScriptedOpenAI))
    return _ScriptedOpenAI


def _complete(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="c")], model="m", max_tokens=8)


@pytest.mark.parametrize("wire_api", ["responses", "chat"])
def test_openai_wire_api_reaches_the_built_provider(scripted_openai, wire_api):
    assert _complete(make_provider("openai", wire_api=wire_api)).text == wire_api
    assert scripted_openai.calls == [wire_api]


def test_retries_allow_one_extra_attempt_per_retry(scripted_openai):
    scripted_openai.failures = 2

    result = _complete(make_provider("openai", retries=2))

    assert result.text == "responses"
    assert result.attempts == 3
    assert len(scripted_openai.calls) == 3


def test_retries_give_up_after_the_last_extra_attempt(scripted_openai):
    scripted_openai.failures = 3

    with pytest.raises(_RateLimited):
        _complete(make_provider("openai", retries=2))

    assert len(scripted_openai.calls) == 3


def test_openai_provider_rejects_an_unknown_wire_api():
    with pytest.raises(ValueError, match="wire API must be one of responses, chat"):
        make_provider("openai", wire_api="completions")
