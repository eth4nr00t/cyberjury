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
    """The names openai and anthropic build OpenAIProvider and AnthropicProvider instances."""
    assert isinstance(make_provider("openai"), OpenAIProvider)
    assert isinstance(make_provider("anthropic"), AnthropicProvider)


def test_default_model_is_provider_specific():
    """Each provider has its own default model."""
    assert default_model_for_provider("openai") == "gpt-5.6"
    assert default_model_for_provider("anthropic") == "claude-opus-5"


def test_unknown_name_fails_loud():
    """An unrecognized provider name such as something-else raises ValueError naming an unknown provider."""
    with pytest.raises(ValueError, match="unknown provider"):
        make_provider("something-else")


def test_no_retries_leaves_the_provider_unwrapped():
    """With retries=0 the factory returns the bare OpenAIProvider without a retry wrapper."""
    provider = make_provider("openai", retries=0)
    assert isinstance(provider, OpenAIProvider)


class _RateLimited(Exception):
    retry_after = 0


class _ScriptedOpenAI:
    calls: ClassVar[list[str]] = []
    failures: ClassVar[int] = 0

    def __init__(self, **_kwargs):
        self.responses = SimpleNamespace(create=self._reply)

    def _reply(self, **request):
        type(self).calls.append(request["model"])
        if len(type(self).calls) <= type(self).failures:
            raise _RateLimited("rate limited")
        return SimpleNamespace(output_text="answered", status="completed")


@pytest.fixture
def scripted_openai(monkeypatch):
    """Install the scripted OpenAI SDK stand-in with no recorded calls or failures."""
    _ScriptedOpenAI.calls = []
    _ScriptedOpenAI.failures = 0
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_ScriptedOpenAI))
    return _ScriptedOpenAI


def _complete(provider):
    return provider.complete(system="s", messages=[Message(role="user", content="c")], model="m", max_tokens=8)


def test_retries_allow_one_extra_attempt_per_retry(scripted_openai):
    """Two rate-limit failures with retries=2 succeed on the third call and report three attempts."""
    scripted_openai.failures = 2

    result = _complete(make_provider("openai", retries=2))

    assert result.text == "answered"
    assert result.attempts == 3
    assert len(scripted_openai.calls) == 3


def test_retries_give_up_after_the_last_extra_attempt(scripted_openai):
    """Three rate-limit failures with retries=2 re-raise the error after exactly three calls."""
    scripted_openai.failures = 3

    with pytest.raises(_RateLimited):
        _complete(make_provider("openai", retries=2))

    assert len(scripted_openai.calls) == 3
