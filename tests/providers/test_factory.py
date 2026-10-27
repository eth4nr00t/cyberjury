"""Provider factory selects lazy backends and applies retry wrapping."""

import sys
from types import SimpleNamespace
from typing import ClassVar

import pytest

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Message
from cyberjury.providers.factory import default_model_for_provider, make_provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider
from tests.support import EMPTY_SCHEMA


def _make(name: str, *, retries: int = 2):
    return make_provider(name, api_base=None, retries=retries, timeout=10.0)


def test_selects_provider_by_name_behind_a_retry_wrapper():
    """The names openai and anthropic build OpenAIProvider and AnthropicProvider inside a RetryProvider."""
    for name, backend in (("openai", OpenAIProvider), ("anthropic", AnthropicProvider)):
        provider = _make(name)
        assert isinstance(provider, RetryProvider)
        assert isinstance(provider._inner, backend)


def test_default_model_is_provider_specific():
    """Each provider has its own default model."""
    assert default_model_for_provider("openai") == "gpt-5.6"
    assert default_model_for_provider("anthropic") == "claude-opus-5"


def test_unknown_name_fails_loud():
    """An unrecognized provider name such as something-else raises ValueError naming an unknown provider."""
    with pytest.raises(ValueError, match="unknown provider"):
        _make("something-else")


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
        return SimpleNamespace(output_text="{}", status="completed")


@pytest.fixture
def scripted_openai(monkeypatch):
    """Install the scripted OpenAI SDK stand-in with no recorded calls or failures."""
    _ScriptedOpenAI.calls = []
    _ScriptedOpenAI.failures = 0
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=_ScriptedOpenAI))
    return _ScriptedOpenAI


def _complete(provider):
    return provider.complete(
        system="s", messages=[Message(role="user", content="c")], model="m", max_tokens=8, response_schema=EMPTY_SCHEMA
    )


def test_retries_allow_one_extra_attempt_per_retry(scripted_openai):
    """Two rate-limit failures with retries=2 succeed on the third call and report three attempts."""
    scripted_openai.failures = 2

    result = _complete(_make("openai"))

    assert result.text == "{}"
    assert result.attempts == 3
    assert len(scripted_openai.calls) == 3


def test_retries_give_up_after_the_last_extra_attempt(scripted_openai):
    """Three rate-limit failures with retries=2 re-raise the error after exactly three calls."""
    scripted_openai.failures = 3

    with pytest.raises(_RateLimited):
        _complete(_make("openai"))

    assert len(scripted_openai.calls) == 3
