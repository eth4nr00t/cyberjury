"""Provider factory selects lazy backends and applies retry wrapping."""

import pytest

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.factory import ROLES, default_model_for_provider, env_defaults, make_provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider


def test_selects_provider_by_name():
    assert isinstance(make_provider("openai"), OpenAIProvider)
    assert isinstance(make_provider("anthropic"), AnthropicProvider)


def test_env_defaults_prefer_openai_when_a_key_is_reachable(monkeypatch):
    """Default provider order prefers OpenAI when a key is reachable."""
    monkeypatch.delenv("CYBERJURY_PROVIDER", raising=False)
    monkeypatch.delenv("CYBERJURY_MODEL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    defaults = env_defaults()

    assert defaults["provider"] == "openai"
    assert defaults["model"] == "gpt-5.6"


def test_env_defaults_fall_back_to_anthropic_without_an_openai_key(monkeypatch):
    """Default provider order falls back to Anthropic without an OpenAI key."""
    monkeypatch.delenv("CYBERJURY_PROVIDER", raising=False)
    monkeypatch.delenv("CYBERJURY_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CYBERJURY_API_KEY", raising=False)

    defaults = env_defaults()

    assert defaults["provider"] == "anthropic"
    assert defaults["model"] == "claude-opus-5"


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


def test_openai_wire_api_reaches_the_built_provider():
    assert make_provider("openai", wire_api="responses")._wire_api == "responses"


def test_env_defaults_read_each_role_backend_field(monkeypatch):
    """Every role field can come from its matching CYBERJURY role variable."""
    for role in ROLES:
        prefix = f"CYBERJURY_{role.upper()}"
        monkeypatch.setenv(f"{prefix}_PROVIDER", f"{role}-provider")
        monkeypatch.setenv(f"{prefix}_MODEL", f"{role}-model")
        monkeypatch.setenv(f"{prefix}_API_KEY", f"{role}-key")
        monkeypatch.setenv(f"{prefix}_API_BASE", f"https://{role}.example.test")
        monkeypatch.setenv(f"{prefix}_WIRE_API", "responses")

    defaults = env_defaults()

    for role in ROLES:
        backend = defaults["role_backends"][role]
        assert backend == {
            "provider": f"{role}-provider",
            "model": f"{role}-model",
            "api_key": f"{role}-key",
            "api_base": f"https://{role}.example.test",
            "wire_api": "responses",
        }


def test_retries_wrap_in_retry_provider_with_one_extra_attempt():
    provider = make_provider("openai", retries=2)
    assert isinstance(provider, RetryProvider)
    assert isinstance(provider._inner, OpenAIProvider)
    assert provider._max_attempts == 3
