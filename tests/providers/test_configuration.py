"""Provider configuration stays independent from CLI argument objects."""

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import (
    EnvironmentDefaults,
    env_defaults,
    provider_configuration_from_env,
)


def test_environment_configuration_applies_command_overrides(monkeypatch):
    monkeypatch.setattr(
        configuration_module,
        "env_defaults",
        lambda: EnvironmentDefaults(
            provider="openai",
            model=None,
            api_key="key",
            api_base=None,
            wire_api="responses",
            retries=2,
            timeout=30.0,
        ),
    )

    configuration = provider_configuration_from_env(model="override")

    assert configuration.seat.model == "override"
    assert configuration.seat.api_key == "key"
    assert configuration.retries == 2
    assert configuration.timeout == 30.0
    assert provider_configuration_from_env().seat.model == "gpt-5.6"
    overridden = provider_configuration_from_env(provider="anthropic", wire_api="chat", retries=0, timeout=5.0)
    assert (overridden.seat.provider, overridden.seat.model, overridden.seat.wire_api) == (
        "anthropic",
        "claude-opus-5",
        "chat",
    )
    assert (overridden.retries, overridden.timeout) == (0, 5.0)


def test_environment_reads_every_seat_variable(monkeypatch):
    monkeypatch.setenv("CYBERJURY_PROVIDER", "openai")
    monkeypatch.setenv("CYBERJURY_MODEL", "seat-model")
    monkeypatch.setenv("CYBERJURY_API_KEY", "seat-key")
    monkeypatch.setenv("CYBERJURY_API_BASE", "https://gateway.example.test")
    monkeypatch.setenv("CYBERJURY_WIRE_API", "chat")

    seat = provider_configuration_from_env().seat

    assert (seat.provider, seat.model, seat.api_key, seat.api_base, seat.wire_api) == (
        "openai",
        "seat-model",
        "seat-key",
        "https://gateway.example.test",
        "chat",
    )


def test_env_defaults_prefer_openai_when_a_key_is_reachable(monkeypatch):
    """Default provider order prefers OpenAI when a key is reachable."""
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    assert env_defaults().provider == "openai"


def test_env_defaults_fall_back_to_anthropic_without_an_openai_key():
    """Default provider order falls back to Anthropic without an OpenAI key."""
    assert env_defaults().provider == "anthropic"


def test_env_defaults_reject_an_unknown_wire_api(monkeypatch):
    monkeypatch.setenv("CYBERJURY_WIRE_API", "Responses")

    with pytest.raises(ValueError, match=r"CYBERJURY_WIRE_API must be one of responses, chat, got 'Responses'"):
        env_defaults()


def test_env_defaults_accept_chat_and_treat_an_empty_wire_api_as_unset(monkeypatch):
    monkeypatch.setenv("CYBERJURY_WIRE_API", "chat")
    assert env_defaults().wire_api == "chat"

    monkeypatch.setenv("CYBERJURY_WIRE_API", "")
    assert env_defaults().wire_api is None


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("CYBERJURY_RETRIES", "-1", "CYBERJURY_RETRIES must be a nonnegative integer"),
        ("CYBERJURY_TIMEOUT", "nan", "CYBERJURY_TIMEOUT must be a finite positive number"),
    ],
)
def test_env_defaults_reject_invalid_client_policy(monkeypatch, name, value, message):
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=message):
        env_defaults()
