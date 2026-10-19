"""Provider configuration stays independent from CLI argument objects."""

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import (
    EnvironmentDefaults,
    ProviderSeat,
    ProviderSeatOverride,
    env_defaults,
    provider_configuration_from_env,
    resolve_provider_seat,
)
from cyberjury.providers.factory import ROLES


def test_role_resolution_drops_cross_vendor_connection_fields():
    base = ProviderSeat(
        provider="anthropic",
        model="claude-base",
        api_key="anthropic-key",
        api_base="https://anthropic.invalid",
        wire_api="messages",
    )

    seat = resolve_provider_seat(base, ProviderSeatOverride(provider="openai"))

    assert seat == ProviderSeat(provider="openai", model="gpt-5.6")


def test_environment_configuration_applies_base_overrides_to_inherited_roles(monkeypatch):
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
            roles={
                "finder": ProviderSeatOverride(),
            },
        ),
    )

    configuration = provider_configuration_from_env(model="override")

    assert configuration.base.model == "override"
    assert configuration.finder.model == "override"
    assert configuration.retries == 2
    assert configuration.timeout == 30.0
    assert provider_configuration_from_env().base.model == "gpt-5.6"
    overridden = provider_configuration_from_env(provider="anthropic", wire_api="chat", retries=0, timeout=5.0)
    assert (overridden.base.provider, overridden.base.model, overridden.base.wire_api) == (
        "anthropic",
        "claude-opus-5",
        "chat",
    )
    assert (overridden.retries, overridden.timeout) == (0, 5.0)


def test_environment_reads_the_finder_role_variables(monkeypatch):
    monkeypatch.setenv("CYBERJURY_PROVIDER", "openai")
    monkeypatch.setenv("CYBERJURY_MODEL", "base-model")
    monkeypatch.setenv("CYBERJURY_FINDER_MODEL", "finder-model")

    configuration = provider_configuration_from_env()

    assert configuration.base.model == "base-model"
    assert configuration.finder.model == "finder-model"


def test_env_defaults_prefer_openai_when_a_key_is_reachable(monkeypatch):
    """Default provider order prefers OpenAI when a key is reachable."""
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    assert env_defaults().provider == "openai"


def test_env_defaults_fall_back_to_anthropic_without_an_openai_key():
    """Default provider order falls back to Anthropic without an OpenAI key."""
    assert env_defaults().provider == "anthropic"


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
        assert defaults.roles[role] == ProviderSeatOverride(
            provider=f"{role}-provider",
            model=f"{role}-model",
            api_key=f"{role}-key",
            api_base=f"https://{role}.example.test",
            wire_api="responses",
        )


@pytest.mark.parametrize("name", ["CYBERJURY_WIRE_API", "CYBERJURY_FINDER_WIRE_API"])
def test_env_defaults_reject_an_unknown_wire_api(monkeypatch, name):
    monkeypatch.setenv(name, "Responses")

    with pytest.raises(ValueError, match=rf"{name} must be one of responses, chat, got 'Responses'"):
        env_defaults()


def test_env_defaults_accept_chat_and_treat_an_empty_wire_api_as_unset(monkeypatch):
    monkeypatch.setenv("CYBERJURY_WIRE_API", "chat")
    monkeypatch.setenv("CYBERJURY_FINDER_WIRE_API", "")

    defaults = env_defaults()

    assert defaults.wire_api == "chat"
    assert defaults.roles["finder"].wire_api is None


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
