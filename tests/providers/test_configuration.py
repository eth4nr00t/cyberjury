"""Provider configuration resolves one model seat from the CYBERJURY_* environment alone."""

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderSeat,
    ProviderSettingError,
    provider_configuration_from_env,
    provider_for_seat,
)
from cyberjury.providers.metering import UsageMeter


def test_an_empty_environment_selects_the_openai_seat_defaults():
    """Without settings the seat is openai with gpt-6-astra and the OpenAI API, 2 retries, and a 240 second timeout."""
    configuration = provider_configuration_from_env()

    assert configuration.seat == ProviderSeat(
        provider="openai", model="gpt-6-astra", base_url="https://api.openai.com/v1"
    )
    assert (configuration.api_key, configuration.retries, configuration.timeout) == (None, 2, 240.0)


def test_the_environment_sets_every_seat_field_and_the_key(monkeypatch):
    """CYBERJURY_PROVIDER, CYBERJURY_API_KEY, CYBERJURY_BASE_URL, and CYBERJURY_MODEL fill the configuration."""
    monkeypatch.setenv("CYBERJURY_PROVIDER", "anthropic")
    monkeypatch.setenv("CYBERJURY_API_KEY", "k")
    monkeypatch.setenv("CYBERJURY_BASE_URL", "https://gateway.example.test")
    monkeypatch.setenv("CYBERJURY_MODEL", "seat-model")

    configuration = provider_configuration_from_env()

    assert configuration.seat == ProviderSeat(
        provider="anthropic", model="seat-model", base_url="https://gateway.example.test"
    )
    assert configuration.api_key == "k"


def test_provider_sdk_variables_are_not_read(monkeypatch):
    """OPENAI_API_KEY and OPENAI_BASE_URL leave the anthropic seat without a key and on the Anthropic API."""
    monkeypatch.setenv("CYBERJURY_PROVIDER", "anthropic")
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openai-gateway.example.test")

    configuration = provider_configuration_from_env()

    assert (configuration.seat.base_url, configuration.api_key) == ("https://api.anthropic.com", None)


def test_blank_settings_count_as_unset(monkeypatch):
    """Whitespace-only provider, key, base URL, and model variables fall back to the openai seat defaults."""
    for name in ("CYBERJURY_PROVIDER", "CYBERJURY_API_KEY", "CYBERJURY_BASE_URL", "CYBERJURY_MODEL"):
        monkeypatch.setenv(name, "  ")

    configuration = provider_configuration_from_env()

    assert configuration.seat == ProviderSeat(
        provider="openai", model="gpt-6-astra", base_url="https://api.openai.com/v1"
    )
    assert configuration.api_key is None


def test_an_unknown_provider_is_rejected(monkeypatch):
    """A CYBERJURY_PROVIDER of claude raises a setting error naming the accepted providers."""
    monkeypatch.setenv("CYBERJURY_PROVIDER", "claude")

    with pytest.raises(ProviderSettingError, match="CYBERJURY_PROVIDER is not openai or anthropic: claude"):
        provider_configuration_from_env()


def test_a_seat_without_a_key_is_rejected_before_review_work(monkeypatch):
    """Building the seat's provider without CYBERJURY_API_KEY raises "set CYBERJURY_API_KEY" and builds nothing."""
    built = []
    monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: built.append(kwargs))
    configuration = ProviderConfiguration(
        seat=ProviderSeat(provider="openai", model="m"), api_key=None, retries=0, timeout=10
    )

    with pytest.raises(ProviderSettingError, match="has no API key, set CYBERJURY_API_KEY"):
        provider_for_seat(configuration, meter=UsageMeter())
    assert built == []
