"""Provider configuration stays independent from CLI argument objects."""

import pytest

from cyberjury.providers.configuration import (
    ProviderCredentialsError,
    ProviderSeat,
    provider_configuration_from_env,
    require_provider_key,
)


def test_a_reachable_openai_key_selects_openai_and_its_default_model(monkeypatch):
    """OPENAI_API_KEY alone selects openai with gpt-6-astra, 2 retries, and a 240 second timeout."""
    monkeypatch.setenv("OPENAI_API_KEY", "k")

    configuration = provider_configuration_from_env()

    assert (configuration.seat.provider, configuration.seat.model) == ("openai", "gpt-6-astra")
    assert (configuration.retries, configuration.timeout) == (2, 240.0)


def test_without_an_openai_key_anthropic_is_the_default():
    """An empty environment resolves the seat to anthropic with claude-fable-5-1."""
    seat = provider_configuration_from_env().seat

    assert (seat.provider, seat.model) == ("anthropic", "claude-fable-5-1")


def test_environment_sets_the_model_and_endpoint(monkeypatch):
    """CYBERJURY_MODEL and CYBERJURY_BASE_URL override the openai seat's model and base_url."""
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("CYBERJURY_MODEL", "seat-model")
    monkeypatch.setenv("CYBERJURY_BASE_URL", "https://gateway.example.test")

    seat = provider_configuration_from_env().seat

    assert seat == ProviderSeat(provider="openai", model="seat-model", base_url="https://gateway.example.test")


def test_a_seat_without_its_sdk_key_is_rejected_before_review_work(monkeypatch):
    """An anthropic seat raises "set ANTHROPIC_API_KEY" until that variable is present."""
    with pytest.raises(ProviderCredentialsError, match="has no API key, set ANTHROPIC_API_KEY"):
        require_provider_key(ProviderSeat(provider="anthropic", model="m"))

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    require_provider_key(ProviderSeat(provider="anthropic", model="m"))


def test_blank_settings_count_as_unset(monkeypatch):
    """Whitespace-only key, model, and base URL variables fall back to the anthropic claude-fable-5-1 seat."""
    for name in ("OPENAI_API_KEY", "CYBERJURY_MODEL", "CYBERJURY_BASE_URL"):
        monkeypatch.setenv(name, "  ")

    seat = provider_configuration_from_env().seat

    assert seat == ProviderSeat(provider="anthropic", model="claude-fable-5-1")
