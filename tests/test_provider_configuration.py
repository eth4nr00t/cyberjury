"""Provider configuration stays independent from CLI argument objects."""

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderSeat,
    ProviderSeatOverride,
    build_diff_providers,
    provider_configuration_from_env,
    resolve_provider_seat,
)
from cyberjury.providers.mock import MockProvider


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


def test_environment_configuration_applies_model_override_to_inherited_roles(monkeypatch):
    monkeypatch.setattr(
        configuration_module,
        "env_defaults",
        lambda: {
            "provider": "openai",
            "model": "base-model",
            "api_key": "key",
            "api_base": None,
            "wire_api": "responses",
            "retries": 2,
            "timeout": 30.0,
            "role_backends": {
                "finder": {"provider": None, "model": None, "api_key": None, "api_base": None, "wire_api": None},
                "challenger": {
                    "provider": None,
                    "model": "skeptic",
                    "api_key": None,
                    "api_base": None,
                    "wire_api": None,
                },
                "judge": {"provider": None, "model": None, "api_key": None, "api_base": None, "wire_api": None},
            },
        },
    )

    configuration = provider_configuration_from_env(model_override="override")

    assert configuration.base.model == "override"
    assert configuration.finder.model == "override"
    assert configuration.challenger.model == "skeptic"
    assert configuration.judge.model == "override"
    assert configuration.retries == 2
    assert configuration.timeout == 30.0


def test_standard_diff_instantiates_only_the_finder_seat(monkeypatch):
    created = []
    monkeypatch.setattr(
        configuration_module,
        "make_provider",
        lambda name, **kwargs: created.append((name, kwargs)) or MockProvider(default="{}"),
    )
    configuration = ProviderConfiguration(
        base=ProviderSeat(provider="openai", model="base", api_key="key"),
        finder=ProviderSeat(provider="openai", model="finder", api_key="key"),
        challenger=ProviderSeat(provider="anthropic", model="skeptic", api_key="key"),
        judge=ProviderSeat(provider="anthropic", model="judge", api_key="key"),
        retries=1,
        timeout=15.0,
    )

    providers = build_diff_providers(configuration, "standard")

    assert providers.base_provider is providers.finder_provider
    assert providers.base_model == "finder"
    assert providers.challenger_provider is None
    assert created == [
        (
            "openai",
            {
                "api_key": "key",
                "api_base": None,
                "retries": 1,
                "wire_api": None,
                "timeout": 15.0,
            },
        )
    ]


def test_diff_provider_mode_fails_before_instantiating_a_seat(monkeypatch):
    monkeypatch.setattr(
        configuration_module,
        "make_provider",
        lambda *args, **kwargs: pytest.fail("invalid mode instantiated a provider"),
    )
    seat = ProviderSeat(provider="openai", model="model", api_key="key")
    configuration = ProviderConfiguration(
        base=seat,
        finder=seat,
        challenger=seat,
        judge=seat,
        retries=0,
        timeout=10,
    )

    with pytest.raises(ValueError, match="unknown review mode"):
        build_diff_providers(configuration, "invalid")
