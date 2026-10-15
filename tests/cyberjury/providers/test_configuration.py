"""Provider configuration stays independent from CLI argument objects."""

import pytest

from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import (
    ProviderSeat,
    ProviderSeatOverride,
    provider_configuration_from_env,
    resolve_provider_seat,
)


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
                "skeptic": {
                    "provider": None,
                    "model": "skeptic",
                    "api_key": None,
                    "api_base": None,
                    "wire_api": None,
                },
                "confirmer": {"provider": None, "model": None, "api_key": None, "api_base": None, "wire_api": None},
            },
        },
    )

    configuration = provider_configuration_from_env(model_override="override")

    assert configuration.base.model == "override"
    assert configuration.finder.model == "override"
    assert configuration.skeptic.model == "skeptic"
    assert configuration.confirmer.model == "override"
    assert configuration.retries == 2
    assert configuration.timeout == 30.0


def test_environment_reads_skeptic_and_confirmer_role_variables(monkeypatch):
    monkeypatch.setenv("CYBERJURY_PROVIDER", "openai")
    monkeypatch.setenv("CYBERJURY_MODEL", "base-model")
    monkeypatch.setenv("CYBERJURY_SKEPTIC_MODEL", "skeptic-model")
    monkeypatch.setenv("CYBERJURY_CONFIRMER_MODEL", "confirmer-model")

    configuration = provider_configuration_from_env()

    assert configuration.skeptic.model == "skeptic-model"
    assert configuration.confirmer.model == "confirmer-model"
    assert not hasattr(configuration, "challenger")
    assert not hasattr(configuration, "judge")


def test_retired_seat_variables_are_rejected_naming_the_replacement(monkeypatch):
    monkeypatch.setenv("CYBERJURY_CHALLENGER_MODEL", "removed-challenger")
    monkeypatch.setenv("CYBERJURY_JUDGE_PROVIDER", "openai")

    with pytest.raises(ValueError, match="retired seat variables are set") as error:
        provider_configuration_from_env()
    assert "CYBERJURY_CHALLENGER_MODEL (use CYBERJURY_SKEPTIC_MODEL)" in str(error.value)
    assert "CYBERJURY_JUDGE_PROVIDER (use CYBERJURY_CONFIRMER_PROVIDER)" in str(error.value)
