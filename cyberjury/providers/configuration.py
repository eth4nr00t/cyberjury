"""Typed provider seat configuration shared by command and evaluation adapters."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cyberjury.providers.base import Provider
from cyberjury.providers.factory import default_model_for_provider, env_defaults, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter


@dataclass(frozen=True, kw_only=True)
class ProviderSeat:
    """One resolved model seat with provider specific connection fields."""

    provider: str
    model: str
    api_key: str | None = None
    api_base: str | None = None
    wire_api: str | None = None


@dataclass(frozen=True, kw_only=True)
class ProviderSeatOverride:
    """Optional role fields resolved against the base seat."""

    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    api_base: str | None = None
    wire_api: str | None = None


@dataclass(frozen=True, kw_only=True)
class ProviderConfiguration:
    """Resolved base and role seats with shared client policy."""

    base: ProviderSeat
    finder: ProviderSeat
    challenger: ProviderSeat
    judge: ProviderSeat
    retries: int
    timeout: float


@dataclass(frozen=True, kw_only=True)
class DiffProviders:
    """Instantiated provider and model seats for one diff review."""

    base_provider: Provider
    base_model: str
    finder_provider: Provider | None = None
    finder_model: str | None = None
    challenger_provider: Provider | None = None
    challenger_model: str | None = None
    judge_provider: Provider | None = None
    judge_model: str | None = None


class ProviderCredentialsError(ValueError):
    """A configured provider seat cannot authenticate a request."""


def resolve_provider_seat(base: ProviderSeat, override: ProviderSeatOverride) -> ProviderSeat:
    """Keep provider specific fields only when a role stays on the base vendor."""
    provider = override.provider or base.provider
    same_vendor = provider == base.provider
    return ProviderSeat(
        provider=provider,
        model=override.model or (base.model if same_vendor else default_model_for_provider(provider)),
        api_key=override.api_key or (base.api_key if same_vendor else None),
        api_base=override.api_base or (base.api_base if same_vendor else None),
        wire_api=override.wire_api or (base.wire_api if same_vendor else None),
    )


def provider_configuration_from_env(*, model_override: str | None = None) -> ProviderConfiguration:
    """Resolve environment defaults into the same seat contract used by the CLI."""
    defaults = env_defaults()
    base = ProviderSeat(
        provider=defaults["provider"],
        model=model_override or defaults["model"],
        api_key=defaults["api_key"],
        api_base=defaults["api_base"],
        wire_api=defaults["wire_api"],
    )
    roles = {
        role: resolve_provider_seat(base, ProviderSeatOverride(**defaults["role_backends"][role]))
        for role in ("finder", "challenger", "judge")
    }
    return ProviderConfiguration(
        base=base,
        finder=roles["finder"],
        challenger=roles["challenger"],
        judge=roles["judge"],
        retries=defaults["retries"],
        timeout=defaults["timeout"],
    )


def require_provider_key(seat: ProviderSeat) -> None:
    """Reject a seat before review work when neither explicit nor SDK credentials exist."""
    sdk_keys = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
    sdk_key = sdk_keys.get(seat.provider)
    if seat.api_key or (sdk_key and os.environ.get(sdk_key)):
        return
    key_name = sdk_key or "the provider SDK key"
    raise ProviderCredentialsError(
        f"the {seat.provider} seat has no reachable API key. Set CYBERJURY_API_KEY, {key_name}, "
        "or a role-specific API key."
    )


def provider_for_seat(
    configuration: ProviderConfiguration,
    seat: ProviderSeat,
    *,
    meter: UsageMeter | None = None,
) -> Provider:
    """Apply shared client policy and optional metering to one resolved seat."""
    require_provider_key(seat)
    provider = make_provider(
        seat.provider,
        api_key=seat.api_key,
        api_base=seat.api_base,
        retries=configuration.retries,
        wire_api=seat.wire_api,
        timeout=configuration.timeout,
    )
    return MeteringProvider(provider, meter) if meter is not None else provider


def build_diff_providers(configuration: ProviderConfiguration, mode: str) -> DiffProviders:
    """Instantiate only the provider seats used by the selected diff mode."""
    if mode not in {"standard", "adversarial"}:
        raise ValueError(f"unknown review mode: {mode}")
    finder = provider_for_seat(configuration, configuration.finder)
    if mode == "standard":
        return DiffProviders(
            base_provider=finder,
            base_model=configuration.finder.model,
            finder_provider=finder,
            finder_model=configuration.finder.model,
        )
    challenger = provider_for_seat(configuration, configuration.challenger)
    judge = provider_for_seat(configuration, configuration.judge)
    return DiffProviders(
        base_provider=finder,
        base_model=configuration.finder.model,
        finder_provider=finder,
        finder_model=configuration.finder.model,
        challenger_provider=challenger,
        challenger_model=configuration.challenger.model,
        judge_provider=judge,
        judge_model=configuration.judge.model,
    )
