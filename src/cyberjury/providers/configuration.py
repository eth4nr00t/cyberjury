"""Typed provider seat configuration shared by command and evaluation adapters."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from cyberjury.providers.base import Provider
from cyberjury.providers.factory import ROLES, default_model_for_provider, env_defaults, make_provider
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
    """Resolved base, finder, and verification seats with shared client policy.

    The skeptic seat tries to refute a candidate. The confirmer seat is the independent
    confirmer that a deletion needs when it differs from both the skeptic and the finder.
    """

    base: ProviderSeat
    finder: ProviderSeat
    skeptic: ProviderSeat
    confirmer: ProviderSeat
    retries: int
    timeout: float


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


def provider_configuration(
    base: ProviderSeat,
    overrides: Mapping[str, ProviderSeatOverride],
    *,
    retries: int,
    timeout: float,
) -> ProviderConfiguration:
    """Resolve every role seat against the base seat with shared client policy."""
    roles = {role: resolve_provider_seat(base, overrides[role]) for role in ROLES}
    return ProviderConfiguration(
        base=base,
        finder=roles["finder"],
        skeptic=roles["skeptic"],
        confirmer=roles["confirmer"],
        retries=retries,
        timeout=timeout,
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
    return provider_configuration(
        base,
        {role: ProviderSeatOverride(**fields) for role, fields in defaults["role_backends"].items()},
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
    require_key: bool = True,
) -> Provider:
    """Apply shared client policy and optional metering to one resolved seat.

    A caller passes ``require_key=False`` only for a seat it will never call.
    """
    if require_key:
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
