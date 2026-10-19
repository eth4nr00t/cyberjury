"""Typed provider seat configuration shared by the review command and its seats."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.factory import (
    DEFAULT_RETRIES,
    ROLES,
    default_model_for_provider,
    make_provider,
    nonnegative_int,
    positive_float,
)
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.openai import WIRE_APIS


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
class EnvironmentDefaults:
    """The base seat, client policy, and role overrides read from the CYBERJURY_* environment."""

    provider: str
    model: str | None
    api_key: str | None
    api_base: str | None
    wire_api: str | None
    retries: int
    timeout: float
    roles: dict[str, ProviderSeatOverride]


@dataclass(frozen=True, kw_only=True)
class ProviderConfiguration:
    """Resolved base and finder seats with shared client policy."""

    base: ProviderSeat
    finder: ProviderSeat
    retries: int
    timeout: float


class ProviderCredentialsError(ValueError):
    """A configured provider seat cannot authenticate a request."""


def _env_number[T](name: str, parse: Callable[[str], T], default: T) -> T:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return parse(raw)
    except ValueError as exc:
        raise ValueError(f"{name} {exc}") from None


def _default_provider() -> str:
    """Prefer OpenAI when a key is reachable, otherwise fall back to Anthropic API defaults."""
    if os.environ.get("CYBERJURY_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "anthropic"


def _env_wire_api(name: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        return None
    if value not in WIRE_APIS:
        raise ValueError(f"{name} must be one of {', '.join(WIRE_APIS)}, got {value!r}")
    return value


def _env_role(role: str) -> ProviderSeatOverride:
    prefix = f"CYBERJURY_{role.upper()}"
    return ProviderSeatOverride(
        provider=os.environ.get(f"{prefix}_PROVIDER"),
        model=os.environ.get(f"{prefix}_MODEL"),
        api_key=os.environ.get(f"{prefix}_API_KEY"),
        api_base=os.environ.get(f"{prefix}_API_BASE"),
        wire_api=_env_wire_api(f"{prefix}_WIRE_API"),
    )


def env_defaults() -> EnvironmentDefaults:
    """Read the environment defaults on call rather than at import, so a loaded .env applies."""
    return EnvironmentDefaults(
        provider=os.environ.get("CYBERJURY_PROVIDER") or _default_provider(),
        model=os.environ.get("CYBERJURY_MODEL"),
        api_key=os.environ.get("CYBERJURY_API_KEY"),
        api_base=os.environ.get("CYBERJURY_API_BASE"),
        wire_api=_env_wire_api("CYBERJURY_WIRE_API"),
        retries=_env_number("CYBERJURY_RETRIES", nonnegative_int, DEFAULT_RETRIES),
        timeout=_env_number("CYBERJURY_TIMEOUT", positive_float, REQUEST_TIMEOUT_SECONDS),
        roles={role: _env_role(role) for role in ROLES},
    )


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


def provider_configuration_from_env(
    *,
    provider: str | None = None,
    model: str | None = None,
    wire_api: str | None = None,
    retries: int | None = None,
    timeout: float | None = None,
) -> ProviderConfiguration:
    """Resolve the environment seats, with optional base seat and client policy overrides.

    Keys, endpoints, and role overrides come only from the environment.
    """
    defaults = env_defaults()
    base_provider = provider or defaults.provider
    base = ProviderSeat(
        provider=base_provider,
        model=model or defaults.model or default_model_for_provider(base_provider),
        api_key=defaults.api_key,
        api_base=defaults.api_base,
        wire_api=wire_api or defaults.wire_api,
    )
    roles = {role: resolve_provider_seat(base, defaults.roles[role]) for role in ROLES}
    return ProviderConfiguration(
        base=base,
        finder=roles["finder"],
        retries=defaults.retries if retries is None else retries,
        timeout=timeout or defaults.timeout,
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
        "or the role's CYBERJURY_<ROLE>_API_KEY."
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
