"""Typed provider seat configuration shared by the review command and its seats."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.factory import DEFAULT_RETRIES, default_model_for_provider, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter

_SDK_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def _setting(name: str) -> str | None:
    return os.getenv(name, "").strip() or None


@dataclass(frozen=True, kw_only=True)
class ProviderSeat:
    """One resolved model seat with provider specific connection fields."""

    provider: str
    model: str
    api_base: str | None = None


@dataclass(frozen=True, kw_only=True)
class ProviderConfiguration:
    """The resolved model seat with its client policy."""

    seat: ProviderSeat
    retries: int
    timeout: float


class ProviderCredentialsError(ValueError):
    """A configured provider seat cannot authenticate a request."""


def provider_configuration_from_env() -> ProviderConfiguration:
    """Resolve the model seat from the environment, which a working directory `.env` fills."""
    seat_provider = "openai" if _setting("OPENAI_API_KEY") else "anthropic"
    return ProviderConfiguration(
        seat=ProviderSeat(
            provider=seat_provider,
            model=_setting("CYBERJURY_MODEL") or default_model_for_provider(seat_provider),
            api_base=_setting("CYBERJURY_API_BASE"),
        ),
        retries=DEFAULT_RETRIES,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def require_provider_key(seat: ProviderSeat) -> None:
    """Reject a seat before review work when its provider SDK has no key."""
    key_name = _SDK_KEYS[seat.provider]
    if not _setting(key_name):
        raise ProviderCredentialsError(f"the {seat.provider} seat has no reachable API key. Set {key_name}.")


def provider_for_seat(configuration: ProviderConfiguration, *, meter: UsageMeter) -> Provider:
    """Build the configured seat's provider with the client policy, metered into the run meter."""
    seat = configuration.seat
    require_provider_key(seat)
    provider = make_provider(
        seat.provider,
        api_base=seat.api_base,
        retries=configuration.retries,
        timeout=configuration.timeout,
    )
    return MeteringProvider(provider, meter)
