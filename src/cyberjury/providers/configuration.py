"""Typed provider seat configuration shared by the review command and its seats."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.envfile import env_setting
from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.factory import DEFAULT_RETRIES, default_model_for_provider, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter

_SDK_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


@dataclass(frozen=True, kw_only=True)
class ProviderSeat:
    """One resolved model seat with provider specific connection fields."""

    provider: str
    model: str
    base_url: str | None = None


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
    seat_provider = "openai" if env_setting("OPENAI_API_KEY") else "anthropic"
    return ProviderConfiguration(
        seat=ProviderSeat(
            provider=seat_provider,
            model=env_setting("CYBERJURY_MODEL") or default_model_for_provider(seat_provider),
            base_url=env_setting("CYBERJURY_BASE_URL"),
        ),
        retries=DEFAULT_RETRIES,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def require_provider_key(seat: ProviderSeat) -> None:
    """Reject a seat before review work when its provider SDK has no key."""
    key_name = _SDK_KEYS[seat.provider]
    if not env_setting(key_name):
        raise ProviderCredentialsError(f"the {seat.provider} provider has no API key, set {key_name}")


def provider_for_seat(configuration: ProviderConfiguration, *, meter: UsageMeter) -> Provider:
    """Build the configured seat's provider with the client policy, metered into the run meter."""
    seat = configuration.seat
    require_provider_key(seat)
    provider = make_provider(
        seat.provider,
        base_url=seat.base_url,
        retries=configuration.retries,
        timeout=configuration.timeout,
    )
    return MeteringProvider(provider, meter)
