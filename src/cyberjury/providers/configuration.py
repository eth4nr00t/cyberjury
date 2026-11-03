"""Typed provider seat configuration shared by the review command and its seats."""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberjury.envfile import env_setting
from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.factory import DEFAULT_PROVIDER, DEFAULT_RETRIES, PROVIDERS, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter


@dataclass(frozen=True, kw_only=True)
class ProviderSeat:
    """One resolved model seat with provider-specific connection fields."""

    provider: str
    model: str
    base_url: str


@dataclass(frozen=True, kw_only=True)
class ProviderConfiguration:
    """The resolved model seat with its API key and client policy."""

    seat: ProviderSeat
    api_key: str | None = field(repr=False)
    retries: int
    timeout: float


class ProviderSettingError(ValueError):
    """A provider setting in the environment is missing or invalid."""


def provider_configuration_from_env() -> ProviderConfiguration:
    """Resolve the model seat from the `CYBERJURY_*` environment, which a working directory `.env` fills."""
    provider = env_setting("CYBERJURY_PROVIDER") or DEFAULT_PROVIDER
    if provider not in PROVIDERS:
        raise ProviderSettingError(f"CYBERJURY_PROVIDER is not {' or '.join(PROVIDERS)}: {provider}")
    defaults = PROVIDERS[provider]
    return ProviderConfiguration(
        seat=ProviderSeat(
            provider=provider,
            model=env_setting("CYBERJURY_MODEL") or defaults.default_model,
            base_url=env_setting("CYBERJURY_BASE_URL") or defaults.default_base_url,
        ),
        api_key=env_setting("CYBERJURY_API_KEY"),
        retries=DEFAULT_RETRIES,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def provider_for_seat(configuration: ProviderConfiguration, *, meter: UsageMeter) -> Provider:
    """Build the configured seat's provider with its key and client policy, metered into the run meter."""
    seat = configuration.seat
    if configuration.api_key is None:
        raise ProviderSettingError(f"the {seat.provider} provider has no API key, set CYBERJURY_API_KEY")
    provider = make_provider(
        seat.provider,
        api_key=configuration.api_key,
        base_url=seat.base_url,
        retries=configuration.retries,
        timeout=configuration.timeout,
    )
    return MeteringProvider(provider, meter)
