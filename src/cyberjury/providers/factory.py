"""Provider factory: build a provider from a name, credentials, and client policy."""

from __future__ import annotations

from math import isfinite

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

PROVIDERS = ("openai", "anthropic")

ROLES = ("finder", "skeptic", "confirmer")

DEFAULT_RETRIES = 2


def nonnegative_int(value: str) -> int:
    """Parse a retry count from a flag or an environment variable."""
    try:
        parsed = int(value)
    except ValueError:
        parsed = -1
    if parsed < 0:
        raise ValueError("must be a nonnegative integer")
    return parsed


def positive_float(value: str) -> float:
    """Parse a timeout in seconds from a flag or an environment variable."""
    try:
        parsed = float(value)
    except ValueError:
        parsed = 0.0
    if not isfinite(parsed) or parsed <= 0:
        raise ValueError("must be a finite positive number")
    return parsed


def default_model_for_provider(provider: str) -> str:
    """Match the default model to the provider selected by the default provider order."""
    return "gpt-5.6" if provider == "openai" else "claude-opus-5"


def make_provider(
    name: str,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
    retries: int = 0,
    wire_api: str | None = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> Provider:
    """Build the named provider and wrap it with retries when requested."""
    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, api_base=api_base, wire_api=wire_api, timeout=timeout)
    elif name == "anthropic":
        provider = AnthropicProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    else:
        raise ValueError(f"unknown provider: {name}")
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
    return provider
