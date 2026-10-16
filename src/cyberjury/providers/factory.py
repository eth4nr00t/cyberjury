"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os
from collections.abc import Callable
from math import isfinite

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import REQUEST_TIMEOUT_SECONDS, Provider
from cyberjury.providers.openai import WIRE_APIS, OpenAIProvider
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


def default_model_for_provider(provider: str) -> str:
    """Match the default model to the provider selected by the default provider order."""
    return "gpt-5.6" if provider == "openai" else "claude-opus-5"


def _env_wire_api(name: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        return None
    if value not in WIRE_APIS:
        raise ValueError(f"{name} must be one of {', '.join(WIRE_APIS)}, got {value!r}")
    return value


def env_defaults() -> dict:
    """The env-backed defaults, read on call rather than frozen at import.

    This lets a CLI that loaded a .env first see them.
    """
    return {
        "provider": os.environ.get("CYBERJURY_PROVIDER") or _default_provider(),
        "model": os.environ.get("CYBERJURY_MODEL"),
        "api_key": os.environ.get("CYBERJURY_API_KEY"),
        "api_base": os.environ.get("CYBERJURY_API_BASE"),
        "wire_api": _env_wire_api("CYBERJURY_WIRE_API"),
        "retries": _env_number("CYBERJURY_RETRIES", nonnegative_int, DEFAULT_RETRIES),
        "timeout": _env_number("CYBERJURY_TIMEOUT", positive_float, REQUEST_TIMEOUT_SECONDS),
        "role_backends": {
            role: {
                "provider": os.environ.get(f"CYBERJURY_{role.upper()}_PROVIDER"),
                "model": os.environ.get(f"CYBERJURY_{role.upper()}_MODEL"),
                "api_key": os.environ.get(f"CYBERJURY_{role.upper()}_API_KEY"),
                "api_base": os.environ.get(f"CYBERJURY_{role.upper()}_API_BASE"),
                "wire_api": _env_wire_api(f"CYBERJURY_{role.upper()}_WIRE_API"),
            }
            for role in ROLES
        },
    }


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
