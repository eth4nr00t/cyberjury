"""Provider factory: build a provider from a name and the environment."""

from __future__ import annotations

import os

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

PROVIDERS = ("openai", "anthropic")

ROLES = ("finder", "challenger", "judge")

_DEFAULT_TIMEOUT = 240.0


def _default_provider() -> str:
    """Prefer OpenAI when a key is reachable, otherwise fall back to Anthropic API defaults."""
    if os.environ.get("CYBERJURY_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return "anthropic"


def _default_model(provider: str) -> str:
    """Match the default model to the provider selected by the default provider order."""
    return "gpt-5.6" if provider == "openai" else "claude-opus-5"


def env_defaults() -> dict:
    """The env-backed defaults, read on call rather than frozen at import.

    This lets a CLI that loaded a .env first see them.
    """
    provider = os.environ.get("CYBERJURY_PROVIDER") or _default_provider()
    return {
        "provider": provider,
        "model": os.environ.get("CYBERJURY_MODEL", _default_model(provider)),
        "api_key": os.environ.get("CYBERJURY_API_KEY"),
        "api_base": os.environ.get("CYBERJURY_API_BASE"),
        "wire_api": os.environ.get("CYBERJURY_WIRE_API"),
        "retries": int(os.environ.get("CYBERJURY_RETRIES", "2")),
        "timeout": float(os.environ.get("CYBERJURY_TIMEOUT") or _DEFAULT_TIMEOUT),
        "role_backends": {
            role: {
                "provider": os.environ.get(f"CYBERJURY_{role.upper()}_PROVIDER"),
                "model": os.environ.get(f"CYBERJURY_{role.upper()}_MODEL"),
                "api_key": os.environ.get(f"CYBERJURY_{role.upper()}_API_KEY"),
                "api_base": os.environ.get(f"CYBERJURY_{role.upper()}_API_BASE"),
                "wire_api": os.environ.get(f"CYBERJURY_{role.upper()}_WIRE_API"),
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
    timeout: float = _DEFAULT_TIMEOUT,
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
