"""Provider construction from a name and client policy."""

from __future__ import annotations

from cyberjury.providers import anthropic, openai
from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

DEFAULT_RETRIES = 2


def default_model_for_provider(provider: str) -> str:
    """Return the model a provider uses when CYBERJURY_MODEL is not set."""
    return "gpt-6-astra" if provider == "openai" else "claude-fable-5-1"


def default_base_url_for_provider(provider: str) -> str:
    """Return the official API endpoint a provider uses when no gateway is configured."""
    return openai.DEFAULT_BASE_URL if provider == "openai" else anthropic.DEFAULT_BASE_URL


def make_provider(name: str, *, api_key: str, base_url: str | None, retries: int, timeout: float) -> Provider:
    """Build the named provider with its key and wrap it with retries."""
    provider: Provider = (
        OpenAIProvider(api_key=api_key, base_url=base_url, timeout=timeout)
        if name == "openai"
        else AnthropicProvider(api_key=api_key, base_url=base_url, timeout=timeout)
    )
    return RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
