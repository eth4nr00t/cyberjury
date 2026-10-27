"""Provider construction from a name and client policy."""

from __future__ import annotations

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

DEFAULT_RETRIES = 2


def default_model_for_provider(provider: str) -> str:
    """Match the default model to the provider selected by the default provider order."""
    return "gpt-5.6" if provider == "openai" else "claude-opus-5"


def make_provider(name: str, *, api_base: str | None, retries: int, timeout: float) -> Provider:
    """Build the named provider and wrap it with retries."""
    provider: Provider = (
        OpenAIProvider(api_base=api_base, timeout=timeout)
        if name == "openai"
        else AnthropicProvider(api_base=api_base, timeout=timeout)
    )
    return RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
