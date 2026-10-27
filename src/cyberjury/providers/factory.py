"""Provider construction from a name and client policy."""

from __future__ import annotations

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

DEFAULT_RETRIES = 2


def default_model_for_provider(provider: str) -> str:
    """Match the default model to the provider selected by the default provider order."""
    return "gpt-6-astra" if provider == "openai" else "claude-fable-5-1"


def make_provider(name: str, *, base_url: str | None, retries: int, timeout: float) -> Provider:
    """Build the named provider and wrap it with retries."""
    provider: Provider = (
        OpenAIProvider(base_url=base_url, timeout=timeout)
        if name == "openai"
        else AnthropicProvider(base_url=base_url, timeout=timeout)
    )
    return RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
