"""Provider construction from a name and client policy."""

from __future__ import annotations

from dataclasses import dataclass

from cyberjury.providers import anthropic, openai
from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.base import Provider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider

DEFAULT_RETRIES = 2
DEFAULT_PROVIDER = "openai"


@dataclass(frozen=True, kw_only=True)
class ProviderBackend:
    """One supported provider: its backend class and the model and endpoint it uses when unset."""

    backend: type[OpenAIProvider] | type[AnthropicProvider]
    default_model: str
    default_base_url: str


PROVIDERS = {
    "openai": ProviderBackend(
        backend=OpenAIProvider, default_model="gpt-6-astra", default_base_url=openai.DEFAULT_BASE_URL
    ),
    "anthropic": ProviderBackend(
        backend=AnthropicProvider, default_model="claude-fable-5-1", default_base_url=anthropic.DEFAULT_BASE_URL
    ),
}


def make_provider(name: str, *, api_key: str, base_url: str, retries: int, timeout: float) -> Provider:
    """Build the named provider with its key and wrap it with retries."""
    provider = PROVIDERS[name].backend(api_key=api_key, base_url=base_url, timeout=timeout)
    return RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
