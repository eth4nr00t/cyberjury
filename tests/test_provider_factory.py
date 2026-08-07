"""make_provider selects a backend and applies retry wrapping.

The other tests monkeypatch the factory out, so this is the only place its real
selection and RetryProvider branch run. Construction is lazy, no SDK or key is touched
until a call is made.
"""

from cyberjury.providers.anthropic import AnthropicProvider
from cyberjury.providers.factory import make_provider
from cyberjury.providers.litellm import LiteLLMProvider
from cyberjury.providers.openai import OpenAIProvider
from cyberjury.providers.retry import RetryProvider


def test_selects_provider_by_name():
    """Exercise the selects provider by name case."""
    assert isinstance(make_provider("openai"), OpenAIProvider)
    assert isinstance(make_provider("litellm"), LiteLLMProvider)
    assert isinstance(make_provider("anthropic"), AnthropicProvider)


def test_unknown_name_defaults_to_anthropic():
    """Exercise the unknown name defaults to anthropic case."""
    assert isinstance(make_provider("something-else"), AnthropicProvider)


def test_no_retries_leaves_the_provider_unwrapped():
    """Exercise the no retries leaves the provider unwrapped case."""
    provider = make_provider("openai", retries=0)
    assert isinstance(provider, OpenAIProvider)


def test_openai_wire_api_reaches_the_built_provider():
    """Exercise the openai wire api reaches the built provider case."""
    assert make_provider("openai", wire_api="responses")._wire_api == "responses"


def test_retries_wrap_in_retry_provider_with_one_extra_attempt():
    """Exercise the retries wrap in retry provider with one extra attempt case."""
    provider = make_provider("litellm", retries=2)
    assert isinstance(provider, RetryProvider)
    assert isinstance(provider._inner, LiteLLMProvider)
    assert provider._max_attempts == 3
