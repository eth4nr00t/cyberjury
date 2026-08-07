"""LiteLLMProvider: Provider backed by LiteLLM, reaching many backends.

LiteLLM speaks the OpenAI chat shape, so the system prompt is sent as the first message.
``cache`` is accepted but not applied here: prompt caching under LiteLLM is backend-
specific, so it stays a no-op until a backend-aware mapping is needed. The completion
callable is injectable so the mapping can be tested without the SDK or an API key.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cyberjury.providers.base import CompletionResult, Message, Provider
from cyberjury.providers.chat_format import choice_text


class LiteLLMProvider(Provider):
    """LiteLLM proxy backend using the OpenAI-compatible call shape."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        temperature: float = 0.0,
        completion: Callable[..., Any] | None = None,
        timeout: float = 240.0,
    ) -> None:
        """Store LiteLLM connection settings for the OpenAI compatible client."""
        self._api_key = api_key
        self._api_base = api_base
        self._temperature = temperature
        self._completion = completion
        self._timeout = timeout

    def _completion_fn(self) -> Callable[..., Any]:
        if self._completion is None:
            try:
                import litellm
            except ImportError as exc:
                raise RuntimeError("litellm not installed. run: pip install 'cyberjury[litellm]'") from exc
            self._completion = litellm.completion
        return self._completion

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
        cache_prefix: str = "",
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages += [{"role": m.role, "content": m.content} for m in messages]

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": self._temperature,
            "timeout": self._timeout,
        }
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._api_base:
            kwargs["api_base"] = self._api_base

        response = self._completion_fn()(**kwargs)
        return CompletionResult(text=choice_text(response))
