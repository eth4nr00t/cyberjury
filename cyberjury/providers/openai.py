"""OpenAIProvider: Provider backed by the OpenAI API, Chat Completions or Responses.

When the caller leaves ``wire_api`` unset, reasoning model names select Responses and
other names select Chat Completions. An explicit ``wire_api`` value overrides that
selection.
OpenAI caches long prefixes automatically, so ``cache`` sets no breakpoint. It does
route: requests are dispatched by a hash of the prompt's first tokens, so the same
prefix scatters across machines and misses. ``cache_prefix`` becomes a
``prompt_cache_key``, the routing hint that holds one prefix to one machine. An api_base
that validates request fields strictly will reject that key. The client is injectable so
the mapping can be tested without the SDK or a key.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage
from cyberjury.providers.chat_format import choice_text


class OpenAIProvider(Provider):
    """OpenAI backend for chat completions and responses calls."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        wire_api: str | None = None,
        timeout: float = 240.0,
    ) -> None:
        """Store OpenAI connection settings without constructing the client eagerly."""
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        self._wire_api = wire_api
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise RuntimeError("openai not installed, it is a base dependency, run: pip install cyberjury") from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._api_base:
                kwargs["base_url"] = self._api_base
            self._client = openai.OpenAI(**kwargs)
        return self._client

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
        routing = _routing_hint(cache, cache_prefix)
        if _wire_api_for_model(self._wire_api, model) == "responses":
            return self._complete_responses(
                system=system, messages=messages, model=model, max_tokens=max_tokens, routing=routing
            )
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages += [{"role": m.role, "content": m.content} for m in messages]

        response = self._get_client().chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
            temperature=0,
            timeout=self._timeout,
            **routing,
        )
        return CompletionResult(text=choice_text(response), usage=_chat_usage(response))

    def _complete_responses(
        self, *, system: str, messages: list[Message], model: str, max_tokens: int, routing: dict[str, str]
    ) -> CompletionResult:
        """The Responses API path the GPT-5 reasoning models use.

        The budget covers reasoning plus output, so it is generous: a budget too small yields
        empty output, which reads as an unusable reply upstream and keeps the finding, never a
        silent wrong refutation.
        """
        user_input = "\n\n".join(m.content for m in messages)
        response = self._get_client().responses.create(
            model=model,
            instructions=system or None,
            input=user_input,
            max_output_tokens=max(max_tokens, 8000),
            timeout=self._timeout,
            **routing,
        )
        return CompletionResult(text=getattr(response, "output_text", "") or "", usage=_responses_usage(response))


def _routing_hint(cache: bool, cache_prefix: str) -> dict[str, str]:
    """Keyed on the prefix itself rather than on a unit or a run.

    so every request that can share a cached prefix shares a key and no request that cannot
    is dragged onto the same machine. The digest is truncated because the key is only a
    routing label, not a lookup.
    """
    if not cache or not cache_prefix:
        return {}
    return {"prompt_cache_key": hashlib.sha256(cache_prefix.encode("utf-8")).hexdigest()[:32]}


def _wire_api_for_model(wire_api: str | None, model: str) -> str:
    """Choose the OpenAI wire API unless the caller explicitly chose one."""
    if wire_api:
        return wire_api
    name = model.lower()
    if name.startswith(("gpt-5", "o1", "o3", "o4")):
        return "responses"
    return "chat"


def _chat_usage(response: Any) -> Usage:
    """The Chat Completions token counts.

    `prompt_tokens` already includes the cached read, so the uncached input is the
    remainder, and OpenAI reports the cache read under prompt_tokens_details.
    """
    u = getattr(response, "usage", None)
    if u is None:
        return Usage()
    cached = _int(_nested(u, "prompt_tokens_details", "cached_tokens"))
    return Usage(
        input_tokens=max(_int(_get(u, "prompt_tokens")) - cached, 0),
        output_tokens=_int(_get(u, "completion_tokens")),
        cache_read_tokens=cached,
    )


def _responses_usage(response: Any) -> Usage:
    """The Responses API token counts, where input_tokens includes cache reads."""
    u = getattr(response, "usage", None)
    if u is None:
        return Usage()
    cached = _int(_nested(u, "input_tokens_details", "cached_tokens"))
    return Usage(
        input_tokens=max(_int(_get(u, "input_tokens")) - cached, 0),
        output_tokens=_int(_get(u, "output_tokens")),
        cache_read_tokens=cached,
    )


def _get(obj: Any, name: str) -> Any:
    value = getattr(obj, name, None)
    if value is None and isinstance(obj, dict):
        value = obj.get(name)
    return value


def _nested(obj: Any, outer: str, inner: str) -> Any:
    return _get(_get(obj, outer) or {}, inner)


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0
