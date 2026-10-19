"""OpenAIProvider: Provider backed by the OpenAI API, Responses or Chat Completions.

The Responses API is the default. ``wire_api="chat"`` selects Chat Completions for
compatible endpoints that only serve that API.
With ``cache`` set, the system prompt and ``cache_prefix`` become one stable routing key so
every request that repeats that prefix can reuse the provider's automatic prefix cache.
The client is injectable so the mapping can be tested without the SDK or a key.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cyberjury.providers.base import (
    REQUEST_TIMEOUT_SECONDS,
    CompletionResult,
    Message,
    Provider,
    ResponseSchema,
    Usage,
)

WIRE_APIS = ("responses", "chat")
_RESPONSES_MIN_OUTPUT_TOKENS = 8_000


class OpenAIProvider(Provider):
    """OpenAI backend for chat completions and responses calls."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        wire_api: str | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store OpenAI connection settings without constructing the client eagerly."""
        if wire_api is not None and wire_api not in WIRE_APIS:
            raise ValueError(f"OpenAI wire API must be one of {', '.join(WIRE_APIS)}, got {wire_api!r}")
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        self._wire_api = wire_api or "responses"
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise RuntimeError("openai not installed, it is a base dependency, run: pip install cyberjury") from exc
            kwargs: dict[str, Any] = {"max_retries": 0}
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
        response_schema: ResponseSchema | None = None,
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
        routing = _routing_hint(cache, system, cache_prefix)
        if self._wire_api == "responses":
            return self._complete_responses(
                system=system,
                messages=messages,
                model=model,
                max_tokens=max_tokens,
                routing=routing,
                response_schema=response_schema,
            )
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages += [{"role": message.role, "content": message.content} for message in messages]

        output_format = (
            {
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": response_schema.name,
                        "strict": True,
                        "schema": response_schema.schema,
                    },
                }
            }
            if response_schema is not None
            else {}
        )
        response = self._get_client().chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
            temperature=0,
            timeout=self._timeout,
            **routing,
            **output_format,
        )
        choices = response.choices
        text = (choices[0].message.content or "") if choices else ""
        return CompletionResult(text=text, usage=_chat_usage(response))

    def _complete_responses(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        routing: dict[str, str],
        response_schema: ResponseSchema | None,
    ) -> CompletionResult:
        """The default Responses API path.

        The budget covers reasoning plus output, so it is generous: a budget too small yields
        empty output, which reads as an unusable reply upstream, never as a clean result.
        """
        output_format = (
            {
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": response_schema.name,
                        "strict": True,
                        "schema": response_schema.schema,
                    }
                }
            }
            if response_schema is not None
            else {}
        )
        response = self._get_client().responses.create(
            model=model,
            instructions=system or None,
            input=[{"role": message.role, "content": message.content} for message in messages],
            max_output_tokens=max(max_tokens, _RESPONSES_MIN_OUTPUT_TOKENS),
            timeout=self._timeout,
            **routing,
            **output_format,
        )
        status = getattr(response, "status", "completed")
        if status != "completed":
            raise RuntimeError(f"response did not complete: {status}")
        return CompletionResult(text=getattr(response, "output_text", "") or "", usage=_responses_usage(response))


def _routing_hint(cache: bool, system: str, cache_prefix: str) -> dict[str, str]:
    """Key on the exact stable prefix, the system prompt plus the reused message prefix.

    Every request that repeats that prefix, such as the initial call and the follow ups of
    one review unit, shares one key, and no request with a different prefix is routed with
    it. The digest is truncated because the key is only a routing label, not a lookup.
    """
    if not cache:
        return {}
    material = f"{system}\x00{cache_prefix}".encode()
    return {"prompt_cache_key": hashlib.sha256(material).hexdigest()[:32]}


def _chat_usage(response: Any) -> Usage:
    """The Chat Completions token counts.

    `prompt_tokens` already includes the cached read, so the uncached input is the
    remainder, and OpenAI reports the cache read under prompt_tokens_details.
    """
    return _usage(response, "prompt_tokens", "completion_tokens", "prompt_tokens_details")


def _responses_usage(response: Any) -> Usage:
    """The Responses API token counts, where input_tokens includes cache reads."""
    return _usage(response, "input_tokens", "output_tokens", "input_tokens_details")


def _usage(response: Any, input_field: str, output_field: str, details_field: str) -> Usage:
    u = getattr(response, "usage", None)
    if u is None:
        return Usage()
    details = getattr(u, details_field, None)
    cached = _int(getattr(details, "cached_tokens", None))
    written = _int(getattr(details, "cache_write_tokens", None))
    return Usage(
        input_tokens=max(_int(getattr(u, input_field, None)) - cached - written, 0),
        output_tokens=_int(getattr(u, output_field, None)),
        cache_read_tokens=cached,
        cache_write_tokens=written,
    )


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0
