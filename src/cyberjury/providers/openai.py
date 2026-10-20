"""OpenAIProvider: Provider backed by the OpenAI Responses API.

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

_RESPONSES_MIN_OUTPUT_TOKENS = 8_000


class OpenAIProvider(Provider):
    """OpenAI backend for Responses API calls."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store OpenAI connection settings without constructing the client eagerly."""
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
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
        cache_segments: tuple[str, ...] = (),
        response_schema: ResponseSchema | None = None,
    ) -> CompletionResult:
        """Call the Responses API and return one completion with its usage.

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
            **_routing_hint(cache, system, cache_prefix),
            **output_format,
        )
        status = getattr(response, "status", "completed")
        if status != "completed":
            raise RuntimeError(f"response did not complete: {status}")
        return CompletionResult(text=getattr(response, "output_text", "") or "", usage=_responses_usage(response))


def _routing_hint(cache: bool, system: str, cache_prefix: str) -> dict[str, str]:
    if not cache:
        return {}
    material = f"{system}\x00{cache_prefix}".encode()
    return {"prompt_cache_key": hashlib.sha256(material).hexdigest()[:32]}


def _responses_usage(response: Any) -> Usage:
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
