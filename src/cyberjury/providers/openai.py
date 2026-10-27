"""A provider backed by the OpenAI Responses API."""

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
        api_base: str | None = None,
        client: Any | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store OpenAI connection settings without constructing the client eagerly."""
        self._api_base = api_base
        self._client = client
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            import openai

            kwargs: dict[str, Any] = {"max_retries": 0}
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
        response_schema: ResponseSchema,
        cache_prefix: str = "",
        cache_segments: tuple[str, ...] = (),
    ) -> CompletionResult:
        """Call the Responses API and return one completion with its usage."""
        response = self._get_client().responses.create(
            model=model,
            instructions=system,
            input=[{"role": message.role, "content": message.content} for message in messages],
            max_output_tokens=max(max_tokens, _RESPONSES_MIN_OUTPUT_TOKENS),
            timeout=self._timeout,
            prompt_cache_key=hashlib.sha256(f"{system}\x00{cache_prefix}".encode()).hexdigest()[:32],
            text={
                "format": {
                    "type": "json_schema",
                    "name": response_schema.name,
                    "strict": True,
                    "schema": response_schema.schema,
                }
            },
        )
        status = getattr(response, "status", "completed")
        if status != "completed":
            raise RuntimeError(f"response did not complete: {status}")
        return CompletionResult(text=getattr(response, "output_text", "") or "", usage=_responses_usage(response))


def _responses_usage(response: Any) -> Usage:
    u = getattr(response, "usage", None)
    if u is None:
        return Usage()
    details = getattr(u, "input_tokens_details", None)
    cached = _int(getattr(details, "cached_tokens", None))
    written = _int(getattr(details, "cache_write_tokens", None))
    return Usage(
        input_tokens=max(_int(getattr(u, "input_tokens", None)) - cached - written, 0),
        output_tokens=_int(getattr(u, "output_tokens", None)),
        cache_read_tokens=cached,
        cache_write_tokens=written,
    )


def _int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0
