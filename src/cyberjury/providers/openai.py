"""A provider backed by the OpenAI Responses API."""

from __future__ import annotations

import hashlib
from typing import Any

from cyberjury.providers.base import (
    REQUEST_TIMEOUT_SECONDS,
    CompletionResult,
    Provider,
    ResponseSchema,
    Usage,
    token_count,
)

DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAIProvider(Provider):
    """OpenAI backend for Responses API calls."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        client: Any | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store OpenAI connection settings without constructing the client eagerly."""
        self._api_key = api_key
        self._base_url = base_url
        self._client = client
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            import openai

            self._client = openai.OpenAI(api_key=self._api_key, base_url=self._base_url, max_retries=0)
        return self._client

    def complete(
        self,
        *,
        system: str,
        prompt: str,
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
            input=[{"role": "user", "content": prompt}],
            max_output_tokens=max_tokens,
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
        return CompletionResult(text=getattr(response, "output_text", "") or "", usage=_usage(response))


def _usage(response: Any) -> Usage:
    usage = getattr(response, "usage", None)
    if usage is None:
        return Usage()
    details = getattr(usage, "input_tokens_details", None)
    cached = token_count(getattr(details, "cached_tokens", None))
    written = token_count(getattr(details, "cache_write_tokens", None))
    return Usage(
        input_tokens=max(token_count(getattr(usage, "input_tokens", None)) - cached - written, 0),
        output_tokens=token_count(getattr(usage, "output_tokens", None)),
        cache_read_tokens=cached,
        cache_write_tokens=written,
    )
