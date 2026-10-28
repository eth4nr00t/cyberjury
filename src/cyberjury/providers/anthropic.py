"""A provider backed by the Anthropic Messages API."""

from __future__ import annotations

from typing import Any

from cyberjury.providers.base import (
    REQUEST_TIMEOUT_SECONDS,
    CompletionResult,
    Provider,
    ResponseSchema,
    Usage,
)

DEFAULT_BASE_URL = "https://api.anthropic.com"


class AnthropicProvider(Provider):
    """Anthropic Messages backend with model-specific temperature handling."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        client: Any | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store Anthropic connection settings without constructing the client eagerly."""
        self._api_key = api_key
        self._base_url = base_url
        self._client = client
        self._temperature: float | None = 0.0
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(
                api_key=self._api_key, base_url=self._base_url or DEFAULT_BASE_URL, max_retries=0
            )
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
        """Send one Messages API request with cached system and prefix blocks, and return its text and usage."""
        request: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "timeout": self._timeout,
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": _user_content(prompt, cache_prefix, cache_segments)}],
            "output_config": {"format": {"type": "json_schema", "schema": response_schema.schema}},
        }
        response = self._create(request)
        return CompletionResult(text=_extract_text(response), usage=_extract_usage(response))

    def _create(self, request: dict[str, Any]) -> Any:
        client = self._get_client()
        if self._temperature is None:
            return client.messages.create(**request)
        try:
            return client.messages.create(temperature=self._temperature, **request)
        except Exception as exc:
            if not _is_temperature_rejected(exc):
                raise
            self._temperature = None
            return client.messages.create(**request)


def _user_content(prompt: str, cache_prefix: str, cache_segments: tuple[str, ...]) -> str | list[dict]:
    if not cache_prefix:
        return prompt
    blocks: list[dict] = [{"type": "text", "text": text} for text in (cache_prefix, *cache_segments)]
    blocks[0]["cache_control"] = blocks[-1]["cache_control"] = {"type": "ephemeral"}
    remainder = prompt[len(cache_prefix) + sum(len(segment) for segment in cache_segments) :]
    if remainder:
        blocks.append({"type": "text", "text": remainder})
    return blocks


def _is_temperature_rejected(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    if status != 400 and "BadRequest" not in type(exc).__name__:
        return False
    return "temperature" in str(exc).lower()


def _extract_usage(response: Any) -> Usage:
    u = getattr(response, "usage", None)
    if u is None:
        return Usage()
    return Usage(
        input_tokens=_int_attr(u, "input_tokens"),
        output_tokens=_int_attr(u, "output_tokens"),
        cache_read_tokens=_int_attr(u, "cache_read_input_tokens"),
        cache_write_tokens=_int_attr(u, "cache_creation_input_tokens"),
    )


def _int_attr(obj: Any, name: str) -> int:
    value = getattr(obj, name, None)
    return int(value) if isinstance(value, (int, float)) else 0


def _extract_text(response: Any) -> str:
    return "".join(text for block in response.content if (text := getattr(block, "text", None)))
