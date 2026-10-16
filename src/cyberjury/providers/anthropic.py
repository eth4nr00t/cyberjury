"""AnthropicProvider: Provider backed by the Anthropic Messages API.

``cache`` marks an ephemeral cache_control breakpoint on the system prompt, which holds
the review contract shared by every call of a run. ``cache_prefix`` adds a second
breakpoint by splitting the first user message after its stable evidence block, so the
follow ups of one unit reuse that evidence. The Anthropic client is injectable so the
mapping and caching logic can be tested without the SDK or an API key. Constructed
lazily otherwise, reading ANTHROPIC_API_KEY from the environment.
"""

from __future__ import annotations

from typing import Any

from cyberjury.providers.base import (
    REQUEST_TIMEOUT_SECONDS,
    CompletionResult,
    Message,
    Provider,
    ResponseSchema,
    Usage,
)


class AnthropicProvider(Provider):
    """Anthropic Messages backend with model-specific temperature handling."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        temperature: float | None = 0.0,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Store Anthropic connection settings without constructing the client eagerly."""
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        self._temperature = temperature
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "anthropic not installed, it is a base dependency, run: pip install cyberjury"
                ) from exc
            kwargs: dict[str, Any] = {"max_retries": 0}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._api_base:
                kwargs["base_url"] = self._api_base
            self._client = anthropic.Anthropic(**kwargs)
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
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        system_param: Any = system
        if cache:
            _mark_cache_prefix(api_messages, cache_prefix)
            if system:
                system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]

        request: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "timeout": self._timeout,
            "system": system_param,
            "messages": api_messages,
        }
        if response_schema is not None:
            request["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": response_schema.schema,
                }
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


def _mark_cache_prefix(api_messages: list[dict], cache_prefix: str) -> None:
    """The two split blocks concatenate back to the original content.

    The model reads the same prompt. A prefix that does not lead the first message leaves
    only the system breakpoint.
    """
    if not cache_prefix or not api_messages:
        return
    content = api_messages[0].get("content")
    if not isinstance(content, str) or not content.startswith(cache_prefix):
        return
    blocks: list[dict] = [{"type": "text", "text": cache_prefix, "cache_control": {"type": "ephemeral"}}]
    remainder = content[len(cache_prefix) :]
    if remainder:
        blocks.append({"type": "text", "text": remainder})
    api_messages[0]["content"] = blocks


def _is_temperature_rejected(exc: Exception) -> bool:
    """True when the API refused only because the model rejected temperature.

    That is the one error recovered from by dropping the field. Matched on the message, not
    a model name list, so a new reasoning model needs no code change.
    """
    status = getattr(exc, "status_code", None)
    if status != 400 and "BadRequest" not in type(exc).__name__:
        return False
    return "temperature" in str(exc).lower()


def _extract_usage(response: Any) -> Usage:
    """The token counts Anthropic reports for uncached input, cache write, and cache read.

    The split lets a run show whether the cached prefix is being hit.
    """
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
