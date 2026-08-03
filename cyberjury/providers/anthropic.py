"""AnthropicProvider: Provider backed by the Anthropic Messages API.

When ``cache`` is set, the system prompt is marked with an ephemeral
cache_control block. The system prompt carries the large security-knowledge
block reused across every review call, so caching it is the high-value target.

The Anthropic client is injectable so the mapping and caching logic can be
tested without the SDK or an API key. Constructed lazily otherwise, reading
ANTHROPIC_API_KEY from the environment.
"""

from __future__ import annotations

from typing import Any

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage


class AnthropicProvider(Provider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        temperature: float | None = 0.0,  # so the same input yields the same verdicts
        timeout: float = 240.0,
    ) -> None:
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        self._temperature = temperature
        # per-request deadline: a hung or rate-limit-stalled call returns to the retry layer
        # to back off, instead of holding the slot until a far longer ceiling
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "anthropic not installed, it is a base dependency, run: pip install cyberjury"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._api_base:
                # the anthropic SDK names this base_url
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
    ) -> CompletionResult:
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        system_param: Any = system
        if cache and _mark_cache_prefix(api_messages, cache_prefix):
            pass
        elif cache and system:
            system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]

        request: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "timeout": self._timeout,
            "system": system_param,
            "messages": api_messages,
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
            # drop it for this provider so later calls skip the rejected param, no wasted retry
            self._temperature = None
            return client.messages.create(**request)


def _mark_cache_prefix(api_messages: list[dict], cache_prefix: str) -> bool:
    """The two split blocks concatenate back to the original content, so the model reads the same
    prompt. Returns False when there is nothing to split, so the caller falls back to the system."""
    if not cache_prefix or not api_messages:
        return False
    content = api_messages[0].get("content")
    if not isinstance(content, str) or not content.startswith(cache_prefix):
        return False
    blocks: list[dict] = [{"type": "text", "text": cache_prefix, "cache_control": {"type": "ephemeral"}}]
    remainder = content[len(cache_prefix) :]
    if remainder:
        blocks.append({"type": "text", "text": remainder})
    api_messages[0]["content"] = blocks
    return True


def _is_temperature_rejected(exc: Exception) -> bool:
    """True when the API refused the call only because this model does not accept the
    temperature param, the one error recovered from by dropping it. Matched on the message,
    not a model name list, so a new reasoning model needs no code change."""
    status = getattr(exc, "status_code", None)
    if status != 400 and "BadRequest" not in type(exc).__name__:
        return False
    return "temperature" in str(exc).lower()


def _extract_usage(response: Any) -> Usage:
    """The token counts Anthropic reports separately for uncached input, cache write, and cache
    read, so a run can show whether the cached prefix is being hit."""
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
    if value is None and isinstance(obj, dict):
        value = obj.get(name)
    return int(value) if isinstance(value, (int, float)) else 0


def _extract_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return str(content or "")
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    return "".join(parts)
