"""MockProvider: a Provider that returns canned text instead of calling a model.

Used for the end-to-end dry-run and for tests, so the pipeline can run with no API key
and deterministic output. It holds no parsing or audit logic: it returns whatever text
it was configured with and records each call for inspection.
"""

from __future__ import annotations

from cyberjury.providers.base import CompletionResult, Message, Provider


class MockProvider(Provider):
    """Deterministic provider used by tests and dry runs."""

    def __init__(self, *, responses: list[str] | None = None, default: str = "") -> None:
        """Copy canned responses so each test consumes its own queue."""
        self._responses = list(responses or [])
        self._default = default
        self.calls: list[dict] = []

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
        self.calls.append(
            {
                "system": system,
                "messages": messages,
                "model": model,
                "cache": cache,
                "cache_prefix": cache_prefix,
                "max_tokens": max_tokens,
            }
        )
        text = self._responses.pop(0) if self._responses else self._default
        return CompletionResult(text=text)
