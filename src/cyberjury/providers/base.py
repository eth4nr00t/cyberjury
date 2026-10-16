"""Provider ABC and its typed input/output.

Deliberately minimal: one synchronous, non-streaming ``complete``. Streaming and tool-
calling are intentionally left out until a concrete need appears, so the interface does
not over-commit early. ``cache`` is a portable hint, not a guarantee, that the system
prompt repeats across calls. Anthropic maps it to a native ``cache_control`` breakpoint.
OpenAI maps it to a routing key and relies on automatic prefix caching. ``cache_prefix``,
when given, is the leading substring of the first user message that stays constant
across calls, such as one review unit's evidence. A provider with explicit cache controls
marks a second breakpoint there, and a routing key covers the system prompt plus that
prefix.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["user", "assistant"]

REQUEST_TIMEOUT_SECONDS = 240.0


@dataclass(frozen=True, kw_only=True)
class Message:
    """One chat message passed to a provider backend."""

    role: Role
    content: str


@dataclass(frozen=True, kw_only=True)
class Usage:
    """Token counts for one call, normalized so cache changes are measured.

    `cache_read_tokens` bill cheap, `cache_write_tokens` carry the write premium, and
    `input_tokens` is the uncached remainder. A field a provider does not report stays 0.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass(frozen=True, kw_only=True)
class CompletionResult:
    """Provider text plus token usage reported for the call."""

    text: str
    usage: Usage = field(default_factory=Usage)
    attempts: int = 1


@dataclass(frozen=True, kw_only=True)
class ResponseSchema:
    """One provider neutral strict JSON output contract."""

    name: str
    schema: dict[str, object]

    def __post_init__(self) -> None:
        """Reject a schema that providers cannot name or apply."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.name):
            raise ValueError("response schema name is invalid")
        if (
            not isinstance(self.schema, dict)
            or self.schema.get("type") != "object"
            or self.schema.get("additionalProperties") is not False
        ):
            raise ValueError("response schema root must be a closed object")


class Provider(ABC):
    """Common provider interface used by both review paths."""

    @abstractmethod
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
