"""Provider ABC and its typed input/output.

Deliberately minimal: one synchronous, non-streaming ``complete``. Streaming and
tool-calling are intentionally left out until a concrete need appears, so the
interface does not over-commit early.

``cache`` is a portable hint, not a guarantee. Anthropic maps it to a native
``cache_control`` breakpoint, OpenAI ignores it and caches long prefixes
automatically, LiteLLM depends on the backend. Each provider decides how to map
the hint onto its own implementation.

``cache_prefix``, when given, is the leading substring of the first user message
that stays constant across calls. A provider that caches explicitly marks the
breakpoint there, so the large reused block is what gets cached, not only the
short system prompt.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["user", "assistant"]


@dataclass(frozen=True, kw_only=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, kw_only=True)
class Usage:
    """Token counts for one call, normalized across providers so a cache change can be measured
    rather than assumed. `cache_read_tokens` bill cheap, `cache_write_tokens` carry the write
    premium, `input_tokens` is the uncached remainder. A field a provider does not report stays 0."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass(frozen=True, kw_only=True)
class CompletionResult:
    text: str
    usage: Usage = field(default_factory=Usage)


class Provider(ABC):
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
    ) -> CompletionResult: ...
