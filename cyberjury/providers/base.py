"""Provider ABC and its typed input/output.

Deliberately minimal: one synchronous, non-streaming ``complete``. Streaming and tool-
calling are intentionally left out until a concrete need appears, so the interface does
not over-commit early. ``cache`` is a portable hint, not a guarantee. Anthropic maps it
to a native ``cache_control`` breakpoint. OpenAI maps it to a routing key and relies on
automatic prefix caching. Each provider decides how to map the hint onto its own
implementation. ``cache_prefix``, when given, is the leading substring of the first
user message that stays constant across calls. A provider with explicit cache controls
marks the breakpoint there, so the large reused block is what gets cached, not only the
short system prompt.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["user", "assistant"]


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
class ProviderFingerprint:
    """Stable public provider configuration used by resumable work."""

    backend: str
    settings: tuple[tuple[str, str], ...] = ()
    inner: ProviderFingerprint | None = None

    def to_data(self) -> dict[str, object]:
        """Return deterministic JSON data without credentials or runtime state."""
        value: dict[str, object] = {
            "backend": self.backend,
            "settings": dict(self.settings),
        }
        if self.inner is not None:
            value["inner"] = self.inner.to_data()
        return value


class Provider(ABC):
    """Common provider interface used by both review paths."""

    def checkpoint_fingerprint(self) -> ProviderFingerprint:
        """Identify response affecting configuration for resumable model work."""
        return ProviderFingerprint(backend=f"{type(self).__module__}.{type(self).__qualname__}")

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
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
