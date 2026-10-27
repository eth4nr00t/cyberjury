"""Provider ABC and its typed input/output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

Role = Literal["user", "assistant"]

REQUEST_TIMEOUT_SECONDS = 240.0


class ProviderAccessError(RuntimeError):
    """The provider rejected the credentials, the permission, or the model of a request, so no retry can succeed."""


@dataclass(frozen=True, kw_only=True)
class Message:
    """One chat message passed to a provider backend."""

    role: Role
    content: str


@dataclass(frozen=True, kw_only=True)
class Usage:
    """Token counts for one call, normalized so cache changes are measured."""

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
        response_schema: ResponseSchema,
        cache_prefix: str = "",
        cache_segments: tuple[str, ...] = (),
    ) -> CompletionResult:
        """Return one completion of the messages under the closed response schema."""
