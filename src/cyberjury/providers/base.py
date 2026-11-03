"""Provider ABC and its typed input/output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

REQUEST_TIMEOUT_SECONDS = 240.0


class ProviderAccessError(RuntimeError):
    """The provider rejected the credentials, the permission, or the model of a request, so no retry can succeed."""

    def __init__(self, message: str, *, attempts: int = 1) -> None:
        """Keep the rejection message and the attempts spent before the rejection."""
        super().__init__(message)
        self.attempts = attempts


class ProviderCallError(RuntimeError):
    """A provider call still failed on its last attempt, and the error records how many attempts it took."""

    def __init__(self, message: str, *, attempts: int) -> None:
        """Keep the failure message and the attempts spent before giving up."""
        super().__init__(message)
        self.attempts = attempts


@dataclass(frozen=True, kw_only=True)
class Usage:
    """Token counts for one call, where input_tokens is uncached input and cache reads and writes are separate."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


def token_count(value: object) -> int:
    """Read one SDK usage counter as an integer, treating a missing or non-numeric value as zero."""
    return int(value) if isinstance(value, (int, float)) else 0


@dataclass(frozen=True, kw_only=True)
class CompletionResult:
    """Provider text plus token usage reported for the call."""

    text: str
    usage: Usage = field(default_factory=Usage)
    attempts: int = 1


@dataclass(frozen=True, kw_only=True)
class ResponseSchema:
    """One provider-neutral strict JSON output contract."""

    name: str
    schema: dict[str, object]


class Provider(ABC):
    """Common provider interface used by both review paths."""

    @abstractmethod
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
        """Complete a prompt that starts with cache_prefix and then each cache segment, under the response schema."""
