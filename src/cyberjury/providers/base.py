"""Provider ABC and its typed input/output."""

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
        cache_segments: tuple[str, ...] = (),
        response_schema: ResponseSchema | None = None,
    ) -> CompletionResult:
        """Return one provider completion with optional usage accounting."""
