"""Token accounting across a whole run, so a repository review can report where the tokens went
without threading usage through every reviewer and verifier return value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from cyberjury.providers.base import CompletionResult, Message, Provider


@dataclass
class UsageMeter:
    """Running token totals for one run. Guarded by a lock since the fan-out records concurrently."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def add(self, result: CompletionResult) -> None:
        u = result.usage
        with self._lock:
            self.calls += 1
            self.input_tokens += u.input_tokens
            self.output_tokens += u.output_tokens
            self.cache_read_tokens += u.cache_read_tokens
            self.cache_write_tokens += u.cache_write_tokens

    def summary(self) -> str:
        return (
            f"tokens over {self.calls} model calls: input={self.input_tokens} "
            f"output={self.output_tokens} cache_read={self.cache_read_tokens} "
            f"cache_write={self.cache_write_tokens}"
        )


class MeteringProvider(Provider):
    """Record each wrapped call's usage into the shared meter. A backend that reports no usage, such
    as the subscription agent, adds zeros, so the total reflects the metered seats and never blocks."""

    def __init__(self, inner: Provider, meter: UsageMeter) -> None:
        self._inner = inner
        self._meter = meter

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
        result = self._inner.complete(
            system=system, messages=messages, model=model, max_tokens=max_tokens, cache=cache, cache_prefix=cache_prefix
        )
        self._meter.add(result)
        return result

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()
