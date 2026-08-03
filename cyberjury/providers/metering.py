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

    model_requests: int = 0
    uncached_input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def add(self, result: CompletionResult) -> None:
        u = result.usage
        with self._lock:
            self.model_requests += 1
            self.uncached_input_tokens += u.input_tokens
            self.output_tokens += u.output_tokens
            self.cache_read_tokens += u.cache_read_tokens
            self.cache_write_tokens += u.cache_write_tokens

    def snapshot(self) -> dict[str, int]:
        """The totals as plain data, so a run can persist them and not only print them.

        `total_input_tokens` is derived because comparing two runs on the uncached count alone
        reads a cache hit as a saving the request never made."""
        with self._lock:
            return {
                "model_requests": self.model_requests,
                "total_input_tokens": self.uncached_input_tokens + self.cache_read_tokens + self.cache_write_tokens,
                "uncached_input_tokens": self.uncached_input_tokens,
                "cache_read_tokens": self.cache_read_tokens,
                "cache_write_tokens": self.cache_write_tokens,
                "output_tokens": self.output_tokens,
            }

    def summary(self) -> str:
        s = self.snapshot()
        return (
            f"tokens over {s['model_requests']} model requests: "
            f"total_input={s['total_input_tokens']} uncached={s['uncached_input_tokens']} "
            f"cache_read={s['cache_read_tokens']} cache_write={s['cache_write_tokens']} "
            f"output={s['output_tokens']}"
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
