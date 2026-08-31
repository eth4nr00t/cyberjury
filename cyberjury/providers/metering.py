"""Token accounting across a run.

Repository Review can report where tokens went without threading usage through every
reviewer and verifier return value.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock

from cyberjury.providers.base import CompletionResult, Message, Provider, ProviderFingerprint


@dataclass
class UsageMeter:
    """Running token totals for one run.

    Guarded by a lock since the fan-out records concurrently.
    """

    model_requests: int = 0
    uncached_input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)

    def add(self, result: CompletionResult) -> None:
        """Add one completion usage record to the shared meter."""
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
        reads a cache hit as a saving the request never made.
        """
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
        """Return aggregate token usage for the run."""
        s = self.snapshot()
        return (
            f"tokens over {s['model_requests']} model requests: "
            f"total_input={s['total_input_tokens']} uncached={s['uncached_input_tokens']} "
            f"cache_read={s['cache_read_tokens']} cache_write={s['cache_write_tokens']} "
            f"output={s['output_tokens']}"
        )


class MeteringProvider(Provider):
    """Record each wrapped call's usage into the shared meter.

    A backend that reports no usage adds zeros, so the
    total reflects the metered seats and never blocks.
    """

    def __init__(self, inner: Provider, meter: UsageMeter) -> None:
        """Wrap one provider and share its usage totals with the run meter."""
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
        """Return one provider completion with optional usage accounting."""
        result = self._inner.complete(
            system=system, messages=messages, model=model, max_tokens=max_tokens, cache=cache, cache_prefix=cache_prefix
        )
        self._meter.add(result)
        return result

    def checkpoint_fingerprint(self) -> ProviderFingerprint:
        """Ignore metering state while preserving the wrapped provider identity."""
        return ProviderFingerprint(
            backend=f"{type(self).__module__}.{type(self).__qualname__}",
            inner=self._inner.checkpoint_fingerprint(),
        )

    def close(self) -> None:
        """Close the wrapped provider when it exposes a close hook."""
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()
