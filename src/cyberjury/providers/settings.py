"""Named network, retry, and wire defaults shared by provider adapters."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderSettings:
    """Keep retry counts in operator terms while adapters use total attempts."""

    request_timeout_seconds: float = 240.0
    retries_after_failure: int = 2
    retry_initial_delay_seconds: float = 1.0
    retry_max_delay_seconds: float = 60.0
    openai_responses_min_output_token_budget: int = 8_000


DEFAULT_PROVIDER_SETTINGS = ProviderSettings()
