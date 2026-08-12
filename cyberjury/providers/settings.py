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

    def __post_init__(self) -> None:
        """Reject invalid request and retry settings before provider construction."""
        values = {
            "request_timeout_seconds": self.request_timeout_seconds,
            "retry_initial_delay_seconds": self.retry_initial_delay_seconds,
            "retry_max_delay_seconds": self.retry_max_delay_seconds,
            "openai_responses_min_output_token_budget": self.openai_responses_min_output_token_budget,
        }
        invalid = [name for name, value in values.items() if value <= 0]
        if self.retries_after_failure < 0:
            invalid.append("retries_after_failure")
        if invalid:
            raise ValueError(f"provider settings are invalid: {', '.join(invalid)}")
        if self.retry_initial_delay_seconds > self.retry_max_delay_seconds:
            raise ValueError("retry_initial_delay_seconds cannot exceed retry_max_delay_seconds")


DEFAULT_PROVIDER_SETTINGS = ProviderSettings()
