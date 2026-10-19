"""Mock provider tests cover deterministic response routing."""

from cyberjury.providers.base import Message
from cyberjury.providers.mock import MockProvider


def test_responder_handles_calls_after_canned_responses_are_consumed():
    provider = MockProvider(
        responses=["first"],
        responder=lambda system, messages: f"{system}:{messages[-1].content}",
    )
    values = [
        provider.complete(
            system="system",
            messages=[Message(role="user", content="prompt")],
            model="model",
            max_tokens=10,
        ).text
        for _ in range(2)
    ]

    assert values == ["first", "system:prompt"]
