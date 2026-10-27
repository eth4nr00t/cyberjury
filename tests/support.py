"""Builders shared by every test package."""

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from cyberjury.providers.base import CompletionResult, Provider, ResponseSchema

EMPTY_SCHEMA = ResponseSchema(
    name="reply", schema={"type": "object", "additionalProperties": False, "properties": {}, "required": []}
)


def git(cwd: Path, *args: str) -> str:
    """Run one git command with a fixed test identity and return its trimmed output."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


type MockResponder = Callable[[str, str], str]


class MockProvider(Provider):
    """Deterministic provider that returns canned replies instead of calling a model."""

    def __init__(
        self,
        *,
        responses: list[str] | None = None,
        default: str = "",
        responder: MockResponder | None = None,
    ) -> None:
        """Copy canned responses so each test consumes its own queue."""
        self._responses = list(responses or [])
        self._default = default
        self._responder = responder
        self.calls: list[dict] = []

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
        """Record the call and return the next canned, responder, or default text."""
        self.calls.append(
            {
                "system": system,
                "prompt": prompt,
                "model": model,
                "cache_prefix": cache_prefix,
                "cache_segments": cache_segments,
                "response_schema": response_schema,
            }
        )
        text = (
            self._responses.pop(0)
            if self._responses
            else self._responder(system, prompt)
            if self._responder is not None
            else self._default
        )
        return CompletionResult(text=text)
