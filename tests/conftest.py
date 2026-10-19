"""Product tests run without the developer's model seat and SDK credential environment."""

import os

import pytest


@pytest.fixture(autouse=True)
def _hermetic_provider_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
