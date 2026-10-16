"""Diff evaluation fixtures run the product review command against a scripted model."""

import json
import os
from types import SimpleNamespace

import pytest

from cyberjury import cli as climod
from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.mock import MockProvider


def _finder_reply(findings: list[dict]) -> str:
    return json.dumps({"findings": findings, "evidence_requests": [], "source_queries": []})


@pytest.fixture
def scripted_model(monkeypatch):
    """Serve every product seat from one scripted provider, with no environment file or real key."""
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(climod, "load_env_file", lambda: [])
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def install(findings=(), *, error: BaseException | None = None) -> MockProvider:
        def respond(system, _messages):
            if error is not None:
                raise error
            if "skeptical security reviewer" in system:
                return json.dumps(
                    {"real": True, "reason": "no shown fact refutes it", "control_file": "", "control_line": 0}
                )
            return _finder_reply([dict(item) for item in findings])

        provider = MockProvider(responder=respond)
        monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: provider)
        return provider

    return install


@pytest.fixture
def owner_finding():
    """One complete Finder finding on the benchmark diff's changed line."""
    return SimpleNamespace(
        reply={
            "title": "Create saves without an owner",
            "category": "missing-authorization",
            "severity": "HIGH",
            "entrypoint": "POST /create",
            "file": "views.py",
            "line": 2,
            "change_anchor": {"file": "views.py", "line": 2, "side": "new"},
            "evidence": "views.py:2 saves with owner=None",
            "attack_path": "anyone creates an unowned record",
            "evidence_refs": ["seed"],
        }
    )
