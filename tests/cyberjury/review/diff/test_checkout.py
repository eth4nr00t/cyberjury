"""The shared checkout Diff Review owns grounding, seats, verification, and source binding."""

from __future__ import annotations

import json

import pytest

from cyberjury.profiles.registry import default_profile
from cyberjury.providers import configuration as configuration_module
from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff import checkout
from cyberjury.review.diff.checkout import DRY_RUN_SEAT, DiffCheckoutHooks, review_diff_checkout
from cyberjury.review.seats import provider_seat_id

_EMPTY_REPLY = json.dumps({"findings": [], "evidence_requests": [], "source_queries": []})


def _patch(path: str, before: str, after: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{before}\n+{after}\n"


def _configuration(*, skeptic: str = "finder", confirmer: str = "finder") -> ProviderConfiguration:
    finder = ProviderSeat(provider="openai", model="finder", api_key="key")
    return ProviderConfiguration(
        base=finder,
        finder=finder,
        skeptic=ProviderSeat(provider="openai", model=skeptic, api_key="key"),
        confirmer=ProviderSeat(provider="openai", model=confirmer, api_key="key"),
        retries=0,
        timeout=10,
    )


def test_dry_run_publishes_grounding_receipts_before_review_and_skips_verification(tmp_path):
    (tmp_path / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("After\n", encoding="utf-8")
    diff = _patch("app.py", "def run():", "def run(name):") + _patch("README.md", "Before", "After")
    events = []

    review = review_diff_checkout(
        diff,
        root=tmp_path,
        profile=default_profile(),
        configuration=_configuration(),
        meter=UsageMeter(),
        concurrency=2,
        dry_run_provider=MockProvider(default=_EMPTY_REPLY),
        hooks=DiffCheckoutHooks(
            on_skipped=lambda paths: events.append(("skipped", paths)),
            on_grounded=lambda receipts: events.append(("grounded", receipts.review_paths)),
            on_reviewed=lambda result: events.append(("reviewed", result.verification_records)),
        ),
    )

    assert events == [("skipped", ("README.md",)), ("grounded", ("app.py",)), ("reviewed", [])]
    assert review.finder_model == DRY_RUN_SEAT.model
    assert review.source_snapshot.root == tmp_path.resolve()
    assert review.receipts.grounding.unit_plan_receipt_sha256 == review.receipts.unit_plan.receipt_sha256
    assert review.result.outcome.degraded is False


def test_scoped_review_extracts_facts_from_the_scope_and_keeps_repository_paths(tmp_path):
    scope = tmp_path / "backend"
    scope.mkdir()
    (scope / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")

    review = review_diff_checkout(
        _patch("backend/app.py", "def run():", "def run(name):"),
        root=tmp_path,
        scope=scope,
        profile=default_profile(),
        configuration=_configuration(),
        meter=UsageMeter(),
        concurrency=1,
        dry_run_provider=MockProvider(default=_EMPTY_REPLY),
    )

    assert review.receipts.review_paths == ("backend/app.py",)
    assert review.source_snapshot.root == tmp_path.resolve()
    assert review.source_snapshot.matches_files(("backend/app.py",))


def test_configured_seats_own_found_by_labels_and_independent_confirmers(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")
    monkeypatch.setattr(configuration_module, "make_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    seen = {}
    original = checkout.run_diff_review

    def capture(diff, *, provider, model, finder_label, options):
        seen["model"] = model
        seen["finder_label"] = finder_label
        seen["options"] = options
        return original(
            diff,
            provider=MockProvider(default=_EMPTY_REPLY),
            model=model,
            finder_label=finder_label,
            options=options,
        )

    monkeypatch.setattr(checkout, "run_diff_review", capture)
    configuration = _configuration(skeptic="skeptic", confirmer="confirmer")

    review_diff_checkout(
        _patch("app.py", "def run():", "def run(name):"),
        root=tmp_path,
        profile=default_profile(),
        configuration=configuration,
        meter=UsageMeter(),
        concurrency=3,
        verification_concurrency=2,
    )

    options = seen["options"]
    finder_id = provider_seat_id(configuration.finder)
    assert seen["model"] == "finder"
    assert seen["finder_label"] == finder_id
    assert options.verification.found_by == (finder_id,)
    assert [label for label, _checker in options.verification.confirmers] == [
        provider_seat_id(configuration.confirmer),
    ]
    assert options.verification.verifier is not None
    assert options.verification.root == str(tmp_path)
    assert options.verification.concurrency == 2
    assert options.execution.concurrency == 3


def test_source_drift_during_review_fails_after_review_decisions_are_published(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def run(name):\n    return name\n", encoding="utf-8")
    reviewed = []

    def mutate(result):
        reviewed.append(result)
        source.write_text("def run(name):\n    return name.upper()\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="diff source changed while the review was running"):
        review_diff_checkout(
            _patch("app.py", "def run():", "def run(name):"),
            root=tmp_path,
            profile=default_profile(),
            configuration=_configuration(),
            meter=UsageMeter(),
            concurrency=1,
            dry_run_provider=MockProvider(default=_EMPTY_REPLY),
            hooks=DiffCheckoutHooks(on_reviewed=mutate),
        )
    assert len(reviewed) == 1
