"""Diff preparation owns skipped files, planning, grounding, and receipts before any model work."""

from __future__ import annotations

import json

import pytest

from cyberjury.providers.configuration import ProviderConfiguration, ProviderSeat
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review import prepare
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.diff.prepare import prepare_diff_review
from cyberjury.review.run import run_review
from cyberjury.review.seats import DRY_RUN_SEAT, provider_seat_id, review_seats
from cyberjury.sources.snapshot import capture_source_snapshot

_EMPTY_REPLY = json.dumps({"findings": [], "evidence_requests": [], "source_queries": []})


def _patch(path: str, before: str, after: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{before}\n+{after}\n"


def _configuration() -> ProviderConfiguration:
    finder = ProviderSeat(provider="openai", model="finder", api_key="key")
    return ProviderConfiguration(base=finder, finder=finder, skeptic=finder, confirmer=finder, retries=0, timeout=10)


def test_dry_run_review_binds_receipts_skips_noise_and_verification(tmp_path):
    (tmp_path / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("After\n", encoding="utf-8")
    diff = _patch("app.py", "def run():", "def run(name):") + _patch("README.md", "Before", "After")
    seats = review_seats(_configuration(), meter=UsageMeter(), dry_run_provider=MockProvider(default=_EMPTY_REPLY))

    prepared = prepare_diff_review(diff, capture_source_snapshot(tmp_path))
    result = run_review(prepared, target=DIFF_TARGET, seats=seats, concurrency=2, verification_concurrency=2)

    assert [item.to_dict() for item in prepared.skipped_files] == [{"path": "README.md", "reason": "noise"}]
    assert prepared.shared.root == tmp_path.resolve()
    assert prepared.unit_plan.expected_owned_paths == ("app.py",)
    assert prepared.grounding.unit_plan_receipt_sha256 == prepared.unit_plan.receipt_sha256
    assert seats.finder_label == provider_seat_id(DRY_RUN_SEAT)
    assert seats.verifier is None
    assert result.verification.records == []
    assert result.outcome.complete is True


@pytest.mark.parametrize(
    ("section", "reason"),
    [
        ("diff --git a/old.py b/new.py\nsimilarity index 100%\nrename from old.py\nrename to new.py\n", "rename_only"),
        ("diff --git a/new.py b/new.py\nold mode 100644\nnew mode 100755\n", "mode_only"),
        ("diff --git a/new.py b/new.py\nnew file mode 100644\nindex 0000000..e69de29\n", "empty_new_file"),
        ("diff --git a/new.py b/new.py\ndeleted file mode 100644\nindex e69de29..0000000\n", "empty_deleted_file"),
    ],
)
def test_file_sections_without_a_hunk_are_skipped_without_review_units(tmp_path, section, reason):
    (tmp_path / "new.py").write_text("def run():\n    return True\n", encoding="utf-8")

    prepared = prepare_diff_review(section, capture_source_snapshot(tmp_path))

    assert [item.to_dict() for item in prepared.skipped_files] == [{"path": "new.py", "reason": reason}]
    assert prepared.units == ()
    assert prepared.unit_plan.units == ()


def test_nonempty_input_without_a_diff_hunk_fails_before_facts_extraction(tmp_path, monkeypatch):
    def unexpected_facts(*args, **kwargs):
        raise AssertionError("facts extraction must not run for invalid input")

    monkeypatch.setattr(prepare, "extract_syntax_facts", unexpected_facts)

    with pytest.raises(ValueError, match="no unified diff hunk"):
        prepare_diff_review("ordinary text", capture_source_snapshot(tmp_path))
