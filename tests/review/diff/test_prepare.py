"""Diff preparation owns skipped files, planning, grounding, and receipts before any model work."""

from __future__ import annotations

import pytest

from cyberjury.review import prepare
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.diff.prepare import prepare_diff_review
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.result import SkippedFiles
from cyberjury.review.seats import ReviewSeats
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.diff.support import reply
from tests.review.support import StubIssueJudge, bound_artifacts, recorder, run_prepared
from tests.support import MockProvider


def _patch(path: str, before: str, after: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{before}\n+{after}\n"


def _prepare(diff: str, root):
    stages = recorder()
    artifacts = bound_artifacts(stages)
    return prepare_diff_review(diff, capture_source_snapshot(root), recorder=stages), artifacts


def test_diff_review_binds_receipts_and_skips_noise(tmp_path):
    """README.md is skipped as noise, app.py is planned with a matching receipt, and the review completes."""
    (tmp_path / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("After\n", encoding="utf-8")
    diff = _patch("app.py", "def run():", "def run(name):") + _patch("README.md", "Before", "After")

    prepared, artifacts = _prepare(diff, tmp_path)
    seats = ReviewSeats(finder=MockProvider(default=reply([])), finder_model="m", issue_judge=StubIssueJudge())
    result = run_prepared(prepared, target=DIFF_TARGET, seats=seats, concurrency=2)

    assert [item.to_dict() for item in artifacts[SkippedFiles].files] == [{"path": "README.md", "reason": "noise"}]
    assert prepared.shared.root == tmp_path.resolve()
    assert [unit.paths for unit in prepared.units] == [("app.py",)]
    assert artifacts[GroundingReceipt].unit_plan_receipt_sha256 == artifacts[UnitPlanReceipt].receipt_sha256
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
    """Rename, mode, and empty new or deleted file sections record their skip reason and plan no units."""
    (tmp_path / "new.py").write_text("def run():\n    return True\n", encoding="utf-8")

    prepared, artifacts = _prepare(section, tmp_path)

    assert [item.to_dict() for item in artifacts[SkippedFiles].files] == [{"path": "new.py", "reason": reason}]
    assert prepared.units == ()
    assert artifacts[UnitPlanReceipt].units == ()


def test_a_diff_of_only_skipped_files_plans_no_units_without_facts_extraction(tmp_path, monkeypatch):
    """A diff touching only README.md records it as noise and plans no units without extracting syntax facts."""
    (tmp_path / "app.py").write_text("def run():\n    return True\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("After\n", encoding="utf-8")

    def unexpected_facts(*args, **kwargs):
        raise AssertionError("facts extraction must not run when no file is reviewable")

    monkeypatch.setattr(prepare, "extract_syntax_facts", unexpected_facts)

    prepared, artifacts = _prepare(_patch("README.md", "Before", "After"), tmp_path)

    assert [item.to_dict() for item in artifacts[SkippedFiles].files] == [{"path": "README.md", "reason": "noise"}]
    assert prepared.units == ()
