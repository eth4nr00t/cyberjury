"""The shared prepare stage extracts facts loudly and grounds every planned unit against them."""

import pytest

from cyberjury.review.facts import Facts
from cyberjury.review.failures import BackendUnavailableError
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.prepare import extract_facts
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.selection import FileSelection
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.snapshot import capture_source_snapshot
from tests.review.support import bound_artifacts, recorder
from tests.review.syntax.support import ignore_progress


def test_extract_facts_fails_loud_when_extraction_fails(tmp_path, monkeypatch):
    """A syntax extractor raising "parser missing" surfaces as BackendUnavailableError "no grounding: ..."."""

    def broken(*_args, **_kwargs):
        raise RuntimeError("parser missing")

    monkeypatch.setattr("cyberjury.review.prepare.extract_syntax_facts", broken)
    selection = FileSelection(review_files=(), navigation_files=(), skipped_files=())

    with pytest.raises(BackendUnavailableError, match="no grounding: parser missing"):
        extract_facts(capture_source_snapshot(tmp_path), selection, progress=ignore_progress)


def test_prepare_grounds_units_with_the_extracted_facts(tmp_path, monkeypatch):
    """Stubbed facts for app.py become the unit's fenced syntax hints and the grounding receipt matches."""
    calls = []

    def extract(root, files, *, progress):
        calls.append(root)
        return Facts(by_file={"app.py": "def f():\n    return 1"})

    monkeypatch.setattr("cyberjury.review.prepare.extract_syntax_facts", extract)
    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    stages = recorder()
    artifacts = bound_artifacts(stages)

    prepared = prepare_repository_review(capture_source_snapshot(tmp_path), recorder=stages)

    assert len(calls) == 1
    assert [unit.grounding.syntax_hints for unit in prepared.units] == [
        "app.py: syntax hints, unverified, cite only delivered source:\n```\ndef f():\n    return 1\n```"
    ]
    grounding, unit_plan = artifacts[GroundingReceipt], artifacts[UnitPlanReceipt]
    assert [record["unit_id"] for record in grounding.contexts] == [unit.id for unit in prepared.units]
    assert grounding.unit_plan_receipt_sha256 == unit_plan.receipt_sha256
