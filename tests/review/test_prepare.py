"""The shared prepare stage extracts facts loudly and grounds every planned unit against them."""

import pytest

from cyberjury.review import prepare
from cyberjury.review.detection import load_detection
from cyberjury.review.facts import Facts
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.selection import FileSelection
from cyberjury.sources.snapshot import capture_source_snapshot


def test_extract_facts_fails_loud_when_extraction_fails(tmp_path, monkeypatch):
    """A syntax extractor raising "parser missing" surfaces as BackendUnavailable "no grounding: ..."."""

    def broken(*_args):
        raise RuntimeError("parser missing")

    monkeypatch.setattr(prepare, "extract_syntax_facts", broken)
    selection = FileSelection(review_files=(), navigation_files=(), skipped_files=())

    with pytest.raises(BackendUnavailable, match="no grounding: parser missing"):
        prepare.extract_facts(capture_source_snapshot(tmp_path), selection, load_detection())


def test_prepare_grounds_units_with_the_extracted_facts(tmp_path, monkeypatch):
    """Stubbed facts for app.py become the unit's fenced syntax hints and the grounding receipt matches."""
    calls = []

    def extract(root, files, navigation_files, detection):
        calls.append(root)
        return Facts(by_file={"app.py": "def f():\n    return 1"})

    monkeypatch.setattr(prepare, "extract_syntax_facts", extract)
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")

    res = prepare_repository_review(capture_source_snapshot(tmp_path))

    assert len(calls) == 1
    assert [unit.grounding.syntax_hints for unit in res.units] == [
        "app.py: syntax hints (unverified, cite only delivered source):\n```\ndef f():\n    return 1\n```"
    ]
    assert [record.unit_id for record in res.grounding.contexts] == [unit.id for unit in res.units]
    assert res.grounding.unit_plan_receipt_sha256 == res.unit_plan.receipt_sha256
