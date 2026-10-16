"""Tests for the shared facts contract and extraction boundary."""

import pytest

from cyberjury.review import prepare
from cyberjury.review.facts import BackendUnavailable, FactLimitation, Facts, FactsReceipt
from cyberjury.selection import FileSelection
from cyberjury.sources.snapshot import capture_source_snapshot


def test_facts_receipt_binds_the_backend_and_its_evidence():
    first = FactsReceipt.create(backend_id="backend", facts=Facts(by_file={"a.py": "one"}))
    second = FactsReceipt.create(backend_id="backend", facts=Facts(by_file={"a.py": "two"}))

    assert first.to_dict()["schema"] == "cyberjury.facts/v3"
    assert first.receipt_sha256 != second.receipt_sha256


def test_extract_facts_fails_loud_when_extraction_fails(tmp_path, monkeypatch):
    def broken(*_args):
        raise RuntimeError("parser missing")

    monkeypatch.setattr(prepare, "extract_syntax_facts", broken)
    selection = FileSelection(review_files=(), navigation_files=(), skipped_files=())

    with pytest.raises(BackendUnavailable, match="no grounding: parser missing"):
        prepare.extract_facts(capture_source_snapshot(tmp_path), selection)


def test_fact_limitation_identity_names_its_location():
    limitation = FactLimitation(source="app.py", analyzer="python", reason="unparsable", line=2, column=4)

    assert limitation.identity == "facts:app.py:2:4"
    assert limitation.message == "app.py at 2:4: python unparsable"
