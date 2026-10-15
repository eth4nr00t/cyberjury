"""Tests for the shared facts contract and extraction boundary."""

import pytest

from cyberjury.review.facts import (
    BackendUnavailable,
    FactLimitation,
    Facts,
    FactsBackend,
    extract_facts,
    normalize_fact_limitations,
)


class _Backend(FactsBackend):
    def __init__(self, *, result=None):
        self._result = result if result is not None else Facts(summary="facts")

    def extract(self, root):
        return self._result


def test_extract_facts_without_a_backend_is_empty():
    assert extract_facts(None, ".").empty


def test_extract_facts_fails_loud_when_extraction_fails():
    class BrokenBackend(_Backend):
        def extract(self, root):
            raise RuntimeError("parser missing")

    with pytest.raises(BackendUnavailable, match="no grounding: parser missing"):
        extract_facts(BrokenBackend(), ".", purpose="test")


def test_extract_facts_rejects_a_non_facts_result():
    with pytest.raises(BackendUnavailable, match="invalid result"):
        extract_facts(_Backend(result={}), ".")


def test_facts_with_source_limitations_are_usable_but_incomplete():
    limitation = FactLimitation(source="app.py", analyzer="python", reason="unparsable", line=2, column=4)
    facts = Facts(limitations=(limitation,))

    assert facts.empty is False
    assert facts.complete is False
    assert limitation.identity == "facts:app.py:2:4"


def test_fact_limitations_reject_partial_locations_and_duplicate_identities():
    with pytest.raises(BackendUnavailable, match="line and column together"):
        normalize_fact_limitations([{"source": "app.py", "analyzer": "python", "reason": "parse", "line": 2}])
    record = {"source": "app.py", "analyzer": "python", "reason": "parse"}
    with pytest.raises(BackendUnavailable, match="unique locations"):
        normalize_fact_limitations([record, record])


def test_extract_facts_validates_backend_source_limitations():
    malformed = FactLimitation(source="app.py", analyzer="python", reason="parse", line=2)

    with pytest.raises(BackendUnavailable, match="line and column together"):
        extract_facts(_Backend(result=Facts(limitations=(malformed,))), ".")


def test_extract_facts_copies_backend_payload_data():
    payload = {"by_file": {"app.py": "facts"}}

    facts = extract_facts(_Backend(result=Facts(data=payload)), ".")
    payload["by_file"]["app.py"] = "changed"

    assert facts.data["by_file"]["app.py"] == "facts"
    with pytest.raises(TypeError, match="immutable"):
        facts.data["by_file"]["app.py"] = "consumer change"


def test_extract_facts_rejects_malformed_shared_payload_fields():
    with pytest.raises(BackendUnavailable, match="per-file facts"):
        extract_facts(_Backend(result=Facts(data={"by_file": {"app.py": 7}})), ".")
