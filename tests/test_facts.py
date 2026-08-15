"""Tests for the shared facts contract and extraction boundary."""

import pytest

from cyberjury.review.context import GroundingContext
from cyberjury.review.facts import (
    BackendUnavailable,
    Facts,
    FactsBackend,
    extract_facts,
    fact_unit_specs,
)


class _Backend(FactsBackend):
    def __init__(self, *, available=True, result=None):
        self._available = available
        self._result = result if result is not None else Facts(summary="facts")

    def available(self) -> bool:
        return self._available

    def extract(self, root):
        return self._result


def test_extract_facts_without_a_backend_is_empty():
    """An unbound profile has no extracted facts."""
    assert extract_facts(None, ".").empty


def test_extract_facts_fails_loud_when_backend_is_unavailable():
    """An unavailable bound backend is not reported as a clean review."""
    with pytest.raises(BackendUnavailable, match="no grounding"):
        extract_facts(_Backend(available=False), ".", purpose="test")


def test_extract_facts_rejects_a_non_facts_result():
    """A backend must return the shared Facts type."""
    with pytest.raises(BackendUnavailable, match="invalid result"):
        extract_facts(_Backend(result={}), ".")


def test_fact_unit_specs_uses_the_shared_output_key():
    """Focused unit specifications use one output key for every profile."""
    facts = Facts(data={"unit_specs": [{"name": "unit", "files": ["a.py"]}]})
    assert fact_unit_specs(facts) == [{"name": "unit", "files": ["a.py"]}]


def test_fact_unit_specs_rejects_a_non_list():
    """Malformed focused unit specifications fail loudly."""
    with pytest.raises(BackendUnavailable, match="unit specifications"):
        fact_unit_specs(Facts(data={"unit_specs": {}}))


def test_grounding_context_marks_its_source_boundary():
    """Shared context carries whether the prompt came from diff or repository input."""
    context = GroundingContext(text="source", files=("app.py",), source="diff")
    assert context.source == "diff"
    assert context.files == ("app.py",)
