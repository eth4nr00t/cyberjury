"""Tests for the shared facts contract and extraction boundary."""

import pytest

from cyberjury.review.facts import (
    BackendUnavailable,
    FactLimitation,
    Facts,
    FactsBackend,
    extract_facts,
    fact_unit_specs,
    normalize_fact_limitations,
    pack_unit_specs,
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
    assert extract_facts(None, ".").empty


def test_extract_facts_fails_loud_when_backend_is_unavailable():
    with pytest.raises(BackendUnavailable, match="no grounding"):
        extract_facts(_Backend(available=False), ".", purpose="test")


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


def test_fact_unit_specs_uses_the_shared_output_key():
    facts = Facts(data={"unit_specs": [{"name": "unit", "files": ["a.py"]}]})
    assert fact_unit_specs(facts) == [{"name": "unit", "files": ["a.py"]}]


def test_fact_unit_specs_rejects_a_non_list():
    with pytest.raises(BackendUnavailable, match="unit specifications"):
        fact_unit_specs(Facts(data={"unit_specs": {}}))


def test_fact_unit_specs_rejects_a_zero_length_fragment():
    with pytest.raises(BackendUnavailable, match="invalid shape"):
        fact_unit_specs(Facts(data={"unit_specs": [{"fragments": [["a.py", 4, 4]]}]}))


@pytest.mark.parametrize("span", [[False, 10], [0.5, 10], ["0", 10], [-1, 10], [10, 10]])
def test_pack_unit_specs_rejects_malformed_function_ranges(span):
    records = {
        "Contract": {
            "file": "Contract.sol",
            "functions": {"withdraw": {"range": span, "calls": [], "risk": True}},
        }
    }

    with pytest.raises(BackendUnavailable, match="malformed function range"):
        pack_unit_specs(records, focus_flags=("risk",), max_source_chars=100)
