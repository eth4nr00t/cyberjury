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
    facts = Facts(data={"unit_specs": [{"name": "unit", "fragments": [["a.py", 0, 10]]}]})
    assert fact_unit_specs(facts) == [{"name": "unit", "files": ["a.py"], "fragments": [("a.py", 0, 10)]}]


def test_fact_unit_specs_rejects_files_that_diverge_from_fragments():
    facts = Facts(
        data={"unit_specs": [{"name": "unit", "files": ["declared.py"], "fragments": [["actual.py", 0, 10]]}]}
    )

    with pytest.raises(BackendUnavailable, match="fragment file projection"):
        fact_unit_specs(facts)


def test_extract_facts_copies_backend_payload_data():
    payload = {"by_file": {"app.py": "facts"}}

    facts = extract_facts(_Backend(result=Facts(data=payload)), ".")
    payload["by_file"]["app.py"] = "changed"

    assert facts.data["by_file"]["app.py"] == "facts"
    with pytest.raises(TypeError, match="immutable"):
        facts.data["by_file"]["app.py"] = "consumer change"


def test_extract_facts_normalizes_capability_probe_failures():
    class BrokenProbe(_Backend):
        def available(self) -> bool:
            raise RuntimeError("probe failed")

    with pytest.raises(BackendUnavailable, match="capability probe failed"):
        extract_facts(BrokenProbe(), ".")


def test_extract_facts_rejects_malformed_shared_payload_fields():
    with pytest.raises(BackendUnavailable, match="per-file facts"):
        extract_facts(_Backend(result=Facts(data={"by_file": {"app.py": 7}})), ".")


def test_fact_unit_specs_rejects_a_non_list():
    with pytest.raises(BackendUnavailable, match="unit specifications"):
        fact_unit_specs(Facts(data={"unit_specs": {}}))


def test_fact_unit_specs_rejects_a_zero_length_fragment():
    with pytest.raises(BackendUnavailable, match="invalid shape"):
        fact_unit_specs(Facts(data={"unit_specs": [{"fragments": [["a.py", 4, 4]]}]}))


def test_writable_facts_backend_runs_in_an_isolated_source_copy(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("original\n")

    class WritingBackend(_Backend):
        writes_analysis_artifacts = True

        def extract(self, root):
            (root / "build").mkdir()
            (root / "build" / "artifact.json").write_text("{}\n")
            return Facts(summary=(root / "app.py").read_text())

    facts = extract_facts(WritingBackend(), tmp_path)

    assert facts.summary == "original\n"
    assert source.read_text() == "original\n"
    assert not (tmp_path / "build").exists()


def test_writable_facts_backend_cannot_modify_an_input_source(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("original\n")

    class MutatingBackend(_Backend):
        writes_analysis_artifacts = True

        def extract(self, root):
            (root / "app.py").write_text("mutated\n")
            return Facts(summary="facts")

    with pytest.raises(BackendUnavailable, match="modified an input source"):
        extract_facts(MutatingBackend(), tmp_path)

    assert source.read_text() == "original\n"
