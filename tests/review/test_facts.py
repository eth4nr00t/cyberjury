"""The shared facts contract binds receipts and names limitation locations."""

from cyberjury.review.facts import FactLimitation, Facts, FactsReceipt


def test_facts_receipt_binds_the_backend_and_its_evidence():
    """Two v1 receipts from one backend whose a.py facts differ ("one" vs "two") have different hashes."""
    first = FactsReceipt.create(backend_id="backend", facts=Facts(by_file={"a.py": "one"}))
    second = FactsReceipt.create(backend_id="backend", facts=Facts(by_file={"a.py": "two"}))

    assert first.to_dict()["schema"] == "cyberjury.facts/v1"
    assert first.receipt_sha256 != second.receipt_sha256


def test_fact_limitation_identity_names_its_location():
    """An app.py limitation at line 2 column 4 has identity facts:app.py:2:4 and a matching message."""
    limitation = FactLimitation(source="app.py", analyzer="python", reason="unparsable", line=2, column=4)

    assert limitation.identity == "facts:app.py:2:4"
    assert limitation.message == "app.py at 2:4: python unparsable"
