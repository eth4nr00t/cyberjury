"""Unit plan receipts preserve deterministic ownership."""

import pytest

from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice

_FACTS = FactsReceipt.create(backend_id="test", facts=Facts())


def _unit(name: str = "app.py") -> UnitPlanRecord:
    return UnitPlanRecord.create(
        kind="source",
        name=name,
        owned_paths=("app.py",),
        source_slices=(UnitSourceSlice(path="app.py", start=0, end=40),),
    )


def test_unit_plan_binds_facts_and_units_into_its_receipt_hash():
    """The receipt cites the facts hash and owns app.py, and renaming the unit changes receipt_sha256."""
    receipt = UnitPlanReceipt.create(facts=_FACTS, units=(_unit(),))
    renamed = UnitPlanReceipt.create(facts=_FACTS, units=(_unit("other"),))

    assert receipt.to_dict()["schema"] == "cyberjury.plan/v1"
    assert receipt.facts_receipt_sha256 == _FACTS.receipt_sha256
    assert receipt.expected_owned_paths == ("app.py",)
    assert renamed.receipt_sha256 != receipt.receipt_sha256


def test_unit_plan_refuses_an_unowned_expected_path():
    """Expecting app.py and missing.py when only app.py is owned raises an unowned missing.py error."""
    with pytest.raises(ValueError, match=r"unowned: missing\.py"):
        UnitPlanReceipt.create(facts=_FACTS, units=(_unit(),), expected_owned_paths=("app.py", "missing.py"))


def test_diff_unit_identity_changes_with_same_length_patch_content():
    """Patches +allow and +block of equal length give different patch hashes and unit ids."""
    first = UnitPlanRecord.create(kind="diff", name="diff:1:app.py", owned_paths=("app.py",), patch_text="+allow\n")
    second = UnitPlanRecord.create(kind="diff", name="diff:1:app.py", owned_paths=("app.py",), patch_text="+block\n")

    assert first.patch_sha256 != second.patch_sha256
    assert first.id != second.id
