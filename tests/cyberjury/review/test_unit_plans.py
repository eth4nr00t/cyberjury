"""Unit plan receipts preserve deterministic ownership and budget evidence."""

import pytest

from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice


def _facts_resolution() -> FactsResolutionReceipt:
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=1,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    return FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def _unit(name: str = "app.py", *, seeds: tuple[str, ...] = ("app.py:route:0:40",)) -> UnitPlanRecord:
    return UnitPlanRecord.create(
        kind="source",
        name=name,
        owned_paths=("app.py",),
        source_slices=(UnitSourceSlice(path="app.py", start=0, end=40),),
        seed_ids=seeds,
        relationship_ids=("call:app.py:route:service.py:load",),
    )


def test_unit_plan_round_trips_with_derived_ownership_and_budget_fields():
    seed = "app.py:route:0:40"
    unit = _unit(seeds=(seed,))
    receipt = UnitPlanReceipt.create(
        facts_resolution=_facts_resolution(),
        units=(unit,),
        expected_seed_ids=(seed,),
    )

    assert receipt.unowned_seed_ids == ()
    assert receipt.multi_unit_seed_ids == ()
    assert unit.source_chars == 40
    assert unit.relationship_chars == len("call:app.py:route:service.py:load")
    assert UnitPlanReceipt.from_dict(receipt.to_dict()) == receipt


def test_unit_plan_exposes_unowned_and_multi_unit_seeds():
    owned = "app.py:route:0:40"
    missing = "missing.py:route:0:20"
    first = _unit("first", seeds=(owned,))
    second = UnitPlanRecord.create(
        kind="relationship",
        name="second",
        owned_paths=("app.py",),
        source_slices=(UnitSourceSlice(path="app.py", start=0, end=40),),
        seed_ids=(owned,),
    )

    receipt = UnitPlanReceipt.create(
        facts_resolution=_facts_resolution(),
        units=(first, second),
        expected_owned_paths=("app.py", "missing.py"),
        expected_seed_ids=(owned, missing),
    )

    assert receipt.unowned_paths == ("missing.py",)
    assert receipt.unowned_seed_ids == (missing,)
    assert receipt.multi_unit_seed_ids == (owned,)


def test_unit_plan_rejects_a_tampered_size():
    receipt = UnitPlanReceipt.create(
        facts_resolution=_facts_resolution(),
        units=(_unit(),),
        expected_seed_ids=("app.py:route:0:40",),
    ).to_dict()
    receipt["units"][0]["source_chars"] = 41

    with pytest.raises(ValueError, match="source character count"):
        UnitPlanReceipt.from_dict(receipt)


def test_unit_plan_rejects_an_unsafe_owned_path():
    with pytest.raises(ValueError, match="normalized repository path"):
        UnitPlanRecord.create(kind="source", name="unsafe", owned_paths=("../app.py",))


def test_unit_plan_loader_rejects_boolean_counts():
    artifact = UnitPlanReceipt.create(
        facts_resolution=_facts_resolution(),
        units=(_unit(),),
        expected_seed_ids=("app.py:route:0:40",),
    ).to_dict()
    artifact["unit_count"] = True

    with pytest.raises(ValueError, match="count is invalid"):
        UnitPlanReceipt.from_dict(artifact)


def test_diff_unit_identity_changes_with_same_length_patch_content():
    first = UnitPlanRecord.create(
        kind="diff",
        name="diff:1:app.py",
        owned_paths=("app.py",),
        patch_text="+allow\n",
    )
    second = UnitPlanRecord.create(
        kind="diff",
        name="diff:1:app.py",
        owned_paths=("app.py",),
        patch_text="+block\n",
    )

    assert first.patch_chars == second.patch_chars
    assert first.patch_sha256 != second.patch_sha256
    assert first.id != second.id
