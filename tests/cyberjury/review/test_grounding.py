"""Grounding receipts bind Stage 06 units to exact initial evidence."""

import pytest

from cyberjury.review.context import EvidenceItem, GroundingContext, SourceSpan
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice
from cyberjury.sources.snapshot import SourceSnapshot


def _facts() -> FactsResolutionReceipt:
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=1,
        definition_count=1,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    return FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def _plan(source_chars: int) -> UnitPlanReceipt:
    unit = UnitPlanRecord.create(
        kind="source",
        name="app.py",
        owned_paths=("app.py",),
        source_slices=(UnitSourceSlice(path="app.py", start=0, end=source_chars),),
        seed_ids=("source:app.py",),
    )
    return UnitPlanReceipt.create(
        facts_resolution=_facts(),
        units=(unit,),
        expected_owned_paths=("app.py",),
        expected_seed_ids=("source:app.py",),
    )


def test_grounding_receipt_round_trips_and_binds_the_unit_plan(tmp_path):
    source = "def route():\n    return 1\n"
    (tmp_path / "app.py").write_text(source)
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",))
    unit_plan = _plan(len(source))
    evidence = EvidenceItem.create(
        identity=f"app.py:route:0:{len(source)}",
        label="app.py:route",
        text=source,
        source_span=SourceSpan(file="app.py", start_line=1, end_line=2),
    )
    context = GroundingContext(
        text=source,
        facts="definition route",
        files=("app.py",),
        evidence=(evidence,),
        source_spans=(SourceSpan(file="app.py", start_line=1, end_line=2),),
        source_snapshot=snapshot,
        snapshot_files=("app.py",),
    )

    receipt = GroundingReceipt.create(unit_plan=unit_plan, contexts=(context,))

    assert receipt.unit_plan_receipt_sha256 == unit_plan.receipt_sha256
    assert receipt.total_context_chars == len(source)
    assert receipt.total_facts_chars == len("definition route")
    assert receipt.contexts[0].evidence[0].content_sha256
    assert GroundingReceipt.from_dict(receipt.to_dict()) == receipt


def test_grounding_receipt_rejects_tampered_context_metadata(tmp_path):
    source = "source"
    (tmp_path / "app.py").write_text(source)
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",))
    context = GroundingContext(text=source, source_snapshot=snapshot, snapshot_files=("app.py",))
    artifact = GroundingReceipt.create(unit_plan=_plan(len(source)), contexts=(context,)).to_dict()
    artifact["contexts"][0]["context_chars"] = 999

    with pytest.raises(ValueError, match="record hash"):
        GroundingReceipt.from_dict(artifact)


def test_grounding_receipt_rejects_a_context_from_the_wrong_review_path(tmp_path):
    source = "source"
    (tmp_path / "app.py").write_text(source)
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",))
    context = GroundingContext(
        text=source,
        source="diff",
        source_snapshot=snapshot,
        snapshot_files=("app.py",),
    )

    with pytest.raises(ValueError, match="source does not match unit"):
        GroundingReceipt.create(unit_plan=_plan(len(source)), contexts=(context,))
