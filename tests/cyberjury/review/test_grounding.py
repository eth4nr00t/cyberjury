"""Grounding receipts bind Stage 06 units to exact initial evidence."""

from cyberjury.canonical import text_sha256
from cyberjury.review.context import EvidenceItem, GroundingContext, SourceEvidence, SourceSpan
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.unit_plans import UnitPlanReceipt, UnitPlanRecord, UnitSourceSlice
from cyberjury.sources.snapshot import SourceSnapshot


def _plan(source_chars: int) -> UnitPlanReceipt:
    unit = UnitPlanRecord.create(
        kind="source",
        name="app.py",
        owned_paths=("app.py",),
        source_slices=(UnitSourceSlice(path="app.py", start=0, end=source_chars),),
    )
    return UnitPlanReceipt.create(
        facts=FactsReceipt.create(backend_id="test", facts=Facts()),
        units=(unit,),
        expected_owned_paths=("app.py",),
    )


def test_grounding_receipt_binds_the_unit_plan_and_exact_evidence_content(tmp_path):
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
        text="call candidates",
        seed=source,
        syntax_hints="definition route",
        files=("app.py",),
        evidence=(evidence,),
        source_spans=(SourceSpan(file="app.py", start_line=1, end_line=2),),
        source_snapshot=snapshot,
        snapshot_files=("app.py",),
    )

    receipt = GroundingReceipt.create(unit_plan=unit_plan, contexts=(context,))

    artifact = receipt.to_dict()
    record = artifact["contexts"][0]
    assert artifact["unit_plan_receipt_sha256"] == unit_plan.receipt_sha256
    assert artifact["receipt_sha256"] == receipt.receipt_sha256
    assert artifact["schema"] == "cyberjury.grounding/v1"
    assert record["seed_chars"] == len(source)
    assert record["seed_sha256"] == text_sha256(source)
    assert record["context_chars"] == len("call candidates")
    assert record["syntax_hints_chars"] == len("definition route")
    assert record["evidence"][0]["content_sha256"] == text_sha256(source)


def test_grounding_receipt_binds_source_the_agent_delivered_before_the_first_call(tmp_path):
    source = "def route():\n    return load()\n"
    callee = "def load():\n    return 1\n"
    (tmp_path / "app.py").write_text(source)
    (tmp_path / "service.py").write_text(callee)
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py", "service.py"))
    delivered = SourceEvidence(
        id="src-0123456789ab",
        identity="service.py:1-2",
        text=callee,
        source_span=SourceSpan(file="service.py", start_line=1, end_line=2),
    )
    context = GroundingContext(
        text=source,
        files=("app.py",),
        source_evidence=(delivered,),
        source_snapshot=snapshot,
        snapshot_files=("app.py", "service.py"),
    )

    receipt = GroundingReceipt.create(unit_plan=_plan(len(source)), contexts=(context,))

    record = receipt.to_dict()["contexts"][0]
    assert record["context_sha256"] == text_sha256(context.text)
    assert record["source_evidence"][0]["id"] == delivered.id
    assert record["source_evidence"][0]["content_chars"] == len(callee)
