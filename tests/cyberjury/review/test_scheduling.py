"""Scheduling receipts bind review policy to exact unit and round execution."""

import hashlib
import json
from dataclasses import replace

import pytest

from cyberjury.review.scheduling import SchedulingReceipt, SchedulingRound


def _schedule(mode="adversarial"):
    return {
        "mode": mode,
        "max_rounds": 3 if mode == "adversarial" else 1,
        "min_rounds": 1,
        "converge_after": 2 if mode == "adversarial" else None,
        "completion": "converge" if mode == "adversarial" else "single",
        "stop_on_failure": True,
    }


def _round(number=1):
    return SchedulingRound(
        round=number,
        unit_ids=("unit-a", "unit-b"),
        new_findings=1,
        union_size=1,
        errors=0,
        failures=0,
        recovered_failures=0,
        incomplete=0,
        pending=0,
        convergence_streak=0,
        clean=True,
        converged=False,
        duration_seconds=0.1,
        new_finding_ids=("union-one",),
        union_finding_ids=("union-one",),
    )


def test_scheduling_receipt_round_trips_with_exact_policy_and_unit_order():
    receipt = SchedulingReceipt.create(
        schedule=_schedule(),
        unit_ids=("unit-a", "unit-b"),
        rounds=(_round(),),
        stop_reason="round_limit",
    )

    assert SchedulingReceipt.from_dict(receipt.to_dict()) == receipt


def test_scheduling_receipt_rejects_a_tampered_round():
    data = SchedulingReceipt.create(
        schedule=_schedule(),
        unit_ids=("unit-a", "unit-b"),
        rounds=(_round(),),
        stop_reason="round_limit",
    ).to_dict()
    data["rounds"][0]["union_size"] = 2
    data["rounds"][0]["union_finding_ids"].append("union-two")

    with pytest.raises(ValueError, match="content hash"):
        SchedulingReceipt.from_dict(data)


def test_scheduling_receipt_rejects_union_identity_drift():
    second = replace(
        _round(2),
        new_findings=0,
        new_finding_ids=(),
        union_finding_ids=("union-other",),
    )

    with pytest.raises(ValueError, match="union identities"):
        SchedulingReceipt.create(
            schedule=_schedule(),
            unit_ids=("unit-a", "unit-b"),
            rounds=(_round(), second),
            stop_reason="round_limit",
        )


def test_scheduling_receipt_reads_the_persisted_v1_shape():
    data = SchedulingReceipt.create(
        schedule=_schedule(),
        unit_ids=("unit-a", "unit-b"),
        rounds=(_round(),),
        stop_reason="round_limit",
    ).to_dict()
    data["schema"] = "cyberjury.scheduling/v1"
    for round_data in data["rounds"]:
        round_data.pop("new_finding_ids")
        round_data.pop("union_finding_ids")
    semantic = {
        "schedule_sha256": data["schedule_sha256"],
        "unit_ids": data["unit_ids"],
        "rounds": data["rounds"],
        "stop_reason": data["stop_reason"],
    }
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    data["content_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()

    receipt = SchedulingReceipt.from_dict(data)

    assert receipt.schema == "cyberjury.scheduling/v1"
    assert receipt.rounds[0].new_finding_ids == ()


def test_scheduling_receipt_rejects_a_non_string_stop_reason():
    data = SchedulingReceipt.create(
        schedule=_schedule(),
        unit_ids=("unit-a", "unit-b"),
        rounds=(_round(),),
        stop_reason="round_limit",
    ).to_dict()
    data["stop_reason"] = []

    with pytest.raises(ValueError, match="stop_reason"):
        SchedulingReceipt.from_dict(data)


def test_scheduling_receipt_requires_every_round_to_execute_the_planned_units():
    with pytest.raises(ValueError, match="planned units"):
        SchedulingReceipt.create(
            schedule=_schedule(),
            unit_ids=("unit-a",),
            rounds=(_round(),),
            stop_reason="round_limit",
        )


@pytest.mark.parametrize("reason", ["no_open_units", "no_reviewable_units"])
def test_nonexecuting_scheduling_receipt_has_no_units_or_rounds(reason):
    receipt = SchedulingReceipt.create(
        schedule=_schedule("standard"),
        unit_ids=(),
        rounds=(),
        stop_reason=reason,
    )

    assert receipt.unit_ids == ()
    assert receipt.rounds == ()
