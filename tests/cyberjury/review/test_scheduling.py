"""Scheduling receipts bind one unit fan-out to its exact unit order and completion state."""

import pytest

from cyberjury.review.scheduling import SchedulingReceipt


def _receipt(*, clean=True, errors=0):
    return SchedulingReceipt.create(
        unit_ids=("unit-a", "unit-b"),
        new_finding_ids=("union-one",),
        union_finding_ids=("union-one",),
        errors=errors,
        failures=0,
        incomplete=0,
        clean=clean,
        duration_seconds=0.1,
    )


def test_scheduling_receipt_round_trips_with_exact_unit_order():
    receipt = _receipt()

    assert receipt.stop_reason == "complete"
    assert SchedulingReceipt.from_dict(receipt.to_dict()) == receipt


def test_scheduling_receipt_records_incomplete_work():
    receipt = _receipt(clean=False, errors=1)

    assert receipt.stop_reason == "incomplete"


def test_scheduling_receipt_rejects_tampered_content():
    data = _receipt().to_dict()
    data["union_finding_ids"].append("union-two")

    with pytest.raises(ValueError, match="content hash"):
        SchedulingReceipt.from_dict(data)


def test_scheduling_receipt_rejects_new_findings_outside_the_union():
    with pytest.raises(ValueError, match="outside the union"):
        SchedulingReceipt.create(
            unit_ids=("unit-a",),
            new_finding_ids=("union-one",),
            union_finding_ids=("union-other",),
            errors=0,
            failures=0,
            incomplete=0,
            clean=True,
            duration_seconds=0.1,
        )


def test_scheduling_receipt_rejects_a_clean_state_with_errors():
    with pytest.raises(ValueError, match="clean scheduling receipt"):
        _receipt(clean=True, errors=1)


def test_scheduling_receipt_rejects_a_non_string_stop_reason():
    data = _receipt().to_dict()
    data["stop_reason"] = []

    with pytest.raises(ValueError, match="stop_reason"):
        SchedulingReceipt.from_dict(data)


@pytest.mark.parametrize("reason", ["no_open_units", "no_reviewable_units"])
def test_nonexecuting_scheduling_receipt_has_no_units(reason):
    receipt = SchedulingReceipt.empty(stop_reason=reason)

    assert receipt.unit_ids == ()
    assert receipt.union_finding_ids == ()
    assert SchedulingReceipt.from_dict(receipt.to_dict()) == receipt
