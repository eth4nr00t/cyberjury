"""Original reports remain individually inspectable after identity folding."""

import pytest

from cyberjury.review.claims import ClaimRecord, merge_claims


def test_claim_record_is_structured_and_hash_bound():
    claim = ClaimRecord.create(
        "candidate-first",
        {"file": "app.py", "line": 10, "attack_path": "first route", "evidence_refs": ["src-one"]},
    )

    assert claim.record["attack_path"] == "first route"
    assert claim.record["candidate_id"] == "candidate-first"
    assert claim.report == {
        "file": "app.py",
        "line": 10,
        "attack_path": "first route",
        "evidence_refs": ["src-one"],
    }
    assert ClaimRecord.from_dict(claim.to_dict()) == claim
    with pytest.raises(ValueError, match="hash does not match"):
        ClaimRecord.from_dict(
            {**claim.to_dict(), "content_json": claim.content_json.replace("first route", "second route")}
        )


def test_claim_union_deduplicates_identical_reports_without_losing_distinct_paths():
    first = ClaimRecord.create("candidate-first", {"attack_path": "first route"})
    second = ClaimRecord.create("candidate-first", {"attack_path": "second route"})

    assert merge_claims((second, first), (first,)) == merge_claims((first, second), ())
    assert len(merge_claims((first, second), ())) == 2
