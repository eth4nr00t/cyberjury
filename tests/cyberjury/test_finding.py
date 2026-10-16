"""The one finding record round trips through its checkpoint form."""

import pytest

from cyberjury.finding import ChangeAnchor, Finding

_FINDING = Finding(
    title="Unscoped account export",
    file="app/v.py",
    line=10,
    severity="HIGH",
    category="missing-authorization",
    entrypoint="POST /export",
    evidence="app/v.py:10 has no ownership check",
    attack_path="request reaches unguarded account export",
    change_anchor=ChangeAnchor(file="app/v.py", line=9, side="old"),
    source_operation_id="call-account-export",
    evidence_refs=("seed", "src-control"),
    found_by=("finder",),
)


def test_checkpoint_form_preserves_identity_provenance_and_anchor():
    restored = Finding.from_dict(_FINDING.to_dict())

    assert restored == _FINDING
    assert restored.candidate_id == _FINDING.candidate_id
    assert (restored.source_operation_id, restored.evidence_refs, restored.found_by) == (
        "call-account-export",
        ("seed", "src-control"),
        ("finder",),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_refs", "abc"),
        ("found_by", [1]),
        ("severity", "SEVERE"),
        ("line", "1"),
        ("line", True),
        ("title", None),
        ("evidence", 1),
        ("change_anchor", {"file": "a.py"}),
        ("extra", 1),
    ],
)
def test_checkpoint_form_rejects_mistyped_fields(field, value):
    with pytest.raises(ValueError, match="finding"):
        Finding.from_dict(_FINDING.to_dict() | {field: value})
