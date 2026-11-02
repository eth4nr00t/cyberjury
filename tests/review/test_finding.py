"""The one finding record round trips through the form its unit findings record stores."""

from dataclasses import replace

import pytest

from cyberjury.review.context import SourceSpan
from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.identity import candidate_identity

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
    cited_spans=(SourceSpan(file="app/v.py", start_line=1, end_line=20),),
    evidence_refs=("seed", "src-control"),
)


def test_stored_form_preserves_identity_evidence_and_anchor():
    """A to_dict/from_dict round trip keeps candidate id, operation id, evidence refs, and spans."""
    restored = Finding.from_dict(_FINDING.to_dict())

    assert restored == _FINDING
    assert restored.candidate_id == _FINDING.candidate_id
    assert (restored.source_operation_id, restored.evidence_refs) == ("call-account-export", ("seed", "src-control"))
    assert restored.cited_spans == _FINDING.cited_spans


def test_cited_spans_never_change_the_candidate_identity():
    """Dropping cited_spans from the finding leaves its candidate_id unchanged."""
    unbound = replace(_FINDING, cited_spans=())

    assert unbound.candidate_id == _FINDING.candidate_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_refs", "abc"),
        ("severity", "SEVERE"),
        ("line", "1"),
        ("line", True),
        ("title", None),
        ("evidence", 1),
        ("change_anchor", {"file": "a.py"}),
        ("change_anchor", {"file": "a.py", "line": "1", "side": "new"}),
        ("change_anchor", {"file": "a.py", "line": 1, "side": "middle"}),
        ("cited_spans", [{"file": "a.py", "start_line": 1}]),
        ("cited_spans", [{"file": "a.py", "range": [0, 1]}]),
        ("extra", 1),
    ],
)
def test_stored_form_rejects_mistyped_fields(field, value):
    """Bad severities, string or bool lines, partial or mistyped anchors and spans, and extra keys raise."""
    with pytest.raises(ValueError, match="finding"):
        Finding.from_dict(_FINDING.to_dict() | {field: value})


def test_candidate_id_hashes_the_target_identity_of_the_finding():
    """A diff finding hashes its change anchor and operation id, and a repository finding hashes no anchor."""
    repository = replace(_FINDING, change_anchor=None, source_operation_id="")

    assert _FINDING.candidate_id == candidate_identity(
        target="diff",
        file="app/v.py",
        line=10,
        category="missing-authorization",
        entrypoint="POST /export",
        anchor=("app/v.py", 9, "old"),
        title="Unscoped account export",
        source_operation_id="call-account-export",
    )
    assert repository.candidate_id == candidate_identity(
        target="repository",
        file="app/v.py",
        line=10,
        category="missing-authorization",
        entrypoint="POST /export",
        anchor=None,
        title="Unscoped account export",
        source_operation_id="",
    )
