"""Map Findings into the machine findings artifact."""

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.report import findings_artifact

_FINDINGS = [
    Finding(
        file="app/payment.py",
        line=42,
        severity="CRITICAL",
        category="sql_injection",
        description="string-concatenated query",
        exploit_scenario="send ' OR 1=1 --",
        confidence=0.95,
    ),
    Finding(
        file="app/views.py",
        line=10,
        severity="MEDIUM",
        category="idor",
        description="missing ownership check",
        confidence=0.6,
    ),
]


def test_artifact_has_findings_and_summary_keys():
    doc = findings_artifact(_FINDINGS).to_dict()
    assert set(doc) == {"schema", "findings", "summary", "content_sha256"}
    assert doc["findings"][0]["severity"] == "CRITICAL"
    assert doc["findings"][0]["status"] == "candidate"


def test_independent_verification_marks_only_verified_findings_confirmed():
    doc = findings_artifact(_FINDINGS, verified_ids={_FINDINGS[0].candidate_id}).to_dict()
    assert [item["status"] for item in doc["findings"]] == ["confirmed", "candidate"]


def test_empty_findings_produce_an_empty_artifact():
    assert findings_artifact([]).to_dict()["findings"] == []


def test_change_anchor_is_preserved_in_the_artifact():
    finding = Finding(
        file="app.py",
        line=20,
        severity="HIGH",
        category="missing-authorization",
        description="authentication was removed",
        change_anchor=ChangeAnchor(file="middleware.py", line=8, side="old"),
    )

    assert findings_artifact([finding]).to_dict()["findings"][0]["change_anchor"] == {
        "file": "middleware.py",
        "line": 8,
        "side": "old",
    }
