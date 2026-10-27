"""The findings artifact maps every target onto one field set, ordered by severity, with its issues."""

from dataclasses import replace

from cyberjury.canonical import canonical_sha256
from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.issues import Issue
from cyberjury.review.result import findings_artifact


def _finding(**values) -> Finding:
    fields = {
        "title": "missing ownership check",
        "file": "views.py",
        "line": 3,
        "severity": "MEDIUM",
        "category": "idor",
        "entrypoint": "GET /records/<id>",
        "evidence": "views.py:3 returns any record",
        "attack_path": "a member reads another record",
    }
    return Finding(**(fields | values))


def test_findings_artifact_maps_every_target_onto_the_same_fields():
    """Diff and repository findings serialize to one v1 field set, with change_anchor None for the repo one."""
    diff = _finding(
        title="record write is unauthenticated",
        file="app.py",
        line=20,
        severity="HIGH",
        evidence="authentication was removed",
        change_anchor=ChangeAnchor(file="middleware.py", line=8, side="old"),
    )
    repository = _finding()

    document = findings_artifact([repository, diff], (Issue(members=(diff,)), Issue(members=(repository,)))).to_dict()

    assert document["schema"] == "cyberjury.findings/v1"
    assert [record["file"] for record in document["findings"]] == ["app.py", "views.py"]
    assert document["findings"][0]["change_anchor"] == {"file": "middleware.py", "line": 8, "side": "old"}
    assert document["findings"][1]["change_anchor"] is None
    assert set(document["findings"][0]) == {
        "id",
        "title",
        "category",
        "severity",
        "file",
        "line",
        "entrypoint",
        "evidence",
        "attack_path",
        "evidence_refs",
        "issue_id",
        "change_anchor",
    }


def test_findings_artifact_records_every_member_of_a_grouped_issue_with_its_issue_id():
    """Two findings linked by location share one issue id, and the summary counts two HIGH."""
    first = _finding(severity="HIGH")
    second = replace(first, title="share link creation lacks a document check")
    issue = Issue(members=(first, second), linked_by=("location",))

    document = findings_artifact([first, second], (issue,)).to_dict()

    assert [record["issue_id"] for record in document["findings"]] == [issue.id, issue.id]
    assert document["issues"] == [
        {
            "id": issue.id,
            "representative": first.candidate_id,
            "members": [first.candidate_id, second.candidate_id],
            "linked_by": ["location"],
        }
    ]
    assert document["summary"] == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}


def test_findings_artifact_hashes_its_content():
    """The content hash covers the findings, the issues, and the summary."""
    finding = _finding()

    document = findings_artifact([finding], (Issue(members=(finding,)),)).to_dict()

    content = {key: document[key] for key in ("findings", "issues", "summary")}
    assert document["content_sha256"] == canonical_sha256(content)
