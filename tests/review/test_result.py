"""The findings artifact maps every target onto one field set, in report order, with its issues."""

from dataclasses import replace

from cyberjury.canonical import canonical_sha256
from cyberjury.review.context import CitedSource, SourceSpan
from cyberjury.review.finding import ChangeAnchor, Finding, Reachability
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


_FIELDS = {
    "id",
    "title",
    "category",
    "severity",
    "file",
    "line",
    "entrypoint",
    "reachability",
    "evidence",
    "attack_path",
    "evidence_refs",
    "cited_sources",
    "issue_id",
    "change_anchor",
    "unit_complete",
}


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

    document = findings_artifact(
        [repository, diff], (Issue(members=(diff,)), Issue(members=(repository,))), unfinished=frozenset()
    ).to_dict()

    assert document["schema"] == "cyberjury.findings/v1"
    assert [record["file"] for record in document["findings"]] == ["app.py", "views.py"]
    assert document["findings"][0]["change_anchor"] == {"file": "middleware.py", "line": 8, "side": "old"}
    assert document["findings"][1]["change_anchor"] is None
    assert all(set(record) == _FIELDS for record in document["findings"])


def test_findings_artifact_resolves_each_evidence_id_to_its_cited_source():
    """A finding citing seed and src-control lists each id with its file and line range."""
    finding = _finding(
        evidence_refs=("seed", "src-control"),
        cited_sources=(
            CitedSource(id="seed", span=SourceSpan(file="views.py", start_line=1, end_line=9)),
            CitedSource(id="src-control", span=SourceSpan(file="auth.py", start_line=20, end_line=31)),
        ),
    )

    document = findings_artifact([finding], (Issue(members=(finding,)),), unfinished=frozenset()).to_dict()

    assert document["findings"][0]["cited_sources"] == [
        {"id": "seed", "file": "views.py", "range": [1, 9]},
        {"id": "src-control", "file": "auth.py", "range": [20, 31]},
    ]


def test_findings_artifact_records_every_member_of_a_grouped_issue_with_its_issue_id():
    """Two findings linked by location share one issue id, and the summary counts two HIGH."""
    first = _finding(severity="HIGH")
    second = replace(first, title="share link creation lacks a document check")
    issue = Issue(members=(first, second), linked_by=("location",))

    document = findings_artifact([first, second], (issue,), unfinished=frozenset()).to_dict()

    assert [record["issue_id"] for record in document["findings"]] == [issue.id, issue.id]
    assert document["issues"] == [
        {
            "id": issue.id,
            "representative_id": first.candidate_id,
            "member_ids": [first.candidate_id, second.candidate_id],
            "linked_by": ["location"],
            "unit_complete": True,
        }
    ]
    assert document["summary"] == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}


def test_findings_artifact_hashes_its_content():
    """The content hash covers the findings, the issues, and the summary."""
    finding = _finding()

    document = findings_artifact([finding], (Issue(members=(finding,)),), unfinished=frozenset()).to_dict()

    content = {key: document[key] for key in ("findings", "issues", "summary")}
    assert document["content_sha256"] == canonical_sha256(content)


def test_findings_artifact_marks_findings_only_failed_units_reported():
    """A finding whose id is unfinished has unit_complete False, and the other finding has it True."""
    finished, unfinished = _finding(), _finding(line=9)

    document = findings_artifact(
        [finished, unfinished],
        (Issue(members=(finished,)), Issue(members=(unfinished,))),
        unfinished=frozenset({unfinished.candidate_id}),
    ).to_dict()

    assert {record["line"]: record["unit_complete"] for record in document["findings"]} == {3: True, 9: False}


def test_an_issue_is_complete_when_any_member_came_from_a_finished_unit():
    """An issue whose unfinished representative has a finished member is complete, and a lone unfinished one is not."""
    unfinished, finished, alone = _finding(severity="HIGH"), _finding(line=9), _finding(line=20)

    document = findings_artifact(
        [finished, unfinished, alone],
        (Issue(members=(unfinished, finished)), Issue(members=(alone,))),
        unfinished=frozenset({unfinished.candidate_id, alone.candidate_id}),
    ).to_dict()

    assert [issue["unit_complete"] for issue in document["issues"]] == [True, False]


def test_findings_artifact_orders_unestablished_reachability_last():
    """Of two equal-severity findings, the one whose reachability is unestablished is listed after the reachable one."""
    reachable = _finding(severity="HIGH", file="a.py", reachability=Reachability(established=True, evidence_ref="seed"))
    orphan = _finding(severity="HIGH", file="b.py", reachability=Reachability(established=False, note="no route"))

    document = findings_artifact(
        [orphan, reachable],
        (Issue(members=(orphan,)), Issue(members=(reachable,))),
        unfinished=frozenset(),
    ).to_dict()

    assert [record["file"] for record in document["findings"]] == ["a.py", "b.py"]
    assert document["findings"][1]["reachability"]["established"] is False
