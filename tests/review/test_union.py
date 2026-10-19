"""The shared finding union folds only exact duplicate reports, in every review target."""

from dataclasses import replace

import pytest

from cyberjury.review.finding import ChangeAnchor, Finding
from cyberjury.review.identity import canonical_category
from cyberjury.review.union import MERGE_RULE, finding_accumulator


def _finding(title="query injection", **fields):
    defaults = {
        "severity": "HIGH",
        "category": "sql-injection",
        "entrypoint": "POST /query",
        "file": "app.py",
        "line": 10,
        "evidence": "attacker input becomes SQL syntax",
        "attack_path": "request reaches the query",
    }
    return Finding(title=title, **{**defaults, **fields})


_ANCHOR = ChangeAnchor(file="app.py", line=10, side="new")


@pytest.mark.parametrize("anchor", [None, _ANCHOR], ids=["repository", "diff"])
def test_findings_at_one_location_stay_separate_unless_they_are_the_same_report(anchor):
    accumulator = finding_accumulator()
    first = _finding(change_anchor=anchor)
    variants = [
        replace(first, title="second exploit"),
        replace(first, category="information-exposure"),
        replace(first, entrypoint="QueryView.post"),
        replace(first, line=11),
        replace(first, file="other.py"),
    ]

    assert accumulator.add([first, *variants]) == 6
    assert [item.title for item in accumulator.findings][:2] == ["query injection", "second exploit"]


def test_distinct_change_anchors_stay_separate():
    accumulator = finding_accumulator()
    findings = [_finding(change_anchor=ChangeAnchor(file="app.py", line=line, side="new")) for line in (10, 11)]

    assert accumulator.add(findings) == 2
    assert [item.change_anchor.line for item in accumulator.findings if item.change_anchor] == [10, 11]


def test_distinct_source_operations_at_one_location_stay_separate():
    accumulator = finding_accumulator()
    findings = [_finding(source_operation_id=operation) for operation in ("call-first", "call-second")]

    assert accumulator.add(findings) == 2


def test_one_source_operation_does_not_fold_findings_at_different_lines():
    accumulator = finding_accumulator()
    findings = [_finding(line=line, source_operation_id="call-outer") for line in (63, 64)]

    assert accumulator.add(findings) == 2


@pytest.mark.parametrize("anchor", [None, _ANCHOR], ids=["repository", "diff"])
def test_an_exact_duplicate_keeps_the_first_report_and_adds_evidence_refs_and_provenance(anchor):
    accumulator = finding_accumulator()
    first = _finding(
        title="SQL injection in X",
        category=canonical_category("SQL Injection"),
        change_anchor=anchor,
        attack_path="first path",
        evidence_refs=("seed",),
        found_by=("a",),
    )
    second = replace(
        first,
        title="SQL  injection in x",
        category=canonical_category("sql_injection"),
        severity="LOW",
        evidence="second evidence",
        attack_path="second path",
        evidence_refs=("seed", "src-1"),
        found_by=("b",),
    )

    assert accumulator.add([first]) == 1
    assert accumulator.add([second]) == 0
    [folded] = accumulator.findings
    assert (folded.title, folded.severity, folded.evidence) == (
        "SQL injection in X",
        "HIGH",
        "attacker input becomes SQL syntax",
    )
    assert folded.attack_path == "first path\n\nsecond path"
    assert folded.evidence_refs == ("seed", "src-1")
    assert folded.found_by == ("a", "b")
    assert folded.candidate_id == first.candidate_id == second.candidate_id
    assert accumulator.add([folded]) == 0


def test_the_merge_rule_names_every_identity_field_the_model_controls():
    for name in ("title", "category", "entrypoint", "file", "line", "change_anchor"):
        assert f"`{name}`" in MERGE_RULE
