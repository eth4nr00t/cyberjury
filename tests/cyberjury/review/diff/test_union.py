"""Diff union keeps distinct findings and applies deterministic identity."""

import json
from dataclasses import replace

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import DiffGroundingOptions, DiffReviewOptions, run_diff_review
from cyberjury.review.diff.union import finding_accumulator
from tests.cyberjury.review.diff.support import repository_prepare


def _review(diff, provider):
    return run_diff_review(
        diff,
        provider=provider,
        model="m",
        options=DiffReviewOptions(grounding=DiffGroundingOptions(prepare_diff=repository_prepare())),
    )


_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        if not finding.get("entrypoint"):
            finding["entrypoint"] = "changed code path"
        if not finding.get("exploit_scenario"):
            finding["exploit_scenario"] = "attacker input reaches the vulnerable operation"
        if not finding.get("recommendation"):
            finding["recommendation"] = "enforce the missing security control"
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps(
        {
            "findings": findings,
            "evidence_requests": [],
            "source_queries": [],
        }
    )


def _confirmed_reply(findings):
    return _reply(findings)


def _provider(findings):
    return MockProvider(default=_reply(findings))


def test_review_keeps_distinct_findings_at_one_location():
    """Accumulation cannot erase a distinct exploit at the same source line."""
    findings = [
        {
            "file": "app.py",
            "line": 1,
            "severity": "HIGH",
            "category": "other",
            "description": description,
            "entrypoint": entrypoint,
            "exploit_scenario": attack_path,
            "confidence": 0.9,
        }
        for description, entrypoint, attack_path in (
            ("first exploit", "GET /first", "public route reaches the first unsafe operation"),
            ("second exploit", "task.run", "background task reaches the second unsafe operation"),
        )
    ]

    result = _review(_DIFF, _provider(findings))

    assert [finding.description for finding in result.outcome.findings] == ["first exploit", "second exploit"]
    assert result.outcome.degraded is False


def test_review_keeps_distinct_entrypoint_paths_at_one_location():
    base = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "description": "attacker input becomes SQL syntax",
        "confidence": 0.9,
    }
    findings = [
        {**base, "entrypoint": "POST /query"},
        {**base, "entrypoint": "QueryView.post"},
    ]

    result = _review(_DIFF, _provider(findings))

    assert len(result.outcome.findings) == 2
    assert result.outcome.degraded is False


def test_diff_union_keeps_distinct_findings_at_one_location():
    accumulator = finding_accumulator()
    findings = [
        Finding(
            file="app.py",
            line=1,
            category="other",
            entrypoint=entrypoint,
            description=description,
            exploit_scenario=attack_path,
        )
        for description, entrypoint, attack_path in (
            ("first exploit", "GET /first", "public route reaches the first unsafe operation"),
            ("second exploit", "task.run", "background task reaches the second unsafe operation"),
        )
    ]

    assert accumulator.add(findings) == 2
    assert [finding.description for finding in accumulator.findings] == ["first exploit", "second exploit"]


def test_diff_union_keeps_distinct_change_anchors():
    accumulator = finding_accumulator()
    finding = Finding(file="app.py", line=10, category="other", description="existing operation is exposed")
    findings = [replace(finding, change_anchor=ChangeAnchor(file="app.py", line=line, side="new")) for line in (10, 11)]

    assert accumulator.add(findings) == 2
    assert [item.change_anchor.line for item in accumulator.findings if item.change_anchor] == [10, 11]


def test_diff_union_keeps_a_stable_identity_when_descriptions_differ_in_case_and_spacing():
    accumulator = finding_accumulator()
    first = Finding(
        file="app.py",
        line=10,
        category="sql-injection",
        description="SQL injection in X",
        exploit_scenario="first path",
        found_by=("a",),
    )
    second = replace(first, description="SQL  injection in x", exploit_scenario="second path", found_by=("b",))

    assert accumulator.add([first]) == 1
    assert accumulator.add([second]) == 0
    [folded] = accumulator.findings
    assert folded.description == "SQL injection in X"
    assert folded.found_by == ("a", "b")
    assert folded.candidate_id == first.candidate_id == second.candidate_id
    assert accumulator.add([folded]) == 0


def test_diff_union_folds_one_cause_across_lines_of_one_source_operation():
    accumulator = finding_accumulator()
    findings = [
        Finding(
            file="app.py",
            line=line,
            category="resource-exhaustion",
            source_operation_id="call-outer",
            entrypoint="matches",
            description="unbounded regex operation",
            change_anchor=ChangeAnchor(file="app.py", line=anchor, side="new"),
        )
        for line, anchor in ((63, 63), (64, 64))
    ]

    assert accumulator.add(findings) == 1
    assert len(accumulator.findings) == 1


def test_diff_union_keeps_distinct_causes_on_one_source_operation():
    accumulator = finding_accumulator()
    findings = [
        Finding(
            file="app.py",
            line=63,
            category="resource-exhaustion",
            source_operation_id="call-outer",
            entrypoint="matches",
            description=rule,
        )
        for rule in ("resource-exhaustion-regex", "resource-exhaustion-amplification")
    ]

    assert accumulator.add(findings) == 2


def test_diff_union_keeps_a_missing_anchor_distinct_from_an_explicit_form():
    accumulator = finding_accumulator()
    finding = Finding(file="app.py", line=10, category="other", description="new sink")

    assert accumulator.add([finding]) == 1
    assert accumulator.add([replace(finding, change_anchor=ChangeAnchor(file="app.py", line=10, side="new"))]) == 1


def test_review_preserves_a_valid_anchor_after_an_invalid_duplicate():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10,3 @@\n"
        " existing()\n"
        "+expose()\n"
        " finish()\n"
    )
    base = {
        "file": "app.py",
        "line": 10,
        "severity": "HIGH",
        "category": "other",
        "description": "existing operation is exposed",
        "confidence": 0.9,
    }
    findings = [
        {**base, "change_anchor": {"file": "app.py", "line": 10, "side": "new"}},
        {**base, "change_anchor": {"file": "app.py", "line": 11, "side": "new"}},
    ]

    result = _review(diff, _provider(findings))

    assert [
        (item.line, item.change_anchor.line if item.change_anchor else None) for item in result.outcome.findings
    ] == [(10, 11)]
    assert result.dropped == []
    assert result.outcome.degraded is True


def _f(file, conf=0.9):
    return Finding(
        file=file,
        line=1,
        severity="HIGH",
        category="sql_injection",
        description="string concatenation reaches the query",
        confidence=conf,
    )


def test_diff_review_does_not_delete_a_finding_on_model_confidence_alone():
    """A confidence score is not a controlling fact that can delete a candidate."""
    provider = _provider([_f("app.py", conf=0.1).to_dict()])

    result = _review(_SRC, provider)

    assert len(result.outcome.findings) == 1
    assert result.dropped == []
    assert result.outcome.degraded is False


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"
