"""Diff union keeps distinct findings and applies deterministic identity."""

import json
from dataclasses import replace

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    audit_diff,
)
from cyberjury.review.diff.union import finding_accumulator, role_accumulator
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    for finding in findings:
        category = finding.get("category")
        if category in {"sql-injection", "sql_injection"}:
            finding.setdefault("decision_rule_id", "sql-syntax-boundary")
        elif category == "other":
            finding.setdefault("decision_rule_id", "")
        else:
            finding.setdefault("decision_rule_id", "")
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
            "decision_rule_assessments": [],
            "decision_rule_requests": [],
            "evidence_requests": [],
            "source_queries": [],
        }
    )


def _confirmed_reply(findings):
    payload = json.loads(_reply(findings))
    payload["decision_rule_requests"] = []
    payload["evidence_requests"] = []
    payload["source_queries"] = []
    rule_ids = {finding["decision_rule_id"] for finding in payload["findings"] if finding.get("decision_rule_id")}
    payload["decision_rule_assessments"] = [
        {
            "decision_rule_id": rule_id,
            "decision": "finding",
            "reason": "the complete rule and source establish the exploit",
            "evidence_refs": ["seed"],
        }
        for rule_id in sorted(rule_ids)
    ]
    return json.dumps(payload)


def _provider(findings):
    initial = _reply(findings)
    if not any(finding.get("decision_rule_id") for finding in json.loads(initial)["findings"]):
        return MockProvider(default=initial)
    return MockProvider(responses=[initial, _confirmed_reply(findings)])


def test_standard_review_keeps_distinct_findings_at_one_location():
    """Standard accumulation cannot erase a distinct exploit at the same source line."""
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

    kept, _dropped, degraded = audit_diff(
        _DIFF,
        provider=_provider(findings),
        model="mock",
        prepare_diff=repository_prepare(),
    )

    assert [finding.description for finding in kept] == ["first exploit", "second exploit"]
    assert degraded is False


def test_standard_review_folds_one_rule_at_one_location_across_entrypoint_wording():
    base = {
        "file": "app.py",
        "line": 1,
        "severity": "HIGH",
        "category": "sql-injection",
        "decision_rule_id": "sql-syntax-boundary",
        "description": "attacker input becomes SQL syntax",
        "confidence": 0.9,
    }
    findings = [
        {**base, "entrypoint": "POST /query"},
        {**base, "entrypoint": "QueryView.post"},
    ]

    kept, _dropped, degraded = audit_diff(
        _DIFF,
        provider=_provider(findings),
        model="mock",
        prepare_diff=repository_prepare(),
    )

    assert len(kept) == 1
    assert degraded is False


def test_adversarial_union_keeps_distinct_findings_at_one_location():
    accumulator = role_accumulator()
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


def test_diff_union_folds_one_rule_across_lines_of_one_source_operation():
    accumulator = finding_accumulator()
    findings = [
        Finding(
            file="app.py",
            line=line,
            category="resource-exhaustion",
            decision_rule_id="resource-exhaustion-regex",
            source_operation_id="call-outer",
            entrypoint="matches",
            description=f"regex operation at line {line}",
            change_anchor=ChangeAnchor(file="app.py", line=anchor, side="new"),
        )
        for line, anchor in ((63, 63), (64, 64))
    ]

    assert accumulator.add(findings) == 1
    assert len(accumulator.findings) == 1


def test_diff_union_keeps_distinct_rules_on_one_source_operation():
    accumulator = finding_accumulator()
    findings = [
        Finding(
            file="app.py",
            line=63,
            category="resource-exhaustion",
            decision_rule_id=rule,
            source_operation_id="call-outer",
            entrypoint="matches",
        )
        for rule in ("resource-exhaustion-regex", "resource-exhaustion-amplification")
    ]

    assert accumulator.add(findings) == 2


def test_diff_union_keeps_a_missing_anchor_distinct_from_an_explicit_form():
    accumulator = finding_accumulator()
    finding = Finding(file="app.py", line=10, category="other", description="new sink")

    assert accumulator.add([finding]) == 1
    assert accumulator.add([replace(finding, change_anchor=ChangeAnchor(file="app.py", line=10, side="new"))]) == 1


def test_standard_review_preserves_a_valid_anchor_after_an_invalid_duplicate():
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

    kept, dropped, degraded = audit_diff(
        diff,
        provider=_provider(findings),
        model="mock",
        prepare_diff=repository_prepare(),
    )

    assert [(item.line, item.change_anchor.line if item.change_anchor else None) for item in kept] == [(10, 11)]
    assert dropped == []
    assert degraded is True


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

    kept, dropped, degraded = audit_diff(
        _SRC,
        provider=provider,
        model="m",
        prepare_diff=repository_prepare(),
    )

    assert len(kept) == 1
    assert dropped == []
    assert degraded is False


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"
