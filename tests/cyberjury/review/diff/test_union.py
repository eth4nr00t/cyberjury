"""Diff union keeps distinct findings and applies deterministic identity."""

import json
from dataclasses import replace

from cyberjury.finding import ChangeAnchor, Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    audit_diff,
)
from cyberjury.review.diff.union import finding_accumulator, role_accumulator

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    return json.dumps({"findings": findings})


def test_standard_review_keeps_distinct_findings_at_one_location():
    """Standard accumulation cannot erase a distinct exploit at the same source line."""
    findings = [
        {
            "file": "app.py",
            "line": 1,
            "severity": "HIGH",
            "category": "other",
            "description": description,
            "confidence": 0.9,
        }
        for description in ("first exploit", "second exploit")
    ]

    kept, _dropped, degraded = audit_diff(
        _DIFF,
        provider=MockProvider(default=_reply(findings)),
        model="mock",
    )

    assert [finding.description for finding in kept] == ["first exploit", "second exploit"]
    assert degraded is False


def test_adversarial_union_keeps_distinct_findings_at_one_location():
    accumulator = role_accumulator()
    findings = [
        Finding(file="app.py", line=1, category="other", description=description)
        for description in ("first exploit", "second exploit")
    ]

    assert accumulator.add(findings) == 2
    assert [finding.description for finding in accumulator.findings] == ["first exploit", "second exploit"]


def test_diff_union_keeps_distinct_change_anchors():
    accumulator = finding_accumulator()
    finding = Finding(file="app.py", line=10, category="other", description="existing operation is exposed")
    findings = [replace(finding, change_anchor=ChangeAnchor(file="app.py", line=line, side="new")) for line in (10, 11)]

    assert accumulator.add(findings) == 2
    assert [item.change_anchor.line for item in accumulator.findings if item.change_anchor] == [10, 11]


def test_diff_union_folds_an_implicit_new_anchor_with_its_explicit_form():
    accumulator = finding_accumulator()
    finding = Finding(file="app.py", line=10, category="other", description="new sink")

    assert accumulator.add([finding]) == 1
    assert accumulator.add([replace(finding, change_anchor=ChangeAnchor(file="app.py", line=10, side="new"))]) == 0


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

    kept, dropped, degraded = audit_diff(diff, provider=MockProvider(default=_reply(findings)), model="mock")

    assert [(item.line, item.change_anchor.line if item.change_anchor else None) for item in kept] == [(10, 11)]
    assert dropped == []
    assert degraded is True


def _f(file, conf=0.9):
    return Finding(file=file, line=1, severity="HIGH", category="sql_injection", confidence=conf)


def test_diff_review_does_not_delete_a_finding_on_model_confidence_alone():
    """A confidence score is not a controlling fact that can delete a candidate."""
    provider = MockProvider(default=_reply([_f("app.py", conf=0.1).to_dict()]))

    kept, dropped, degraded = audit_diff(_SRC, provider=provider, model="m")

    assert len(kept) == 1
    assert dropped == []
    assert degraded is False


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"
