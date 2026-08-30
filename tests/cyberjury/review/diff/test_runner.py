"""Diff batch execution preserves progress, failures, rounds, and concurrency."""

import json
from dataclasses import replace
from threading import Barrier

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    audit_diff,
    run_diff_review,
)
from cyberjury.review.diff.model import (
    DiffUnit,
)
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import role_accumulator
from cyberjury.review.engine import ReviewCycle, review_plan
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    for finding in findings:
        finding.setdefault("evidence_refs", ["seed"])
        if "file" in finding and "line" in finding:
            finding.setdefault(
                "change_anchor",
                {"file": finding["file"], "line": finding["line"], "side": "new"},
            )
    return json.dumps({"findings": findings})


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def test_audit_diff_reports_one_progress_call_per_batch(monkeypatch):
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    two = _SRC + "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+y = 2\n"
    seen = []
    audit_diff(
        two,
        provider=MockProvider(default='{"findings": []}'),
        model="m",
        prepare_diff=repository_prepare(),
        on_batch=lambda done, total, secs: seen.append((done, total)),
    )
    assert seen == [(1, 2), (2, 2)]


def test_audit_diff_records_failed_batch_and_continues(monkeypatch):
    """A large diff keeps completed batch results while surfacing failed batches."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    provider = MockProvider(
        responses=[
            "not json",
            _reply(
                [
                    {
                        "file": "other.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "missing-authorization",
                        "description": "unguarded sink",
                        "confidence": 0.9,
                    }
                ]
            ),
        ]
    )

    result = run_diff_review(
        _SRC + other,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
            execution=DiffExecutionOptions(concurrency=1),
        ),
    )

    assert [f.description for f in result.outcome.findings] == ["unguarded sink"]
    assert result.dropped == []
    assert result.outcome.degraded is True
    assert len(provider.calls) == 2
    failures = result.outcome.failures
    assert failures[0].index == 1
    assert failures[0].total == 2
    assert failures[0].paths == ("app.py",)
    assert failures[0].reason.startswith("AuditError:")


def test_audit_diff_records_each_batch_when_failures_repeat(monkeypatch):
    """Identical failures remain attributable to every incomplete batch."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    result = run_diff_review(
        _SRC + other,
        provider=MockProvider(default="not json"),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
        ),
    )

    assert result.outcome.findings == ()
    assert result.dropped == []
    assert result.outcome.degraded is True
    assert [failure.paths for failure in result.outcome.failures] == [("app.py",), ("other.py",)]


def test_audit_diff_records_single_batch_failure():
    """A small diff uses the same failure record shape as a split diff."""
    result = run_diff_review(
        _SRC,
        provider=MockProvider(default="not json"),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
        ),
    )

    assert result.outcome.findings == ()
    assert result.dropped == []
    assert result.outcome.degraded is True
    failures = result.outcome.failures
    assert failures[0].index == 1
    assert failures[0].total == 1
    assert failures[0].paths == ("app.py",)
    assert failures[0].reason.startswith("AuditError:")


def test_diff_rounds_carry_only_findings_for_the_current_batch(monkeypatch):
    """Prior findings cannot dilute an unrelated diff unit on later rounds."""
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    other = "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    seen: list[tuple[int, str, tuple[str, ...]]] = []

    def execute(round_no, unit, known):
        path = "app.py" if "app.py" in unit.diff else "b.py"
        seen.append((round_no, path, tuple(finding.file for finding in known)))
        findings = (
            [Finding(file=path, line=1, severity="HIGH", category="other", description=path)] if round_no == 1 else []
        )
        return ReviewCycle(findings=findings)

    outcome = run_batches(
        _SRC + other,
        execute,
        plan=review_plan("adversarial", max_rounds=2, converge_after=1),
        accumulator=role_accumulator(),
        concurrency=1,
    )

    assert seen == [
        (1, "app.py", ()),
        (1, "b.py", ()),
        (2, "app.py", ("app.py",)),
        (2, "b.py", ("b.py",)),
    ]
    assert outcome.complete is True


def test_diff_batches_support_explicit_concurrent_execution():
    barrier = Barrier(2)
    units = [
        DiffUnit(index=1, total=2, diff=_DIFF, paths=("app.py",)),
        DiffUnit(index=2, total=2, diff=_DIFF, paths=("other.py",)),
    ]

    def execute(_round_no, _unit, _known):
        barrier.wait(timeout=1)
        return ReviewCycle(findings=[])

    outcome = run_batches(
        _DIFF,
        execute,
        plan=review_plan("standard", max_rounds=1),
        accumulator=role_accumulator(),
        prepare=lambda _diff: units,
        concurrency=2,
    )

    assert outcome.complete is True
