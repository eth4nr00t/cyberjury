"""Diff batch execution preserves progress, failures, and concurrency."""

import json
from threading import Barrier

from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    run_diff_review,
)
from cyberjury.review.diff.model import (
    DiffUnit,
)
from cyberjury.review.diff.runner import run_batches
from cyberjury.review.diff.union import finding_accumulator
from cyberjury.review.engine import ReviewCycle
from tests.cyberjury.review.diff.support import repository_prepare

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


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def test_diff_review_reports_one_progress_call_per_batch():
    two = _SRC + "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+y = 2\n"
    seen = []
    run_diff_review(
        two,
        provider=MockProvider(default=_reply([])),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare(max_chars=1)),
            execution=DiffExecutionOptions(on_batch=lambda done, total, secs: seen.append((done, total))),
        ),
    )
    assert seen == [(1, 2), (2, 2)]


def test_diff_review_records_failed_batch_and_continues():
    """A large diff keeps completed batch results while surfacing failed batches."""
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    findings = [
        {
            "file": "other.py",
            "line": 1,
            "severity": "HIGH",
            "category": "missing-authorization",
            "description": "unguarded sink",
            "confidence": 0.9,
        }
    ]
    provider = MockProvider(
        responses=[
            "not json",
            _reply(findings),
            _confirmed_reply(findings),
        ]
    )

    result = run_diff_review(
        _SRC + other,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare(max_chars=1)),
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


def test_diff_review_records_each_batch_when_failures_repeat():
    """Identical failures remain attributable to every incomplete batch."""
    other = "diff --git a/other.py b/other.py\n@@ -0,0 +1 @@\n+sink(user)\n"
    result = run_diff_review(
        _SRC + other,
        provider=MockProvider(default="not json"),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare(max_chars=1)),
        ),
    )

    assert result.outcome.findings == ()
    assert result.dropped == []
    assert result.outcome.degraded is True
    assert [failure.paths for failure in result.outcome.failures] == [("app.py",), ("other.py",)]


def test_diff_review_records_single_batch_failure():
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


def test_diff_batches_support_explicit_concurrent_execution():
    barrier = Barrier(2)
    units = [
        DiffUnit(index=1, total=2, diff=_DIFF, paths=("app.py",)),
        DiffUnit(index=2, total=2, diff=_DIFF, paths=("other.py",)),
    ]

    def execute(_unit):
        barrier.wait(timeout=1)
        return ReviewCycle(findings=[])

    outcome = run_batches(
        _DIFF,
        execute,
        accumulator=finding_accumulator(),
        prepare=lambda _diff: units,
        concurrency=2,
    )

    assert outcome.complete is True
    assert outcome.scheduling is not None
    assert outcome.scheduling.unit_ids == ("diff-unit-1", "diff-unit-2")
    assert outcome.scheduling.stop_reason == "complete"
