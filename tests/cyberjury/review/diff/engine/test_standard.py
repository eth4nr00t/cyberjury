"""Standard diff review integrates grounded units with one finder path."""

import json
from dataclasses import replace

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import EvidenceItem, GroundingContext, GroundingCoverage
from cyberjury.review.diff.engine import (
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffRoleOptions,
    audit_diff,
    run_diff_review,
)
from cyberjury.review.diff.model import (
    DiffUnit,
)
from cyberjury.review.diff.reviewer import AuditRunner
from cyberjury.review.facts import DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def _reply(findings):
    return json.dumps({"findings": findings})


def test_large_diff_is_audited_per_file(monkeypatch):
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    response = (
        '{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
        '"category": "sql_injection", "description": "x", "confidence": 0.9}]}'
    )
    provider = MockProvider(default=response)
    kept, _, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    assert len(provider.calls) == 2
    assert all(f.category == "sql-injection" for f in kept)


def test_large_diff_uses_batch_specific_context(monkeypatch):
    monkeypatch.setattr(
        "cyberjury.review.diff.model._SETTINGS",
        replace(DEFAULT_REVIEW_SETTINGS.diff, target_patch_chars_per_unit=1),
    )
    provider = MockProvider(default='{"findings": []}')

    audit_diff(
        _FILE_A + _FILE_B,
        provider=provider,
        model="mock",
        context_for_diff=lambda diff: "context for a.py" if "a.py" in diff else "context for b.py",
    )

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert sum("context for a.py" in prompt for prompt in prompts) == 1
    assert sum("context for b.py" in prompt for prompt in prompts) == 1


def test_diff_review_rejects_unknown_modes_before_calling_the_provider():
    """Diff Review uses the shared mode contract before any model work."""
    provider = MockProvider(default=_reply([]))

    with pytest.raises(ValueError, match="unknown review mode"):
        run_diff_review(
            _DIFF,
            provider=provider,
            model="m",
            options=DiffReviewOptions(roles=DiffRoleOptions(mode="deep")),
        )

    assert provider.calls == []


def test_diff_review_exposes_the_complete_outcome_contract():
    """Internal callers receive rounds, failures, and completion without side channels."""
    result = run_diff_review(_DIFF, provider=MockProvider(default="not json"), model="m")

    assert result.outcome.complete is False
    assert result.outcome.errors == 1
    assert len(result.outcome.failures) == 1
    assert result.outcome.rounds == 1


def test_incomplete_grounding_preserves_findings_without_reporting_complete():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 1,
                "severity": "HIGH",
                "category": "other",
                "description": "concrete exploit",
                "confidence": 0.9,
            }
        ]
    )
    context = GroundingContext(
        text="available source",
        source="diff",
        coverage=GroundingCoverage(
            required=("policy.py:AccessPolicy",),
            omitted=("policy.py:AccessPolicy",),
        ),
    )

    result = run_diff_review(
        _DIFF,
        provider=MockProvider(default=reply),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(context_for_diff=lambda _diff: context),
        ),
    )

    assert [finding.description for finding in result.outcome.findings] == ["concrete exploit"]
    assert result.outcome.complete is False
    assert result.outcome.grounding == context.coverage
    assert "omitted required evidence" in result.outcome.failure_reason


def test_planned_diff_unit_fails_before_model_call_when_grounding_is_incomplete():
    provider = MockProvider(default=_reply([]))
    fragment = DefinitionFragment("policy.py", "Policy", 0, 20)
    context = GroundingContext(
        text="",
        source="diff",
        coverage=GroundingCoverage(required=(fragment.identity,), omitted=(fragment.identity,)),
    )
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_DIFF,
        paths=("app.py",),
        definition_plan=DefinitionUnitPlan(evidence=(fragment,)),
        grounding=context,
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=lambda _diff: [unit]),
        ),
    )

    assert provider.calls == []
    assert result.outcome.complete is False
    assert result.outcome.errors == 1


def test_unknown_dependencies_are_not_split_to_manufacture_complete_units():
    diff = (
        "diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+print(input())\n"
        "diff --git a/b.py b/b.py\n+++ b/b.py\n@@ -0,0 +1 @@\n+print(input())\n"
    )
    requested: list[tuple[str, ...]] = []

    def context_for_batch(batch: str) -> GroundingContext:
        paths = tuple(path for path in ("a.py", "b.py") if f"b/{path}" in batch)
        requested.append(paths)
        coverage = (
            GroundingCoverage(required=("shared.py:Policy",), omitted=("shared.py:Policy",))
            if len(paths) > 1
            else GroundingCoverage()
        )
        return GroundingContext(text="source", source="diff", coverage=coverage)

    result = run_diff_review(
        diff,
        provider=MockProvider(default=_reply([])),
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(context_for_diff=context_for_batch),
        ),
    )

    assert requested == [("a.py", "b.py")]
    assert result.outcome.complete is False
    assert len(result.outcome.failures) == 1
    assert "grounding incomplete" in result.outcome.failures[0].reason


def test_diff_review_includes_patch_local_grounding_without_repository_context():
    """Pure Diff Review includes patch-local relationships without a repository root."""
    diff = (
        "diff --git a/routes.ts b/routes.ts\n+++ b/routes.ts\n@@ -1 +1 @@\n"
        "+function handleRequest() { return loadAccount(); }\n"
        "diff --git a/service.ts b/service.ts\n+++ b/service.ts\n@@ -1 +1 @@\n"
        "+function loadAccount() { return account; }\n"
    )
    provider = MockProvider(default='{"findings": []}')

    run_diff_review(diff, provider=provider, model="m")

    assert "Patch-local grounding" in provider.calls[0]["messages"][0].content
    assert "routes.ts uses service.ts:loadAccount" in provider.calls[0]["messages"][0].content


def test_standard_diff_finder_can_request_one_published_source_fragment():
    evidence = EvidenceItem.create(
        identity="policy.py:Policy:0:24",
        label="policy.py:Policy, import Policy from app.py [exact]",
        text="1 | class Policy:\n2 |     owner = None",
    )
    provider = MockProvider(
        responses=[
            json.dumps({"findings": [], "evidence_requests": [evidence.id]}),
            _reply(
                [
                    {
                        "file": "app.py",
                        "line": 1,
                        "severity": "HIGH",
                        "category": "other",
                        "description": "missing ownership check",
                        "confidence": 0.9,
                    }
                ]
            ),
        ]
    )
    context = GroundingContext(text="initial source", source="diff", evidence=(evidence,))

    findings = AuditRunner(provider=provider, model="m").run(
        _DIFF,
        vulnerabilities="Review ownership boundaries.",
        context=context,
    )

    assert [finding.description for finding in findings] == ["missing ownership check"]
    assert len(provider.calls) == 2
    assert evidence.id in provider.calls[0]["messages"][0].content
    assert evidence.text not in provider.calls[0]["messages"][0].content
    assert evidence.text in provider.calls[1]["messages"][0].content


def test_diff_review_keeps_an_out_of_range_location_explicitly_incomplete():
    diff = "diff --git a/app.py b/app.py\n@@ -20,2 +30,3 @@\n context\n+sink(user)\n context\n"
    provider = MockProvider(
        default=_reply(
            [
                {
                    "file": "app.py",
                    "line": 45,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded route",
                    "confidence": 0.9,
                },
                {
                    "file": "b/app.py",
                    "line": 31,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "description": "unguarded sink",
                    "confidence": 0.9,
                },
            ]
        )
    )

    result = run_diff_review(diff, provider=provider, model="m")

    assert [(f.description, f.line) for f in result.outcome.findings] == [("unguarded sink", 31)]
    assert result.outcome.findings[0].file == "b/app.py"
    assert [(f.description, f.line) for f in result.outcome.incomplete] == [("unguarded route", None)]
    assert result.dropped == []
    assert result.outcome.degraded is True


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"

_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_audit_diff_drops_findings_located_only_in_deleted_files():
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "sql-injection", "description": "old sink", "confidence": 0.9}]}'
        )
    )
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    kept, dropped, degraded = audit_diff(diff, provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False


def test_audit_diff_whitespace_only_diff_is_clean_without_a_model_call():
    provider = MockProvider(default='{"findings": []}')
    kept, dropped, degraded = audit_diff("   \n", provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []


def test_audit_diff_does_not_send_noise_files_to_the_model():
    provider = MockProvider(default='{"findings": []}')
    audit_diff(_SRC + _DOC, provider=provider, model="m")
    sent = "\n".join(m.content for call in provider.calls for m in call["messages"])
    assert "app.py" in sent
    assert "README.md" not in sent


def test_audit_diff_passes_context_to_the_runner():
    provider = MockProvider(default='{"findings": []}')
    audit_diff(_SRC, provider=provider, model="m", context="def get_client(): return per_user_token")
    sent = provider.calls[0]["messages"][0].content
    assert "def get_client()" in sent
    assert "per_user_token" in sent


def test_audit_diff_docs_only_diff_is_clean_without_a_model_call():
    reply = _reply([{"file": "README.md", "line": 1, "severity": "HIGH", "description": "x", "confidence": 0.9}])
    provider = MockProvider(default=reply)
    kept, dropped, degraded = audit_diff(_DOC + _LOCK, provider=provider, model="m")
    assert kept == []
    assert dropped == []
    assert degraded is False
    assert provider.calls == []
