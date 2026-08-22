"""Diff reviewers parse responses and reuse evidence across knowledge packs."""

import json

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    run_diff_review,
)
from cyberjury.review.diff.prompts import standard_audit_prompt
from cyberjury.review.diff.reviewer import AuditRunner
from cyberjury.review.vulnerabilities import Vulnerability, VulnerabilityCatalog

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _reply(findings):
    return json.dumps({"findings": findings})


def test_engine_parses_findings():
    reply = _reply(
        [
            {
                "file": "app.py",
                "line": 3,
                "severity": "CRITICAL",
                "category": "sql_injection",
                "description": "string-concatenated query",
                "confidence": 0.95,
            },
        ]
    )
    out = AuditRunner(provider=MockProvider(default=reply), model="m").run(_DIFF)
    assert len(out) == 1
    assert out[0].severity == "CRITICAL"
    assert out[0].category == "sql_injection"


def test_diff_review_reports_a_malformed_finding_as_failed_work():
    provider = MockProvider(default='{"findings": [{"severity": "HIGH"}]}')

    result = run_diff_review(_DIFF, provider=provider, model="m")

    assert result.outcome.findings == []
    assert result.outcome.degraded is True
    assert "must name a source file" in result.outcome.failures[0].reason


def test_diff_review_reports_a_malformed_change_anchor_as_failed_work():
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, '
            '"change_anchor": {"file": "app.py", "line": 1, "side": "context"}}]}'
        )
    )

    result = run_diff_review(_DIFF, provider=provider, model="m")

    assert result.outcome.findings == []
    assert result.outcome.degraded is True
    assert "change_anchor is malformed" in result.outcome.failures[0].reason


def test_engine_empty_on_no_findings():
    assert AuditRunner(provider=MockProvider(default='{"findings": []}'), model="m").run(_DIFF) == []


def test_engine_raises_on_unparseable_reply():

    from cyberjury.review.diff.reviewer import AuditError

    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default="not json"), model="m").run(_DIFF)
    with pytest.raises(AuditError, match="failed audit"):
        AuditRunner(provider=MockProvider(default=""), model="m").run(_DIFF)


def test_engine_raises_on_wrong_shape_json():

    from cyberjury.review.diff.reviewer import AuditError

    for bad in ("{}", '{"result": "ok"}'):
        with pytest.raises(AuditError, match="failed audit"):
            AuditRunner(provider=MockProvider(default=bad), model="m").run(_DIFF)


def test_guides_for_diff_selects_by_path_and_content():
    from cyberjury.review.diff.reviewer import guides_for_diff

    diff = "diff --git a/app/urls.py b/app/urls.py\n+from django.urls import path\n+urlpatterns = []\n"
    notes = guides_for_diff(diff)
    assert "Django" in notes
    assert "Python" in notes
    assert guides_for_diff("+++ b/README.md\n+hello\n") == ""


def test_guides_for_diff_preserves_a_source_path_with_spaces():
    from cyberjury.review.diff.reviewer import guides_for_diff

    diff = "diff --git a/app route.py b/app route.py\n+++ b/app route.py\n+def route(): pass\n"

    assert "Python" in guides_for_diff(diff)


def test_standard_diff_audit_avoids_a_single_use_cache_write():
    """A lone standard judgment has no later call that can reuse its prefix."""
    provider = MockProvider(default='{"findings": []}')
    AuditRunner(provider=provider, model="m").run(_DIFF, vulnerabilities="VULN-X")
    call = provider.calls[0]
    prompt = call["messages"][0].content
    assert call["cache"] is False
    assert call["cache_prefix"] == ""
    assert "VULN-X" in prompt
    assert "SELECT * FROM u" in prompt


def test_standard_diff_audit_selects_vulnerabilities_from_context():
    """Repository evidence must influence knowledge selection even when the patch lacks the signal."""
    provider = MockProvider(default='{"findings": []}')
    diff = "+++ b/app.py\n@@ -0,0 +1 @@\n+token = make_token()\n"
    AuditRunner(provider=provider, model="m").run(diff, context="def make_token():\n    return uuid.uuid1().hex\n")

    prompt = provider.calls[0]["messages"][0].content

    assert "UUIDv1 is not a secret generator" in prompt
    assert "Exhaustively review the evidence for this assigned vulnerability class pack:" in prompt
    assert "insecure-cryptography" in prompt
    assert prompt.index("Exhaustively review") > prompt.index("Surrounding code")


def test_standard_diff_audit_assigns_other_selected_classes_to_other_judgments():
    """Parallel knowledge judgments must not rescan classes assigned elsewhere."""
    prompt = standard_audit_prompt(
        _DIFF,
        vulnerabilities="alpha guidance",
        vulnerability_categories=("alpha",),
        selected_vulnerability_categories=("alpha", "beta"),
    )

    assert "Do not report them here:\nbeta" in prompt
    assert "outside the complete selected class set" in prompt


def test_standard_diff_audit_reuses_evidence_across_knowledge_packs():
    """Every selected pack sees identical diff evidence before its changing guidance."""
    provider = MockProvider(default='{"findings": []}')
    runner = AuditRunner(provider=provider, model="m")
    items = tuple(
        Vulnerability(
            id=name,
            title=name,
            impact="HIGH",
            tags=(),
            aliases=(),
            selection_hints=(name,),
            body=name * 2_000,
        )
        for name in ("alpha", "beta")
    )
    runner._vulnerability_catalog = VulnerabilityCatalog(
        items=items,
        ids=frozenset(item.id for item in items),
        aliases={},
    )

    cycle = runner.review_round("+++ b/app.py\n+alpha beta\n", finder_label="finder")

    assert cycle.clean is True
    assert len(provider.calls) == 2
    assert all(call["cache"] is True for call in provider.calls)
    prefixes = [call["cache_prefix"] for call in provider.calls]
    assert prefixes[0] == prefixes[1]
    assert "alpha beta" in prefixes[0]
    assert "alphaalpha" not in prefixes[0]
    assert "alphaalpha" in provider.calls[0]["messages"][0].content
    assert "betabeta" in provider.calls[1]["messages"][0].content


def test_audit_runner_sends_the_severity_rubric():
    provider = MockProvider(default='{"findings": []}')
    AuditRunner(provider=provider, model="m").run(_DIFF)
    sent = provider.calls[0]["messages"][0].content
    assert "Grade each finding's severity on this rubric" in sent
    assert "Severity Rubric" in sent
