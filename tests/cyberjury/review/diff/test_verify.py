"""Diff verification preserves candidates when model backed votes fail."""

import json

import pytest

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffRoleOptions,
    DiffVerificationOptions,
    _analyze_candidate_coverage,
    audit_diff,
    run_diff_review,
)
from cyberjury.review.diff.verify import DiffVerifyResult
from cyberjury.review.verification import RefutationCheck, RefutationChecker, Verdict, Verifier
from tests.cyberjury.review.diff.support import repository_prepare

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _review_reply(description: str) -> str:
    return json.dumps(
        {
            "findings": [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "entrypoint": "GET /route",
                    "description": description,
                    "exploit_scenario": f"public request reaches the {description}",
                    "confidence": 0.9,
                    "change_anchor": {"file": "app.py", "line": 1, "side": "new"},
                    "evidence_refs": ["seed"],
                }
            ],
            "assessments": [
                {
                    "category": "sql-injection",
                    "decision": "not_exploitable",
                    "reason": "the assigned injection class is not established",
                    "evidence_refs": ["seed"],
                }
            ],
        }
    )


class _Verifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        if candidate.title in self.refute:
            return Verdict(
                real=False,
                reason="guard dominates the route",
                control_file=candidate.file,
                control_line=candidate.line,
            )
        return Verdict(real=True, reason="")


class _Checker(RefutationChecker):
    def __init__(self, holds_titles):
        self.holds_titles = set(holds_titles)

    def holds(self, candidate, reason, root):
        holds = candidate.title in self.holds_titles
        return RefutationCheck(holds=holds, reason="control covers path" if holds else "control misses path")


class _BrokenVerifier(Verifier):
    def verify(self, candidate, root):
        raise RuntimeError("rate limited")


def test_diff_coverage_analysis_uses_verified_candidates_only():
    account = Finding(file="accounts.py", line=10, category="missing-authorization", description="account path")
    rule = Finding(file="rules.py", line=20, category="missing-authorization", description="rule path")
    umbrella = Finding(
        file="urls.py",
        line=30,
        category="missing-authorization",
        description="account and rule paths",
    )
    provider = MockProvider(
        default=(
            '{"decisions":['
            '{"candidate_id":"candidate-1","verdict":"independent","represented_by":[],"reason":"specific"},'
            '{"candidate_id":"candidate-2","verdict":"independent","represented_by":[],"reason":"specific"},'
            '{"candidate_id":"candidate-3","verdict":"represented",'
            '"represented_by":["candidate-1","candidate-2"],"reason":"no residual path"}'
            "]}"
        )
    )

    result = _analyze_candidate_coverage(
        DiffVerifyResult(findings=[account, rule, umbrella], dropped=[]),
        provider,
        "model",
        DiffRoleOptions(),
        None,
        enabled=True,
    )

    assert result.findings == [account, rule, umbrella]
    assert result.suggestions[0].finding == umbrella


def test_diff_does_not_analyze_coverage_for_unverified_candidates():
    findings = [
        Finding(file="one.py", line=1, category="missing-authorization", description="one"),
        Finding(file="two.py", line=2, category="missing-authorization", description="two"),
    ]
    provider = MockProvider(default='{"decisions":[]}')

    result = _analyze_candidate_coverage(
        DiffVerifyResult(findings=findings, dropped=[]),
        provider,
        "model",
        DiffRoleOptions(),
        None,
        enabled=False,
    )

    assert result.findings == findings
    assert provider.calls == []


def test_diff_verification_failure_keeps_its_provider_reason(tmp_path):
    """The final incomplete outcome must explain why verification failed."""
    (tmp_path / "app.py").write_text("sink()\n")
    provider = MockProvider(default=_review_reply("unguarded route"))

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
            verification=DiffVerificationOptions(root=str(tmp_path), verifier=_BrokenVerifier()),
        ),
    )

    assert result.outcome.degraded is True
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"


def test_diff_verification_configuration_fails_before_review_calls():
    provider = MockProvider(default='{"findings": []}')

    with pytest.raises(ValueError, match="verification_root is required"):
        run_diff_review(
            _DIFF,
            provider=provider,
            model="m",
            options=DiffReviewOptions(
                grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
                verification=DiffVerificationOptions(verifier=_Verifier([])),
            ),
        )

    assert provider.calls == []


def test_audit_diff_verification_drops_a_confirmed_refutation(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    provider = MockProvider(default=_review_reply("unguarded route"))
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        prepare_diff=repository_prepare(),
        verification_root=str(tmp_path),
        verifier=_Verifier(["unguarded route"]),
        verification_confirmers=[("", _Checker(["unguarded route"]))],
    )
    assert kept == []
    assert dropped[0][0].description == "unguarded route"
    assert "verified false positive" in dropped[0][1]
    assert degraded is False


def test_audit_diff_verification_skips_a_confirmer_that_found_the_finding(tmp_path):
    """A confirmer that surfaced a finding is not an independent deletion vote."""
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    provider = MockProvider(default=_review_reply("unguarded route"))
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        prepare_diff=repository_prepare(),
        verification_root=str(tmp_path),
        verifier=_Verifier(["unguarded route"]),
        verification_confirmers=[("finder", _Checker(["unguarded route"]))],
        verification_found_by=("finder",),
    )
    assert [f.description for f in kept] == ["unguarded route"]
    assert dropped == []
    assert degraded is False


def test_audit_diff_failed_verification_keeps_and_degrades(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    sink()\n")
    provider = MockProvider(default=_review_reply("open route"))
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        prepare_diff=repository_prepare(),
        verification_root=str(tmp_path),
        verifier=_BrokenVerifier(),
        verification_confirmers=[("", _Checker(["open route"]))],
    )
    assert [f.description for f in kept] == ["open route"]
    assert dropped == []
    assert degraded is True
