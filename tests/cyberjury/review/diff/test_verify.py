"""Diff verification preserves candidates when model backed votes fail."""

import json

import pytest

from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffVerificationOptions,
    run_diff_review,
)
from cyberjury.review.diff.verify import _candidates_from_findings
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
                    "recommendation": "enforce the missing authorization control",
                    "confidence": 0.9,
                    "change_anchor": {"file": "app.py", "line": 1, "side": "new"},
                    "evidence_refs": ["seed"],
                }
            ],
            "evidence_requests": [],
            "source_queries": [],
        }
    )


def _confirmed_review_reply(description: str) -> str:
    return _review_reply(description)


def _review_provider(description: str) -> MockProvider:
    return MockProvider(default=_review_reply(description))


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
        return Verdict(real=True, reason="candidate remains exploitable")


class _Checker(RefutationChecker):
    def __init__(self, holds_titles):
        self.holds_titles = set(holds_titles)

    def holds(self, candidate, reason, root):
        holds = candidate.title in self.holds_titles
        return RefutationCheck(holds=holds, reason="control covers path" if holds else "control misses path")


class _BrokenVerifier(Verifier):
    def verify(self, candidate, root):
        raise RuntimeError("rate limited")


def test_diff_verification_preserves_the_finding_entrypoint():
    finding = Finding(
        file="app.py",
        line=1,
        category="missing-authorization",
        entrypoint="POST /accounts/{id}",
        description="unguarded account update",
    )

    candidates, _by_source = _candidates_from_findings([finding])

    assert candidates[0].endpoint == "POST /accounts/{id}"


def test_diff_verification_failure_keeps_its_provider_reason(tmp_path):
    """The final incomplete outcome must explain why verification failed."""
    (tmp_path / "app.py").write_text("sink()\n")
    provider = _review_provider("unguarded route")

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
            verification=DiffVerificationOptions(
                root=str(tmp_path),
                verifier=_BrokenVerifier(),
                confirmers=(("confirmer", _Checker([])),),
            ),
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


def _review(provider, verification):
    return run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            grounding=DiffGroundingOptions(prepare_diff=repository_prepare()),
            verification=verification,
        ),
    )


def test_diff_verification_drops_a_confirmed_refutation(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    result = _review(
        _review_provider("unguarded route"),
        DiffVerificationOptions(
            root=str(tmp_path),
            verifier=_Verifier(["unguarded route"]),
            confirmers=(("confirmer", _Checker(["unguarded route"])),),
        ),
    )
    assert result.outcome.findings == ()
    assert result.dropped[0][0].description == "unguarded route"
    assert "verified false positive" in result.dropped[0][1]
    assert result.outcome.degraded is False


def test_diff_verification_skips_a_confirmer_that_found_the_finding(tmp_path):
    """A confirmer that surfaced a finding is not an independent deletion vote."""
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    result = _review(
        _review_provider("unguarded route"),
        DiffVerificationOptions(
            root=str(tmp_path),
            verifier=_Verifier(["unguarded route"]),
            confirmers=(("finder", _Checker(["unguarded route"])),),
            found_by=("finder",),
        ),
    )
    assert [f.description for f in result.outcome.findings] == ["unguarded route"]
    assert result.dropped == []
    assert result.outcome.degraded is False


def test_diff_failed_verification_keeps_and_degrades(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    sink()\n")
    result = _review(
        _review_provider("open route"),
        DiffVerificationOptions(
            root=str(tmp_path),
            verifier=_BrokenVerifier(),
            confirmers=(("confirmer", _Checker(["open route"])),),
        ),
    )
    assert [f.description for f in result.outcome.findings] == ["open route"]
    assert result.dropped == []
    assert result.outcome.degraded is True
