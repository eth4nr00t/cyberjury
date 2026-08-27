"""Diff verification preserves candidates when model backed votes fail."""

from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import (
    DiffReviewOptions,
    DiffVerificationOptions,
    audit_diff,
    run_diff_review,
)
from cyberjury.review.verification import RefutationChecker, Verdict, Verifier

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


class _Verifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        if candidate.title in self.refute:
            return Verdict(real=False, reason="guard dominates the route")
        return Verdict(real=True, reason="")


class _Checker(RefutationChecker):
    def __init__(self, holds_titles):
        self.holds_titles = set(holds_titles)

    def holds(self, candidate, reason, root):
        return candidate.title in self.holds_titles


class _BrokenVerifier(Verifier):
    def verify(self, candidate, root):
        raise RuntimeError("rate limited")


def test_diff_verification_failure_keeps_its_provider_reason(tmp_path):
    """The final incomplete outcome must explain why verification failed."""
    (tmp_path / "app.py").write_text("sink()\n")
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "unguarded route", "confidence": 0.9, '
            '"evidence_refs": ["seed"]}]}'
        )
    )

    result = run_diff_review(
        _DIFF,
        provider=provider,
        model="m",
        options=DiffReviewOptions(
            verification=DiffVerificationOptions(root=str(tmp_path), verifier=_BrokenVerifier()),
        ),
    )

    assert result.outcome.degraded is True
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"


def test_audit_diff_verification_drops_a_confirmed_refutation(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "unguarded route", "confidence": 0.9, '
            '"evidence_refs": ["seed"]}]}'
        )
    )
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
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
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "unguarded route", "confidence": 0.9, '
            '"evidence_refs": ["seed"]}]}'
        )
    )
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
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
    provider = MockProvider(
        default=(
            '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
            '"category": "missing-authorization", "description": "open route", "confidence": 0.9, '
            '"evidence_refs": ["seed"]}]}'
        )
    )
    kept, dropped, degraded = audit_diff(
        _DIFF,
        provider=provider,
        model="m",
        verification_root=str(tmp_path),
        verifier=_BrokenVerifier(),
        verification_confirmers=[("", _Checker(["open route"]))],
    )
    assert [f.description for f in kept] == ["open route"]
    assert dropped == []
    assert degraded is True
