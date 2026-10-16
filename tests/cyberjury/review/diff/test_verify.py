"""Diff verification preserves candidates when model backed votes fail."""

from cyberjury.providers.mock import MockProvider
from tests.cyberjury.review.diff.support import reply, review
from tests.cyberjury.review.support import StubChecker, StubVerifier

_DIFF = "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _review_provider(description: str) -> MockProvider:
    return MockProvider(
        default=reply(
            [
                {
                    "file": "app.py",
                    "line": 1,
                    "severity": "HIGH",
                    "category": "missing-authorization",
                    "entrypoint": "GET /route",
                    "evidence": description,
                    "attack_path": f"public request reaches the {description}",
                }
            ]
        )
    )


def _review(provider, root, verifier, confirmers, finder_label="m"):
    return review(
        _DIFF,
        provider=provider,
        root=root,
        verifier=verifier,
        confirmers=confirmers,
        finder_label=finder_label,
    )


def _claims(*claims):
    return lambda candidate: candidate.evidence in claims


def test_diff_verification_drops_a_confirmed_refutation_under_the_finding_identity(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    result = _review(
        _review_provider("unguarded route"),
        tmp_path,
        StubVerifier(_claims("unguarded route")),
        (("confirmer", StubChecker(_claims("unguarded route"))),),
    )
    assert result.outcome.findings == ()
    [(finding, reason)] = result.verification.refuted
    assert finding.evidence == "unguarded route"
    assert reason == "app.py:1: controlling fact holds"
    assert result.outcome.complete is True
    assert result.verification.candidate_ids == (finding.candidate_id,)
    assert [record.candidate for record in result.verification.records] == [finding]


def test_diff_verification_skips_a_confirmer_that_found_the_finding(tmp_path):
    """A confirmer that surfaced a finding is not an independent deletion vote."""
    (tmp_path / "app.py").write_text("def route():\n    guard()\n    sink()\n")
    result = _review(
        _review_provider("unguarded route"),
        tmp_path,
        StubVerifier(_claims("unguarded route")),
        (("finder", StubChecker(_claims("unguarded route"))),),
        finder_label="finder",
    )
    assert [f.evidence for f in result.outcome.findings] == ["unguarded route"]
    assert result.verification.refuted == []
    assert result.outcome.complete is True


def test_diff_failed_verification_keeps_and_degrades(tmp_path):
    (tmp_path / "app.py").write_text("def route():\n    sink()\n")
    result = _review(
        _review_provider("open route"),
        tmp_path,
        StubVerifier(error=RuntimeError("rate limited")),
        (("confirmer", StubChecker(_claims("open route"))),),
    )
    assert [f.evidence for f in result.outcome.findings] == ["open route"]
    assert result.verification.refuted == []
    assert result.outcome.complete is False
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"
