"""The Repository Finder locates each finding by the cited source that covers it."""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import SourceEvidence, SourceSpan
from cyberjury.review.finding import Finding
from cyberjury.review.repository.finder import locate
from tests.review.repository.support import UnitReviewError, finder, finder_reply, finding, review, source_unit


def test_repository_finding_location_must_be_covered_by_its_cited_source(tmp_path):
    """A finding at other.py citing only the app.py seed fails with "cited source receipt"."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n", encoding="utf-8")
    reply = finder_reply([finding("other.py", 2, title="wrong location")])
    reviewer = finder(MockProvider(default=reply))

    with pytest.raises(UnitReviewError, match="cited source receipt"):
        review(reviewer, source_unit(tmp_path, "app.py", name="app"))


def test_repository_location_uses_the_canonical_path_from_its_receipt():
    """A finding at ./views.py is relocated to views.py, the path of its seed source span."""
    located_finding = Finding(
        title="missing ownership check",
        severity="HIGH",
        category="other",
        file="./views.py",
        line=2,
        entrypoint="GET /accounts/<id>",
        evidence="the control is missing",
        attack_path="request reaches it",
        evidence_refs=("seed",),
    )

    located = locate(None, located_finding, (), (SourceSpan(file="views.py", start_line=1, end_line=3),))

    assert located.file == "views.py"


def test_repository_location_accepts_preexisting_source_evidence():
    """A finding citing existing SourceEvidence for service.py lines 7-8 keeps file, line 8, and refs."""
    evidence = SourceEvidence(
        id="src-existing",
        identity="service.py:load:0:20",
        text="7 | def load():\n8 |     return secret",
        source_span=SourceSpan(file="service.py", start_line=7, end_line=8),
    )
    located_finding = Finding(
        title="missing control",
        severity="HIGH",
        category="other",
        file="service.py",
        line=8,
        entrypoint="GET /accounts/<id>",
        evidence="the control is missing",
        attack_path="request reaches it",
        evidence_refs=(evidence.id,),
    )

    located = locate(None, located_finding, (evidence,), ())

    assert (located.file, located.line, located.evidence_refs) == ("service.py", 8, (evidence.id,))
