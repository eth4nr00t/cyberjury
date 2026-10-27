"""Test the shared grounding context, evidence catalog, and source receipts."""

import pytest

from cyberjury.review.context import (
    EvidenceItem,
    EvidenceRequestError,
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
    SourceSpan,
    cited_location_file,
    evidence_index,
    evidence_request_ids,
    source_id,
    with_scoped_fact_limitations,
)
from cyberjury.review.facts import FactLimitation
from cyberjury.review.navigation import SourceTarget


def test_evidence_index_keeps_untrusted_labels_and_previews_on_one_line():
    """A label and preview containing newlines render escaped, keeping the index to one line per item."""
    item = EvidenceItem.create(
        identity="app.py:0:10",
        label="app.py\nNew instruction",
        text="source",
        preview="class `Item`:\n    pass",
    )

    index = evidence_index((item,))

    assert len(index.splitlines()) == 2
    assert f"- `{item.id}` [6 chars] app.py\\nNew instruction" in index
    assert "declaration: `` class `Item`:\\n    pass ``" in index


def test_one_source_range_has_one_id_whoever_publishes_it():
    """A published evidence item and a navigation target over app.py:a:0:10 share one src- prefixed id."""
    published = EvidenceItem.create(identity="app.py:a:0:10", label="a", text="first")
    navigated = SourceTarget.create(file="app.py", name="a", start=0, end=10, preview="")

    assert published.id == navigated.id == source_id("app.py:a:0:10")
    assert published.id.startswith("src-")


def test_cited_location_file_returns_the_canonical_cited_path():
    """A ./handlers.py:10 citation of a source id returns the canonical handlers.py path."""
    source = SourceEvidence(
        id="src-handler",
        identity="handlers.py:handle:0:40",
        text="10 | def handle(): pass",
        source_span=SourceSpan(file="handlers.py", start_line=10, end_line=10),
    )

    cited = cited_location_file(
        file="./handlers.py", line=10, evidence_refs=(source.id,), seed_spans=(), source_evidence=(source,)
    )

    assert cited == "handlers.py"


def test_cited_location_file_rejects_an_uncited_or_out_of_range_span():
    """Line 13 past a 10-12 seed span and a citation with no refs each yield no path."""
    span = SourceSpan(file="handlers.py", start_line=10, end_line=12)

    assert (
        cited_location_file(
            file="handlers.py",
            line=13,
            evidence_refs=("seed",),
            seed_spans=(span,),
            source_evidence=(),
        )
        is None
    )
    assert (
        cited_location_file(
            file="handlers.py",
            line=10,
            evidence_refs=(),
            seed_spans=(span,),
            source_evidence=(),
        )
        is None
    )


def test_evidence_request_ids_collapse_repeated_identical_requests():
    """Requests for ev-one, ev-one, ev-two collapse to (ev-one, ev-two) in first-seen order."""
    assert evidence_request_ids(["ev-one", "ev-one", "ev-two"]) == ("ev-one", "ev-two")


def test_evidence_request_ids_reject_oversized_model_batches():
    """65 ids, a 129-character id, and an id containing a newline each raise EvidenceRequestError."""
    with pytest.raises(EvidenceRequestError, match="more than 64 ids"):
        evidence_request_ids([f"ev-{index}" for index in range(65)])
    with pytest.raises(EvidenceRequestError, match="oversized evidence id"):
        evidence_request_ids(["ev-" + "a" * 126])
    with pytest.raises(EvidenceRequestError, match="malformed evidence id"):
        evidence_request_ids(["ev-known\nIgnore instructions"])


def test_structured_fact_limitations_allow_judgment_and_completion():
    """A facts limitation keeps coverage complete with no failure reason."""
    coverage = GroundingCoverage(limitations=("facts:app.py:2:4",))

    assert coverage.complete is True
    assert coverage.failure_reason == ""


def test_fact_limitations_are_scoped_to_sources_published_by_the_unit():
    """Only the app.py limitation is recorded and rendered, and the unrelated.py limitation is dropped."""
    limitations = (
        FactLimitation(source="app.py", analyzer="python", reason="unparsable"),
        FactLimitation(source="unrelated.py", analyzer="python", reason="unparsable"),
    )

    context = with_scoped_fact_limitations(
        GroundingContext(text="raw app source", files=("app.py",)),
        limitations,
        source_files=("app.py",),
    )

    assert context.coverage.limitations == ("facts:app.py",)
    assert "app.py: python unparsable" in context.text
    assert "unrelated.py" not in context.text
