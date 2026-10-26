"""Engine tests cover grounded judgment, the review unit scheduler, and the review outcome."""

import pytest

from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
)
from cyberjury.review.engine import (
    ReviewCycle,
    ReviewOutcome,
    extend_review_outcome,
    run_grounded_judgment,
    run_review_units,
)
from cyberjury.review.exchange import EvidenceJudgment
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.union import FindingAccumulator
from tests.review.support import StubFinding, finding_key, fold_findings


def test_grounded_judgment_assigns_finder_provenance():
    """A clean judgment returning one finding stamps found_by with the "finder" label."""
    result = run_grounded_judgment(
        GroundingContext(text="seed"),
        run_judgment=lambda _navigation: EvidenceJudgment(findings=[StubFinding("one", "a:1")]),
        finder_label="finder",
    )

    assert result.clean is True
    assert result.findings[0].found_by == ("finder",)


def test_grounded_judgment_keeps_candidates_and_carries_delivered_source():
    """A provisional finding plus src-owner coverage keep the finding, its references, and source evidence."""
    source = SourceEvidence(id="src-owner", identity="models.py:Owned:0:20", text="class Owned: owner = user")
    coverage = GroundingCoverage(required=(source.identity,), included=(source.identity,), references=(source.id,))

    result = run_grounded_judgment(
        GroundingContext(text="seed"),
        run_judgment=lambda _navigation: EvidenceJudgment(
            findings=[StubFinding("provisional", "seed:1")],
            grounding=coverage,
            source_evidence=(source,),
        ),
        finder_label="finder",
    )

    assert result.clean is True
    assert [finding.title for finding in result.findings] == ["provisional"]
    assert result.grounding.references == ("src-owner",)
    assert result.source_evidence == (source,)


def test_grounded_judgment_reports_a_raised_judgment_as_failed_work():
    """A RuntimeError in the judgment yields an unclean result with no findings and the error as reason."""

    def run_judgment(_navigation):
        raise RuntimeError("provider unavailable")

    result = run_grounded_judgment(GroundingContext(text="seed"), run_judgment=run_judgment, finder_label="finder")

    assert result.clean is False
    assert result.findings == []
    assert result.failure_reason == "RuntimeError: provider unavailable"


def test_grounded_judgment_keeps_a_current_failure():
    """A judgment's own failure_reason and unresolved "current request" survive into the result."""
    result = run_grounded_judgment(
        GroundingContext(text="seed"),
        run_judgment=lambda _navigation: EvidenceJudgment(
            findings=[],
            grounding=GroundingCoverage(unresolved=("current request",)),
            failure_reason="current request failed",
        ),
        finder_label="finder",
    )

    assert result.failure_reason
    assert result.failure_reason.startswith("current request failed")
    assert result.grounding.unresolved == ("current request",)


class _Unit(str):
    @property
    def id(self) -> str:
        return str(self)

    @property
    def paths(self) -> tuple[str, ...]:
        return (str(self),)


def _units(units, execute, **kwargs):
    return run_review_units(
        [_Unit(unit) for unit in units],
        execute=execute,
        accumulator=kwargs.pop("accumulator", None) or FindingAccumulator(key=finding_key, fold=fold_findings),
        **kwargs,
    )


def test_review_units_rejects_an_empty_worklist():
    """Missing target work cannot become a complete clean review."""
    with pytest.raises(ValueError, match="at least one review unit"):
        _units([], lambda _unit: ReviewCycle(findings=[]))


def test_review_units_report_one_merged_grounding_failure():
    """Two units sharing the unresolved a.ts:helper evidence mention it only once in the failure reason."""
    coverage = GroundingCoverage(unresolved=("a.ts:helper",))

    outcome = _units(["one", "two"], lambda _unit: ReviewCycle(findings=[], grounding=coverage))

    assert outcome.failure_reason.count("a.ts:helper") == 1


def test_review_outcome_rejects_every_incomplete_state():
    """Both targets derive success from the same completion conditions."""
    finding = StubFinding("one", "a:1")

    assert ReviewOutcome(findings=(finding,)).complete is True
    assert ReviewOutcome(findings=(finding,), incomplete=(finding,)).complete is False
    assert ReviewOutcome(findings=(finding,), errors=1).complete is False
    assert ReviewOutcome(findings=(finding,), failure_reason="failed").complete is False
    assert (
        ReviewOutcome(
            findings=(finding,),
            grounding=GroundingCoverage(required=("a.py:helper",), omitted=("a.py:helper",)),
        ).complete
        is False
    )


def test_postprocessing_preserves_the_shared_completion_state():
    """Target filtering and issue grouping cannot drop prior completion state."""
    finding = StubFinding("one", "a:1")
    base = ReviewOutcome(findings=(finding,), errors=1, failure_reason="unit failed")

    outcome = extend_review_outcome(base, findings=[finding], incomplete=[finding], errors=1)

    assert outcome.errors == 2
    assert outcome.failure_reason == "unit failed"
    assert outcome.incomplete == (finding,)


def test_postprocessing_cannot_delete_historical_failures():
    """Extending an outcome with failures=() keeps the base unit failure and the outcome stays incomplete."""
    failure = ReviewUnitFailure(index=1, total=1, paths=("a.py",), reason="failed")
    base = ReviewOutcome(findings=(), failures=(failure,))

    outcome = extend_review_outcome(base, findings=(), failures=())

    assert outcome.failures == (failure,)
    assert outcome.complete is False


def test_review_outcome_bounds_the_failure_summary():
    """A 3000-character failure reason is cut to 2000 characters ending in "[failure reason truncated]"."""
    outcome = ReviewOutcome(findings=(), failure_reason="x" * 3000)

    assert len(outcome.failure_reason) == 2000
    assert outcome.failure_reason.endswith("[failure reason truncated]")


def test_review_units_continue_past_a_failed_unit_and_record_it():
    """Unit "one" failing still runs "two", keeps its finding, and records failure index 1 of 2."""
    seen = []

    def execute(unit):
        seen.append(unit)
        if unit == "one":
            return ReviewCycle(findings=[], errors=1, failure_reason="unavailable")
        return ReviewCycle(findings=[StubFinding("two", "b:1")])

    outcome = _units(["one", "two"], execute, concurrency=1)

    assert seen == ["one", "two"]
    assert [finding.title for finding in outcome.findings] == ["two"]
    assert outcome.errors == 1
    assert outcome.failures == (ReviewUnitFailure(index=1, total=2, paths=("one",), reason="unavailable"),)
    assert outcome.complete is False


def test_review_units_record_a_raised_unit_as_failed_work():
    """A unit raising RuntimeError is recorded as a failure with that message and counted as one error."""

    def execute(unit):
        if unit == "one":
            raise RuntimeError("provider unavailable")
        return ReviewCycle(findings=[])

    outcome = _units(["one", "two"], execute)

    assert outcome.failures[0].reason == "RuntimeError: provider unavailable"
    assert outcome.errors == 1


def test_a_failing_unit_hook_stops_the_run_instead_of_losing_its_record():
    """An on_unit hook raising "unit record write failed" propagates out of run_review_units."""

    def fail(*_args):
        raise RuntimeError("unit record write failed")

    with pytest.raises(RuntimeError, match="unit record write failed"):
        _units(["one"], lambda _unit: ReviewCycle(findings=[]), on_unit=fail)


def test_review_units_reuse_completed_units_and_retry_failed_units_keeping_their_findings():
    """Restored "done" is skipped, "failed" reruns keeping its earlier finding, and "open" runs fresh."""
    earlier = {
        "done": ReviewCycle(findings=[StubFinding("done", "d:1")]),
        "failed": ReviewCycle(findings=[StubFinding("earlier", "f:1")], errors=1),
    }
    executed = []
    completed = []

    def execute(unit):
        executed.append(unit)
        return ReviewCycle(findings=[StubFinding(f"new {unit}", f"{unit}:2")])

    outcome = _units(
        ["done", "failed", "open"],
        execute,
        restore=lambda unit: earlier.get(unit.id),
        on_unit=lambda unit, cycle, _seconds: completed.append((unit.id, [f.title for f in cycle.findings])),
    )

    assert executed == ["failed", "open"]
    assert completed == [("failed", ["earlier", "new failed"]), ("open", ["new open"])]
    assert [finding.title for finding in outcome.findings] == ["done", "earlier", "new failed", "new open"]
    assert outcome.complete is True


def test_review_unitsfold_findings_new_findings_into_the_carried_union():
    """A pre-seeded accumulator finding at c:1 stays first, followed by unit "one"'s finding at a:1."""
    accumulator = FindingAccumulator(key=finding_key, fold=fold_findings)
    accumulator.add([StubFinding("carried", "c:1")])

    def execute(unit):
        return ReviewCycle(findings=[StubFinding("one", "a:1")] if unit == "one" else [])

    outcome = _units(["one", "two"], execute, accumulator=accumulator, concurrency=1)

    assert outcome.complete is True
    assert [finding.location for finding in outcome.findings] == ["c:1", "a:1"]
