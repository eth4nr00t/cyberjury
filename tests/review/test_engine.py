"""Engine tests cover grounded judgment, the review unit scheduler, and the review outcome."""

import pytest

from cyberjury.review.context import (
    GroundingContext,
    GroundingCoverage,
    SourceEvidence,
)
from cyberjury.review.engine import ReviewCycle, ReviewOutcome, run_grounded_judgment, run_review_units
from cyberjury.review.exchange import EvidenceJudgment
from cyberjury.review.failures import ReviewUnitFailure
from tests.review.support import stub_finding


def test_grounded_judgment_keeps_candidates_and_carries_delivered_source():
    """A provisional finding plus src-owner coverage keep the finding, its references, and source evidence."""
    source = SourceEvidence(id="src-owner", identity="models.py:Owned:0:20", text="class Owned: owner = user")
    coverage = GroundingCoverage(included=(source.identity,), references=(source.id,))

    result = run_grounded_judgment(
        GroundingContext(text="seed"),
        run_judgment=lambda _navigation: EvidenceJudgment(
            findings=[stub_finding("provisional", "seed:1")],
            grounding=coverage,
            source_evidence=(source,),
        ),
    )

    assert result.clean is True
    assert [finding.title for finding in result.findings] == ["provisional"]
    assert result.grounding.references == ("src-owner",)
    assert result.source_evidence == (source,)


def test_grounded_judgment_reports_a_raised_judgment_as_failed_work():
    """A RuntimeError in the judgment yields an unclean result with no findings and the error as reason."""

    def run_judgment(_navigation):
        raise RuntimeError("provider unavailable")

    result = run_grounded_judgment(GroundingContext(text="seed"), run_judgment=run_judgment)

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
    values = {
        "concurrency": 1,
        "restore": lambda _unit: None,
        "on_unit": lambda *_args: None,
    }
    return run_review_units([_Unit(unit) for unit in units], execute=execute, **(values | kwargs))


def test_review_units_record_an_unresolved_grounding_as_a_unit_failure():
    """A unit whose grounding leaves a.ts:helper unresolved fails with that grounding reason."""
    coverage = GroundingCoverage(unresolved=("a.ts:helper",))

    outcome = _units(["one"], lambda _unit: ReviewCycle(findings=[], grounding=coverage))

    assert outcome.failures == (ReviewUnitFailure(index=1, total=1, paths=("one",), reason=coverage.failure_reason),)


def test_review_outcome_is_complete_exactly_when_no_unit_failed():
    """An outcome with a unit failure is incomplete, and one without is complete."""
    failure = ReviewUnitFailure(index=1, total=1, paths=("a.py",), reason="failed")

    assert ReviewOutcome(findings=()).complete is True
    assert ReviewOutcome(findings=(), failures=(failure,)).complete is False


def test_review_units_continue_past_a_failed_unit_and_record_it():
    """Unit "one" failing still runs "two", keeps its finding, and records failure index 1 of 2."""
    seen = []

    def execute(unit):
        seen.append(unit)
        if unit == "one":
            return ReviewCycle(findings=[], failure_reason="unavailable")
        return ReviewCycle(findings=[stub_finding("two", "b:1")])

    outcome = _units(["one", "two"], execute, concurrency=1)

    assert seen == ["one", "two"]
    assert [finding.title for finding in outcome.findings] == ["two"]
    assert outcome.failures == (ReviewUnitFailure(index=1, total=2, paths=("one",), reason="unavailable"),)
    assert outcome.complete is False


def test_review_units_record_a_raised_unit_as_failed_work():
    """A unit raising RuntimeError is recorded as a failure with that message."""

    def execute(unit):
        if unit == "one":
            raise RuntimeError("provider unavailable")
        return ReviewCycle(findings=[])

    outcome = _units(["one", "two"], execute)

    assert [failure.reason for failure in outcome.failures] == ["RuntimeError: provider unavailable"]


def test_a_failing_unit_hook_stops_the_run_instead_of_losing_its_record():
    """An on_unit hook raising "unit record write failed" propagates out of run_review_units."""

    def fail(*_args):
        raise RuntimeError("unit record write failed")

    with pytest.raises(RuntimeError, match="unit record write failed"):
        _units(["one"], lambda _unit: ReviewCycle(findings=[]), on_unit=fail)


def test_review_units_reuse_completed_units_and_retry_failed_units_keeping_their_findings():
    """Restored "done" is skipped, "failed" reruns keeping its earlier finding, and "open" runs fresh."""
    earlier = {
        "done": ReviewCycle(findings=[stub_finding("done", "d:1")]),
        "failed": ReviewCycle(findings=[stub_finding("earlier", "f:1")], failure_reason="unit review did not complete"),
    }
    executed = []
    completed = []

    def execute(unit):
        executed.append(unit)
        return ReviewCycle(findings=[stub_finding(f"new {unit}", f"{unit}:2")])

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


def test_review_units_name_the_findings_only_failed_units_reported():
    """A finding from failed unit "one" is unfinished unless clean unit "two" reports it too."""
    shared, failed_only = stub_finding("shared", "a:1"), stub_finding("failed only", "a:2")

    def execute(unit):
        if unit == "one":
            return ReviewCycle(findings=[shared, failed_only], failure_reason="unavailable")
        return ReviewCycle(findings=[shared])

    outcome = _units(["one", "two"], execute)

    assert outcome.unfinished == frozenset({failed_only.candidate_id})
