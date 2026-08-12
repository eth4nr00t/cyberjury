"""Shared review orchestration enforces one role and convergence contract."""

from dataclasses import dataclass

import pytest

from cyberjury.review.engine import (
    ConvergenceState,
    FindingAccumulator,
    ReviewCycle,
    ReviewOutcome,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    extend_review_outcome,
    parse_role_response,
    review_plan,
    run_review_cycles,
    run_review_units,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.failures import ReviewUnitFailure


@dataclass(frozen=True)
class _Finding:
    title: str
    location: str
    severity: str = "HIGH"
    found_by: tuple[str, ...] = ()


def _key(finding: _Finding) -> str:
    return finding.location


def _fold(existing: _Finding, incoming: _Finding) -> _Finding:
    labels = tuple(sorted(set(existing.found_by) | set(incoming.found_by)))
    return _Finding(existing.title, existing.location, existing.severity, labels)


def test_standard_round_assigns_finder_provenance():
    """Standard and adversarial callers must not attach provenance differently."""
    result = run_role_round(
        find=lambda: [_Finding("one", "a:1")],
        finder_label="finder",
        key=_key,
        title=lambda finding: finding.title,
    )

    assert result.clean is True
    assert result.findings[0].found_by == ("finder",)


def test_standard_judgments_merge_successes_and_surface_each_failure():
    """One failed knowledge pack cannot erase siblings or become a clean cycle."""
    calls = []
    progress = []

    def execute(item, cache):
        calls.append((item, cache))
        if item == "two":
            raise RuntimeError("unavailable")
        return [_Finding(item, f"{item}:1")]

    result = run_standard_judgments(
        ["one", "two", "three"],
        execute_judgment=execute,
        describe_judgment=str,
        finder_label="finder",
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        key=_key,
        title=lambda finding: finding.title,
        on_judgment=lambda index, total, label, seconds: progress.append((index, total, label, seconds)),
    )

    assert calls == [("one", True), ("two", True), ("three", True)]
    assert [finding.title for finding in result.findings] == ["one", "three"]
    assert [finding.found_by for finding in result.findings] == [("finder",), ("finder",)]
    assert result.errors == 1
    assert result.failure_reason.startswith("RuntimeError: unavailable")
    assert "knowledge judgment 2/3 for two" in result.failure_reason
    assert [(index, total, label) for index, total, label, _seconds in progress] == [
        (1, 3, "one"),
        (2, 3, "two"),
        (3, 3, "three"),
    ]
    assert all(seconds >= 0 for _index, _total, _label, seconds in progress)


def test_single_standard_judgment_avoids_a_cache_write_with_no_reuse():
    """One Finder call has no sibling that can consume a newly written prefix."""
    cache_values = []

    result = run_standard_judgments(
        ["only"],
        execute_judgment=lambda _item, cache: cache_values.append(cache) or [],
        describe_judgment=str,
        finder_label="finder",
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        key=_key,
        title=lambda finding: finding.title,
    )

    assert cache_values == [False]
    assert result.clean is True


def test_standard_judgments_reject_an_empty_worklist():
    """A planner defect cannot turn missing review work into a clean result."""
    with pytest.raises(ValueError, match="at least one judgment"):
        run_standard_judgments(
            [],
            execute_judgment=lambda _item, _cache: [],
            describe_judgment=str,
            finder_label="finder",
            accumulator=FindingAccumulator(key=_key, fold=_fold),
            key=_key,
            title=lambda finding: finding.title,
        )


def test_judge_failure_preserves_both_independent_finding_sets():
    """A failed final role cannot erase candidates produced by completed roles."""

    def challenge(_findings):
        return RoleChallenge(rebuttals=[], new_findings=[_Finding("two", "b:2")])

    def judge(_findings, _challenged):
        raise RuntimeError("judge unavailable")

    result = run_role_round(
        find=lambda: [_Finding("one", "a:1")],
        finder_label="finder",
        challenge=challenge,
        challenger_label="challenger",
        judge=judge,
        judge_label="judge",
        key=_key,
        title=lambda finding: finding.title,
    )

    assert result.clean is False
    assert result.failure_role == "judge"
    assert [finding.title for finding in result.findings] == ["one", "two"]
    assert [finding.found_by for finding in result.findings] == [("finder",), ("challenger",)]


def test_successful_judge_labels_candidates_by_their_origin():
    """A Judge decision keeps the independent role provenance needed by verification."""
    finder = _Finding("one", "a:1")
    challenger = _Finding("two", "b:2")
    result = run_role_round(
        find=lambda: [finder],
        finder_label="finder",
        challenge=lambda _findings: RoleChallenge(rebuttals=[], new_findings=[challenger]),
        challenger_label="challenger",
        judge=lambda findings, challenged: RoleJudgment(findings=[*findings, *challenged.new_findings]),
        judge_label="judge",
        key=_key,
        title=lambda finding: finding.title,
    )

    assert [finding.found_by for finding in result.findings] == [("finder",), ("challenger",)]


def test_role_response_requires_every_declared_field():
    """A partial role object is failed work rather than a clean empty result."""
    with pytest.raises(RoleResponseError, match="new_findings"):
        parse_role_response(
            '{"rebuttals": []}',
            role="challenger",
            required_keys=("rebuttals", "new_findings"),
        )


def test_role_response_requires_list_values_for_role_collections():
    """A present but malformed role collection is failed work."""
    with pytest.raises(RoleResponseError, match="non-list required fields: findings"):
        parse_role_response(
            '{"findings": "none"}',
            role="finder",
            required_keys=("findings",),
        )


def test_role_response_validates_optional_collections_when_present():
    """An optional role collection cannot bypass the shared response contract."""
    with pytest.raises(RoleResponseError, match="non-list optional fields: pending"):
        parse_role_response(
            '{"findings": [], "pending": "later"}',
            role="judge",
            required_keys=("findings",),
            optional_list_keys=("pending",),
        )


def test_review_plan_rejects_unknown_modes_before_execution():
    """Every target accepts the same finite review mode vocabulary."""
    with pytest.raises(ValueError, match="unknown review mode"):
        review_plan("deep", max_rounds=1)


def test_accumulation_and_convergence_share_clean_round_semantics():
    """Failed and pending rounds cannot advance a monotonic union to convergence."""
    accumulator = FindingAccumulator(key=_key, fold=_fold)
    convergence = ConvergenceState(converge_after=2)

    convergence.record(accumulator.add([_Finding("one", "a:1")]))
    convergence.record(accumulator.add([]), clean=False)
    convergence.record(accumulator.add([]), pending=True)
    assert convergence.converged is False

    convergence.record(accumulator.add([]))
    convergence.record(accumulator.add([]))
    assert convergence.converged is True
    assert [finding.title for finding in accumulator.findings] == ["one"]


def test_review_outcome_rejects_every_incomplete_state():
    """Both targets derive success from the same completion conditions."""
    finding = _Finding("one", "a:1")

    assert ReviewOutcome(findings=[finding]).complete is True
    assert ReviewOutcome(findings=[finding], converged=False).degraded is True
    assert ReviewOutcome(findings=[finding], incomplete=[finding]).degraded is True
    assert ReviewOutcome(findings=[finding], errors=1).degraded is True
    assert ReviewOutcome(findings=[finding], failure_reason="failed").degraded is True


def test_postprocessing_preserves_the_shared_completion_policy():
    """Target filtering and verification cannot drop prior completion state."""
    finding = _Finding("one", "a:1")
    base = ReviewOutcome(
        findings=[finding],
        pending=[{"target": "a:2"}],
        converged=False,
        requires_convergence=False,
        rounds=1,
    )

    outcome = extend_review_outcome(base, findings=[finding], incomplete=[finding], errors=1)

    assert outcome.pending == base.pending
    assert outcome.requires_convergence is False
    assert outcome.rounds == 1
    assert outcome.errors == 1
    assert outcome.incomplete == [finding]


def test_accumulator_stabilizes_severity_for_every_target():
    """Severity voting belongs to the shared union rather than one target adapter."""
    accumulator = FindingAccumulator(
        key=_key,
        fold=_fold,
        grade=lambda finding: finding.severity,
        with_grade=lambda finding, severity: _Finding(
            finding.title,
            finding.location,
            severity,
            finding.found_by,
        ),
    )

    for severity in ("LOW", "CRITICAL", "HIGH"):
        accumulator.add([_Finding("one", "a:1", severity)])

    assert accumulator.findings[0].severity == "HIGH"


def test_standard_cycle_completes_once_without_claiming_convergence():
    """A standard plan completes one clean Finder cycle without a convergence claim."""
    calls = []
    accumulator = FindingAccumulator(key=_key, fold=_fold)

    def execute(round_no, _known):
        calls.append(round_no)
        return ReviewCycle(findings=[_Finding("one", "a:1")])

    outcome = run_review_cycles(
        plan=review_plan("standard", max_rounds=3),
        execute=execute,
        accumulator=accumulator,
    )

    assert calls == [1]
    assert outcome.complete is True
    assert outcome.converged is False
    assert outcome.requires_convergence is False


def test_adversarial_cycles_require_clean_empty_rounds():
    """An adversarial plan stops only after its coded convergence condition."""
    accumulator = FindingAccumulator(key=_key, fold=_fold)

    def execute(round_no, _known):
        findings = [_Finding("one", "a:1")] if round_no == 1 else []
        return ReviewCycle(findings=findings)

    outcome = run_review_cycles(
        plan=review_plan("adversarial", max_rounds=5, converge_after=2),
        execute=execute,
        accumulator=accumulator,
    )

    assert outcome.complete is True
    assert outcome.converged is True
    assert outcome.rounds == 3


def test_pending_work_blocks_shared_completion():
    """A clean model call with an unresolved judgment is still incomplete work."""
    outcome = run_review_cycles(
        plan=review_plan("adversarial", max_rounds=1, converge_after=1),
        execute=lambda _round, _known: ReviewCycle(findings=[], pending=[{"target": "a:1"}]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
    )

    assert outcome.pending == [{"target": "a:1"}]
    assert outcome.complete is False
    assert outcome.converged is False


@pytest.mark.parametrize(("stop_on_failure", "calls"), [(True, [1]), (False, [1, 2])])
def test_failure_policy_controls_whether_later_cycles_run(stop_on_failure, calls):
    """Targets share failure accounting while choosing whether independent work continues."""
    seen = []

    def execute(round_no, _known):
        seen.append(round_no)
        if round_no == 1:
            return ReviewCycle(findings=[], errors=1, failure_reason="unavailable")
        return ReviewCycle(findings=[])

    run_review_cycles(
        plan=review_plan(
            "adversarial",
            max_rounds=2,
            converge_after=1,
            stop_on_failure=stop_on_failure,
        ),
        execute=execute,
        accumulator=FindingAccumulator(key=_key, fold=_fold),
    )

    assert seen == calls


def test_unit_fanout_separates_historical_errors_from_active_failures():
    """A recovered unit leaves an error count without remaining on the retry list."""
    units = ["one", "two"]

    def execute(round_no, unit, _known):
        if round_no == 1 and unit == "two":
            return ReviewCycle(findings=[], errors=1, failure_reason="unavailable")
        return ReviewCycle(findings=[])

    outcome = run_review_units(
        units,
        plan=review_plan("adversarial", max_rounds=2, converge_after=1, stop_on_failure=False),
        execute=execute,
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        failure_for=lambda index, total, unit, reason: ReviewUnitFailure(
            index=index,
            total=total,
            paths=(unit,),
            reason=reason,
        ),
    )

    assert outcome.errors == 1
    assert outcome.failures == []
    assert outcome.complete is False


def test_unit_fanout_shares_the_round_union_with_every_adapter():
    """Every target unit receives the same prior-round union for cross-unit convergence."""
    seen: list[tuple[int, str, tuple[str, ...]]] = []

    def execute(round_no, unit, known):
        seen.append((round_no, unit, tuple(finding.location for finding in known)))
        findings = [_Finding("one", "a:1")] if round_no == 1 and unit == "one" else []
        return ReviewCycle(findings=findings)

    outcome = run_review_units(
        ["one", "two"],
        plan=review_plan("adversarial", max_rounds=2, converge_after=1),
        execute=execute,
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        failure_for=lambda index, total, unit, reason: ReviewUnitFailure(
            index=index,
            total=total,
            paths=(unit,),
            reason=reason,
        ),
    )

    assert seen == [
        (1, "one", ()),
        (1, "two", ()),
        (2, "one", ("a:1",)),
        (2, "two", ("a:1",)),
    ]
    assert outcome.complete is True
