"""Shared engine tests cover orchestration behavior and target adapter boundaries."""

import ast
import re
from dataclasses import dataclass
from importlib.util import resolve_name
from pathlib import Path

import pytest

from cyberjury.review.context import EvidenceItem, GroundingContext, GroundingCoverage, select_evidence
from cyberjury.review.engine import (
    ConvergenceState,
    EvidenceJudgment,
    FindingAccumulator,
    ReviewCycle,
    ReviewOutcome,
    ReviewPlan,
    RoleChallenge,
    RoleJudgment,
    RoleResponseError,
    extend_review_outcome,
    parse_role_response,
    review_plan,
    run_evidence_judgment,
    run_review_cycles,
    run_review_units,
    run_role_round,
    run_standard_judgments,
)
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.navigation import SourceNavigator


@dataclass(frozen=True)
class _Finding:
    title: str
    location: str
    severity: str = "HIGH"
    found_by: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


def _key(finding: _Finding) -> str:
    return finding.location


def _fold(existing: _Finding, incoming: _Finding) -> _Finding:
    labels = tuple(sorted(set(existing.found_by) | set(incoming.found_by)))
    return _Finding(
        existing.title,
        existing.location,
        existing.severity,
        labels,
        existing.evidence_refs or incoming.evidence_refs,
    )


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


def test_unknown_evidence_request_preserves_findings_and_fails_the_judgment():
    evidence = EvidenceItem.create(identity="a.py:helper:0:10", label="a.py:helper", text="1 | def helper")
    finding = _Finding("one", "a:1")

    result = run_evidence_judgment(
        GroundingContext(text="source", evidence=(evidence,)),
        ask=lambda _context: {"findings": [finding], "evidence_requests": ["ev-invented"]},
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=100,
    )

    assert result.findings == [finding]
    assert result.failure_reason == "evidence request contains unknown ids: ev-invented"
    assert result.grounding.complete is False


def test_evidence_follow_up_folds_a_repeated_finding():
    evidence = EvidenceItem.create(identity="a.py:helper:0:10", label="a.py:helper", text="1 | def helper")
    replies = iter(
        (
            {
                "findings": [_Finding("one", "a:1", found_by=("initial",))],
                "evidence_requests": [evidence.id],
            },
            {
                "findings": [_Finding("one", "a:1", found_by=("follow-up",))],
                "evidence_requests": [],
            },
        )
    )

    result = run_evidence_judgment(
        GroundingContext(text="source", evidence=(evidence,)),
        ask=lambda _context: next(replies),
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=100,
    )

    assert len(result.findings) == 1
    assert result.findings[0].found_by == ("follow-up", "initial")


def test_finding_that_cites_evidence_requested_in_the_same_reply_is_deferred():
    evidence = EvidenceItem.create(identity="a.py:helper:0:10", label="a.py:helper", text="1 | def helper")
    finding = _Finding("one", "a:1", evidence_refs=(evidence.id,))
    replies = iter(
        (
            {"findings": [finding], "evidence_requests": [evidence.id]},
            {"findings": [], "evidence_requests": []},
        )
    )

    result = run_evidence_judgment(
        GroundingContext(text="source", evidence=(evidence,)),
        ask=lambda _prompt: next(replies),
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=100,
        evidence_refs=lambda item: item.evidence_refs,
    )

    assert result.findings == []
    assert result.grounding.references == (evidence.id,)
    assert "were not accepted" in result.prompt_controls


def test_deferred_finding_is_accepted_after_requested_evidence_is_read():
    evidence = EvidenceItem.create(identity="a.py:helper:0:10", label="a.py:helper", text="1 | def helper")
    finding = _Finding("one", "a:1", evidence_refs=(evidence.id,))
    replies = iter(
        (
            {"findings": [finding], "evidence_requests": [evidence.id]},
            {"findings": [finding], "evidence_requests": []},
        )
    )

    result = run_evidence_judgment(
        GroundingContext(text="source", evidence=(evidence,)),
        ask=lambda _prompt: next(replies),
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=100,
        evidence_refs=lambda item: item.evidence_refs,
    )

    assert result.findings == [finding]
    assert result.grounding.references == (evidence.id,)


def test_published_evidence_reference_is_an_implicit_read_request():
    evidence = EvidenceItem.create(identity="a.py:helper:0:10", label="a.py:helper", text="1 | def helper")
    finding = _Finding("one", "a:1", evidence_refs=(evidence.id,))
    replies = iter(
        (
            {"findings": [finding], "evidence_requests": []},
            {"findings": [finding], "evidence_requests": []},
        )
    )

    result = run_evidence_judgment(
        GroundingContext(text="source", evidence=(evidence,)),
        ask=lambda _prompt: next(replies),
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=100,
        evidence_refs=lambda item: item.evidence_refs,
    )

    assert result.findings == [finding]
    assert result.grounding.references == (evidence.id,)


def test_source_navigation_searches_then_reads_before_forming_a_finding(tmp_path):
    source = "class Record:\n    owner = 'user'\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"models.py": {"Record": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    prompts = []
    read_target = []
    trace = []

    def ask(prompt):
        prompts.append(prompt)
        if len(prompts) == 1:
            return {
                "findings": [],
                "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
            }
        if len(prompts) == 2:
            target = re.search(r"`(src-[0-9a-f]+)`", prompt.controls)
            assert target is not None
            read_target.append(target.group(1))
            return {
                "findings": [],
                "source_queries": [{"kind": "read_source", "target": target.group(1)}],
            }
        return {
            "findings": [_Finding("one", "models.py:1", evidence_refs=(read_target[0],))],
            "source_queries": [],
        }

    result = run_evidence_judgment(
        GroundingContext(text="source", navigator=navigator),
        ask=ask,
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=10_000,
        max_followups=2,
        evidence_refs=lambda finding: finding.evidence_refs,
        trace=trace.append,
    )

    assert result.findings == [_Finding("one", "models.py:1", evidence_refs=(read_target[0],))]
    assert result.grounding.included == (f"models.py:Record:0:{len(source)}",)
    assert "owner = 'user'" in result.prompt_controls
    navigation_events = [event for event in trace if event["event"] == "navigation"]
    assert [event["requests"][0]["kind"] for event in navigation_events] == [
        "search_symbols",
        "read_source",
    ]
    assert [event["exchange"] for event in navigation_events] == [1, 2]
    assert "2 request batches remain" in prompts[0].controls
    assert "1 request batch remains" in prompts[1].controls
    assert "No evidence or source request batches remain" in prompts[2].controls


def test_source_search_reference_is_read_before_the_finding_is_accepted(tmp_path):
    source = "class Record:\n    owner = 'user'\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"models.py": {"Record": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    calls = 0
    read_target = []

    def ask(prompt):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {
                "findings": [],
                "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
            }
        target = re.search(r"`(src-[0-9a-f]+)`", prompt.controls)
        assert target is not None
        read_target.append(target.group(1))
        return {
            "findings": [_Finding("one", "models.py:1", evidence_refs=(target.group(1),))],
            "source_queries": [],
        }

    result = run_evidence_judgment(
        GroundingContext(text="source", navigator=navigator),
        ask=ask,
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=10_000,
        max_followups=2,
        evidence_refs=lambda finding: finding.evidence_refs,
    )

    assert result.findings == [_Finding("one", "models.py:1", evidence_refs=(read_target[0],))]
    assert result.grounding.references == (read_target[0],)
    assert result.grounding.complete is True


def test_source_navigation_round_limit_is_incomplete(tmp_path):
    source = "class Record:\n    pass\n"
    (tmp_path / "models.py").write_text(source, encoding="utf-8")
    navigator = SourceNavigator.from_graph(
        tmp_path,
        {
            "callgraph": {"models.py": {"Record": [{"range": [0, len(source)], "calls": []}]}},
            "imports": {},
            "references": {},
            "import_targets": {},
        },
    )
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return {
            "findings": [],
            "source_queries": [{"kind": "search_symbols", "query": "Record", "page": 0}],
        }

    result = run_evidence_judgment(
        GroundingContext(text="source", navigator=navigator),
        ask=ask,
        findings_from_reply=lambda reply: list(reply["findings"]),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        target_chars=10_000,
        max_followups=1,
    )

    assert result.failure_reason == "finder requested evidence after 1 follow ups"
    assert result.grounding.complete is False
    assert "1 request batch remains" in prompts[0].controls
    assert "No evidence or source request batches remain" in prompts[1].controls


def test_standard_judgment_preserves_evidence_failure_and_grounding():
    coverage = GroundingCoverage(unresolved=("a.py:missing",))
    finding = _Finding("one", "a:1")

    result = run_standard_judgments(
        ["only"],
        execute_judgment=lambda _item, _cache: EvidenceJudgment(
            findings=[finding],
            grounding=coverage,
            failure_reason="missing evidence",
        ),
        describe_judgment=str,
        finder_label="finder",
        accumulator=FindingAccumulator(key=_key, fold=_fold),
        key=_key,
        title=lambda item: item.title,
    )

    assert [item.title for item in result.findings] == ["one"]
    assert result.errors == 1
    assert result.failure_reason.startswith("missing evidence")
    assert result.grounding == coverage


def test_one_oversized_definition_remains_indivisible_evidence():
    evidence = EvidenceItem.create(identity="large.py:Big:0:200", label="large.py:Big", text="x" * 200)

    selected = select_evidence(
        (evidence,),
        [evidence.id],
        target_chars=100,
    )

    assert selected.text == evidence.text
    assert selected.coverage.included == (evidence.identity,)


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


def test_review_plan_rejects_a_minimum_above_its_round_cap():
    """An impossible round floor cannot become a complete review."""
    with pytest.raises(ValueError, match="min_rounds cannot exceed max_rounds"):
        review_plan("adversarial", min_rounds=2, max_rounds=1)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"mode": "deep", "max_rounds": 1}, "unknown review mode"),
        ({"mode": "standard", "max_rounds": 0, "completion": "single"}, "must be positive"),
        ({"mode": "adversarial", "min_rounds": 2, "max_rounds": 1}, "min_rounds cannot exceed"),
        ({"mode": "standard", "max_rounds": 1, "completion": "bogus"}, "unknown review completion"),
    ],
)
def test_public_review_plan_cannot_bypass_policy_validation(values, message):
    with pytest.raises(ValueError, match=message):
        ReviewPlan(**values)


def test_public_review_plan_and_factory_resolve_the_same_mode_default():
    assert ReviewPlan(mode="standard", max_rounds=1).completion == "single"
    assert ReviewPlan(mode="adversarial", max_rounds=1).completion == "converge"
    assert ReviewPlan(mode="standard", max_rounds=1) == review_plan("standard", max_rounds=1)


@pytest.mark.parametrize("completion", ["", "bogus"])
def test_review_plan_rejects_an_unknown_completion_policy_before_execution(completion):
    calls = []

    def execute(_round, _known):
        calls.append(True)
        return ReviewCycle(findings=[])

    with pytest.raises(ValueError, match="unknown review completion policy"):
        run_review_cycles(
            plan=review_plan("standard", max_rounds=1, completion=completion),
            execute=execute,
            accumulator=FindingAccumulator(key=_key, fold=_fold),
        )

    assert calls == []


def test_review_units_rejects_an_empty_worklist():
    """Missing target work cannot become a complete clean review."""
    with pytest.raises(ValueError, match="at least one review unit"):
        run_review_units(
            [],
            plan=review_plan("standard", max_rounds=1),
            execute=lambda _round, _unit, _known: ReviewCycle(findings=[]),
            accumulator=FindingAccumulator(key=_key, fold=_fold),
            failure_for=lambda index, total, unit, reason: ReviewUnitFailure(
                index=index,
                total=total,
                paths=(str(unit),),
                reason=reason,
            ),
        )


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


def test_review_cycles_report_one_merged_grounding_failure():
    coverage = GroundingCoverage(limitations=("facts:a.ts:1:1",))

    outcome = run_review_cycles(
        plan=review_plan("adversarial", max_rounds=2, converge_after=2),
        execute=lambda _round, _known: ReviewCycle(findings=[], grounding=coverage),
        accumulator=FindingAccumulator(key=_key, fold=_fold),
    )

    assert outcome.failure_reason.count("facts:a.ts:1:1") == 1


def test_review_outcome_rejects_every_incomplete_state():
    """Both targets derive success from the same completion conditions."""
    finding = _Finding("one", "a:1")

    assert ReviewOutcome(findings=[finding]).complete is True
    assert ReviewOutcome(findings=[finding], converged=False).degraded is True
    assert ReviewOutcome(findings=[finding], incomplete=[finding]).degraded is True
    assert ReviewOutcome(findings=[finding], errors=1).degraded is True
    assert ReviewOutcome(findings=[finding], failure_reason="failed").degraded is True
    assert (
        ReviewOutcome(
            findings=[finding],
            grounding=GroundingCoverage(required=("a.py:helper",), omitted=("a.py:helper",)),
        ).degraded
        is True
    )


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


def test_cycle_failure_reason_survives_later_clean_cycle():
    """Historical failures remain diagnosable when independent cycles continue."""
    seen = []

    def execute(round_no, _known):
        seen.append(round_no)
        if round_no == 1:
            return ReviewCycle(findings=[], errors=1, failure_reason="unavailable")
        return ReviewCycle(findings=[])

    outcome = run_review_cycles(
        plan=review_plan(
            "adversarial",
            max_rounds=2,
            converge_after=1,
            stop_on_failure=False,
        ),
        execute=execute,
        accumulator=FindingAccumulator(key=_key, fold=_fold),
    )

    assert seen == [1, 2]
    assert outcome.errors == 1
    assert "unavailable" in outcome.failure_reason


def test_unit_fanout_retains_recovered_failures_for_resume():
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
    assert len(outcome.failures) == 1
    assert outcome.failures[0].paths == ("two",)
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


_REVIEW_ROOT = Path(__file__).resolve().parents[3] / "cyberjury" / "review"

_PROFILES_ROOT = _REVIEW_ROOT.parent / "profiles"

_TARGET_MODULES = ("cyberjury.review.diff", "cyberjury.review.repository")

_COMMON_ADAPTERS = {
    "__init__.py",
    "context.py",
    "engine.py",
    "model.py",
    "prompts.py",
    "reviewer.py",
    "runner.py",
    "union.py",
    "verify.py",
}

_COMMON_FACTS_MODULES = {"__init__.py", "analyzer.py", "backend.py", "graph.py", "resolver.py"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_path = path.relative_to(_REVIEW_ROOT.parents[1]).with_suffix("")
    package_parts = module_path.parts if path.name == "__init__.py" else module_path.parts[:-1]
    package = ".".join(package_parts)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            modules.add(resolve_name(f"{'.' * node.level}{module}", package) if node.level else module)
    return modules


def _names_imported_from(path: Path, module: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == module
        for alias in node.names
    }


def _top_level_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)}


def test_review_targets_use_the_same_stage_modules():
    """Only repository workspace setup and gating justify target-only modules."""
    diff_modules = {path.name for path in (_REVIEW_ROOT / "diff").glob("*.py")}
    repository_modules = {path.name for path in (_REVIEW_ROOT / "repository").glob("*.py")}

    assert diff_modules == _COMMON_ADAPTERS
    assert repository_modules == _COMMON_ADAPTERS | {"gate.py", "scaffold.py"}


def test_profile_facts_use_the_same_stage_modules():
    """Profile toolchains vary while their analysis pipeline keeps one shape."""
    for profile in ("web", "evm"):
        modules = {path.name for path in (_PROFILES_ROOT / profile / "facts").glob("*.py")}
        assert modules == _COMMON_FACTS_MODULES


def test_profile_facts_use_one_way_stage_dependencies():
    """Each profile coordinates analyzer, resolver, and graph work only in its backend."""
    allowed = {
        "analyzer.py": set(),
        "resolver.py": {"analyzer"},
        "graph.py": {"analyzer", "resolver"},
        "backend.py": {"analyzer", "resolver", "graph"},
    }
    for profile in ("web", "evm"):
        package = f"cyberjury.profiles.{profile}.facts"
        for module, expected in allowed.items():
            imported = {
                name.rsplit(".", 1)[-1]
                for name in _imports(_PROFILES_ROOT / profile / "facts" / module)
                if name.startswith(f"{package}.")
            }
            assert imported <= expected


def test_profile_facts_stage_names_keep_the_same_public_responsibilities():
    for profile, resolver_entry in (("web", "resolve_repository"), ("evm", "resolve_project")):
        facts = _PROFILES_ROOT / profile / "facts"

        assert any(name.startswith("analyze") for name in _top_level_names(facts / "analyzer.py"))
        resolver_names = _top_level_names(facts / "resolver.py")
        graph_names = _top_level_names(facts / "graph.py")
        assert {resolver_entry, "resolve_dependencies"} <= resolver_names
        assert "resolve_dependencies" not in graph_names
        assert {"build_graph", "facts_from_graph"} <= graph_names
        assert "extract" in {
            child.name
            for node in ast.parse((facts / "backend.py").read_text(encoding="utf-8")).body
            if isinstance(node, ast.ClassDef)
            for child in node.body
            if isinstance(child, ast.FunctionDef)
        }


def test_profile_native_tool_imports_stop_at_the_analyzer_boundary():
    for profile, native_package in (("web", "tree_sitter"), ("evm", "slither")):
        facts = _PROFILES_ROOT / profile / "facts"
        analyzer_imports = _imports(facts / "analyzer.py")
        assert any(name == native_package or name.startswith(f"{native_package}.") for name in analyzer_imports)

        for module in ("resolver.py", "graph.py"):
            imports = _imports(facts / module)
            assert not any(name == native_package or name.startswith(f"{native_package}.") for name in imports)


def test_target_runners_delegate_fanout_to_the_shared_engine():
    """Runners own worklists without taking back role execution."""
    for target in ("diff", "repository"):
        imported = _names_imported_from(_REVIEW_ROOT / target / "runner.py", "cyberjury.review.engine")
        assert "run_review_units" in imported
        assert "run_role_round" not in imported


def test_target_reviewers_delegate_role_contracts_to_the_shared_engine():
    """Both reviewer adapters must use one parsing and role execution contract."""
    for target in ("diff", "repository"):
        imported = _names_imported_from(_REVIEW_ROOT / target / "reviewer.py", "cyberjury.review.engine")
        assert {"RoleChallenge", "RoleJudgment", "parse_role_response", "run_role_round"} <= imported


def test_target_unions_and_verifiers_delegate_their_common_mechanics():
    """Target identity policies cannot duplicate accumulation or verification mechanics."""
    for target in ("diff", "repository"):
        union_imports = _names_imported_from(_REVIEW_ROOT / target / "union.py", "cyberjury.review.engine")
        verify_imports = _names_imported_from(
            _REVIEW_ROOT / target / "verify.py",
            "cyberjury.review.verification",
        )
        assert "FindingAccumulator" in union_imports
        assert "verify_findings" in verify_imports


def test_shared_review_modules_do_not_depend_on_target_implementations():
    """A shared primitive cannot acquire a Diff Review or Repository Review dependency."""
    violations = {
        path.name: sorted(module for module in _imports(path) if module.startswith(_TARGET_MODULES))
        for path in _REVIEW_ROOT.glob("*.py")
    }

    assert not {path: modules for path, modules in violations.items() if modules}


def test_review_targets_do_not_depend_on_each_other():
    """Target adapters meet only through modules owned by the shared review layer."""
    violations: dict[str, list[str]] = {}
    for target, forbidden in (("diff", _TARGET_MODULES[1]), ("repository", _TARGET_MODULES[0])):
        for path in (_REVIEW_ROOT / target).rglob("*.py"):
            imports = sorted(module for module in _imports(path) if module.startswith(forbidden))
            if imports:
                violations[str(path.relative_to(_REVIEW_ROOT))] = imports

    assert not violations
