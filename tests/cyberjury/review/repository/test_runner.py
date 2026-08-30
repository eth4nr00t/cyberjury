"""The pass loop runs deterministic unit review passes to convergence."""

import pytest

from cyberjury.review.context import definition_relationships
from cyberjury.review.definitions import DefinitionDependency, DefinitionFragment, DefinitionUnitPlan
from cyberjury.review.engine import RoleJudgment, review_plan
from cyberjury.review.facts import FactLimitation
from cyberjury.review.repository.context import Unit, gather
from cyberjury.review.repository.reviewer import (
    UnitChallenge,
    UnitReviewer,
)
from cyberjury.review.repository.runner import run_passes
from cyberjury.review.repository.union import Candidate

_U = [Unit(name="u", root=".", files=())]


class _StaticReviewer(UnitReviewer):
    def __init__(self, candidates):
        self.candidates = candidates
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        return list(self.candidates)


class _NewEachPassReviewer(UnitReviewer):
    def __init__(self):
        self.n = 0

    def review(self, unit, *, shared_context=""):
        self.n += 1
        return [Candidate(title=f"f{self.n}", endpoint=f"GET /{self.n}")]


class _SecondRoundReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        if self.calls == 1:
            return [Candidate(title="A", endpoint="GET /a")]
        return [Candidate(title="B", endpoint="GET /b")]


def test_role_rounds_union_converges_then_stops_early():
    a = Candidate(title="a", endpoint="GET /1")
    reviewer = _StaticReviewer([a])
    acc = run_passes(_U, reviewer, converge_after=2, max_passes=24)

    assert {c.title for c in acc.findings} == {"a"}
    assert acc.converged
    assert reviewer.calls == 3
    assert acc.new_per_pass == [1, 0, 0]


def test_runs_to_max_passes_when_never_converges():
    reviewer = _NewEachPassReviewer()
    acc = run_passes(_U, reviewer, converge_after=2, max_passes=5)
    assert not acc.converged
    assert len(acc.new_per_pass) == 5
    assert len(acc.findings) == 5


def test_runner_rejects_more_finders_than_the_round_budget():
    reviewers = [_StaticReviewer([]) for _ in range(3)]

    with pytest.raises(ValueError, match="finder reviewers cannot run within"):
        run_passes(_U, reviewers, max_passes=2)

    assert [reviewer.calls for reviewer in reviewers] == [0, 0, 0]


def test_min_round_floor_keeps_a_run_from_one_shot():
    reviewer = _SecondRoundReviewer()
    acc = run_passes(_U, reviewer, converge_after=2, min_rounds=2, max_passes=24)
    assert {c.title for c in acc.findings} == {"A", "B"}
    assert reviewer.calls >= 2


def test_one_round_floor_can_stop_after_convergence():
    reviewer = _StaticReviewer([Candidate(title="A", endpoint="GET /a")])
    acc = run_passes(_U, reviewer, converge_after=1, min_rounds=1, max_passes=24)
    assert {c.title for c in acc.findings} == {"A"}
    assert len(acc.new_per_pass) == 2


class _FinderRoleReviewer(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def find(self, unit, *, shared_context="", known=None):
        return [Candidate(title="finder", endpoint="GET /finder")]


class _ChallengerRoleReviewer(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        return UnitChallenge(rebuttals=[], new_findings=[Candidate(title="challenger", endpoint="GET /challenger")])


class _JudgeRoleReviewer(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        return finder_findings + new_findings


def test_role_loop_unions_finder_and_challenger_candidates():
    acc = run_passes(
        _U,
        _FinderRoleReviewer(),
        challenger=_ChallengerRoleReviewer(),
        judge=_JudgeRoleReviewer(),
        converge_after=2,
        max_passes=3,
    )
    assert {c.title for c in acc.findings} == {"finder", "challenger"}
    labels = {c.title: set(c.found_by) for c in acc.findings}
    assert labels == {"finder": {"model-0"}, "challenger": {"challenger"}}


class _FailingChallenger(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        raise RuntimeError("challenger failed")


def test_challenger_failure_keeps_finder_label_only_and_counts_error():
    acc = run_passes(
        _U,
        _FinderRoleReviewer(),
        challenger=_FailingChallenger(),
        judge=_JudgeRoleReviewer(),
        converge_after=1,
        min_rounds=1,
        max_passes=1,
    )
    (finding,) = acc.findings
    assert finding.title == "finder"
    assert finding.found_by == ("model-0",)
    assert acc.errors == 1


@pytest.mark.parametrize(("stop_on_failure", "rounds"), [(True, 1), (False, 2)])
def test_explicit_failure_policy_controls_repository_rounds(stop_on_failure, rounds):
    acc = run_passes(
        _U,
        _FinderRoleReviewer(),
        challenger=_FailingChallenger(),
        judge=_JudgeRoleReviewer(),
        plan=review_plan(
            "adversarial",
            max_rounds=2,
            converge_after=1,
            stop_on_failure=stop_on_failure,
        ),
    )

    assert len(acc.new_per_pass) == rounds


def test_required_repository_checkpoint_failure_marks_the_run_incomplete():
    reviewer = _StaticReviewer([])

    def fail_checkpoint(_round, _label, _new, _union, _cycle):
        raise OSError("status unavailable")

    acc = run_passes(
        _U,
        reviewer,
        plan=review_plan("adversarial", max_rounds=2, converge_after=1),
        checkpoint_cycle=fail_checkpoint,
    )

    assert reviewer.calls == 1
    assert acc.outcome.complete is False
    assert "round checkpoint failed: OSError: status unavailable" in acc.outcome.failure_reason


class _FailingJudge(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        raise RuntimeError("judge failed")


def test_judge_failure_keeps_finder_and_challenger_candidates():
    acc = run_passes(
        _U,
        _FinderRoleReviewer(),
        challenger=_ChallengerRoleReviewer(),
        judge=_FailingJudge(),
        converge_after=1,
        min_rounds=1,
        max_passes=1,
    )

    assert {finding.title for finding in acc.findings} == {"finder", "challenger"}
    assert acc.errors == 1
    assert acc.unit_failures[0].reason == "RuntimeError: judge failed"


class _PendingJudge(UnitReviewer):
    supports_pending_work = True

    def review(self, unit, *, shared_context=""):
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        return RoleJudgment(findings=[], pending=[{"target": "runtime"}])


def test_pending_judge_work_prevents_repository_convergence():
    acc = run_passes(
        _U,
        _FinderRoleReviewer(),
        challenger=_ChallengerRoleReviewer(),
        judge=_PendingJudge(),
        converge_after=1,
        max_passes=2,
    )

    assert acc.converged is False


class _KnownAwareReviewer(UnitReviewer):
    def __init__(self):
        self.known_titles = []

    def review(self, unit, *, shared_context=""):
        return []

    def find(self, unit, *, shared_context="", known=None):
        self.known_titles.append([c.title for c in known or []])
        return [Candidate(title="A", endpoint="GET /a")]


def test_role_rounds_carry_known_findings_forward():
    reviewer = _KnownAwareReviewer()
    run_passes(_U, reviewer, converge_after=2, min_rounds=2, max_passes=3)
    assert reviewer.known_titles[0] == []
    assert reviewer.known_titles[1] == ["A"]


class _PerUnitReviewer(UnitReviewer):
    """One distinct finding per unit, so merge order is observable."""

    def review(self, unit, *, shared_context=""):
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_concurrency_yields_same_union_as_serial():
    units = [Unit(name=f"u{i}", root=".", files=()) for i in range(6)]
    serial = run_passes(units, _PerUnitReviewer(), concurrency=1, max_passes=3)
    parallel = run_passes(units, _PerUnitReviewer(), concurrency=4, max_passes=3)
    assert {c.key() for c in serial.findings} == {c.key() for c in parallel.findings}
    assert len(parallel.findings) == 6


class _FlakyReviewer(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        if unit.name == "bad":
            raise RuntimeError("rate limited")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_unit_failures_are_counted_not_silent():
    units = [
        Unit(name="ok1", root=".", files=()),
        Unit(name="bad", root=".", files=()),
        Unit(name="ok2", root=".", files=()),
    ]
    acc = run_passes(units, _FlakyReviewer(), concurrency=2, max_passes=2)
    assert acc.errors >= 1
    assert len(acc.unit_failures) == 1
    assert acc.unit_failures[0].paths == ("bad",)
    assert acc.unit_failures[0].reason == "RuntimeError: rate limited"
    assert {c.title for c in acc.findings} == {"ok1", "ok2"}


def test_repository_unit_fails_before_judgment_when_owned_fragments_do_not_fit(tmp_path):
    source = "A" * 120_001 + "B"
    (tmp_path / "large.py").write_text(source, encoding="utf-8")
    unit = Unit(
        name="large",
        root=str(tmp_path),
        files=("large.py",),
        fragments=(("large.py", 0, 120_001), ("large.py", 120_001, 120_002)),
    )

    reviewer = _StaticReviewer([Candidate(title="kept", file="large.py")])
    acc = run_passes(
        [unit],
        reviewer,
        plan=review_plan("standard", max_rounds=1),
    )

    assert reviewer.calls == 0
    assert acc.findings == []
    assert acc.outcome is not None
    assert acc.outcome.complete is False
    assert acc.outcome.errors == 1
    assert acc.outcome.grounding.omitted == ("large.py:120001:120002",)


def test_repository_runner_materializes_prompt_grounding_once(tmp_path, monkeypatch):
    from cyberjury.review.repository import context as context_module

    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    reads = 0
    original = context_module._read_unit_text

    def counted(unit, rel):
        nonlocal reads
        reads += 1
        return original(unit, rel)

    class GatheringReviewer(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            assert "value = 1" in gather(unit)
            return []

    monkeypatch.setattr(context_module, "_read_unit_text", counted)

    run_passes(
        [Unit(name="unit", root=str(tmp_path), files=("unit.py",))],
        GatheringReviewer(),
        plan=review_plan("standard", max_rounds=1),
    )

    assert reads == 1


def test_repository_runner_fails_before_review_when_secondary_source_is_omitted(tmp_path):
    rendered = tuple(f"rendered_{index}.py" for index in range(5))
    for path in rendered:
        (tmp_path / path).write_text("x" * 24_000, encoding="utf-8")
    (tmp_path / "unrendered.py").write_text("value = 1\n", encoding="utf-8")
    observed = []

    class GroundingReviewer(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            observed.append(unit.grounding)
            return []

    acc = run_passes(
        [Unit(name=rendered[0], root=str(tmp_path), files=(*rendered, "unrendered.py"))],
        GroundingReviewer(),
        plan=review_plan("standard", max_rounds=1),
        fact_limitations=(
            FactLimitation(source="unrendered.py", analyzer="python", reason="unparsable", line=1, column=1),
        ),
    )

    assert observed == []
    assert acc.outcome is not None
    assert acc.outcome.complete is False
    assert "omitted required evidence" in acc.outcome.failure_reason


def test_repository_runner_attaches_a_limitation_to_its_rendered_source(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    observed = []

    class GroundingReviewer(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            observed.append(unit.grounding)
            return []

    acc = run_passes(
        [Unit(name="broken.py", root=str(tmp_path), files=("broken.py",))],
        GroundingReviewer(),
        plan=review_plan("standard", max_rounds=1),
        fact_limitations=(
            FactLimitation(source="broken.py", analyzer="python", reason="unparsable", line=1, column=11),
        ),
    )

    assert observed[0].coverage.limitations == ("facts:broken.py:1:11",)
    assert "broken.py at 1:11" in observed[0].text
    assert acc.outcome is not None
    assert acc.outcome.complete is False


def test_repository_runner_attaches_a_limitation_to_a_published_relationship_source(tmp_path):
    app_source = "def route():\n    return load()\n"
    service_source = "def load():\n    return 1\n"
    (tmp_path / "app.py").write_text(app_source, encoding="utf-8")
    (tmp_path / "service.py").write_text(service_source, encoding="utf-8")
    source = DefinitionFragment("app.py", "route", 0, len(app_source))
    target = DefinitionFragment("service.py", "load", 0, len(service_source))
    plan = DefinitionUnitPlan(
        seeds=(source,),
        dependencies=(DefinitionDependency("app.py", target, source, "call"),),
        evidence=(source,),
    )
    observed = []

    class GroundingReviewer(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            observed.append(unit.grounding)
            return []

    acc = run_passes(
        [
            Unit(
                name="route",
                root=str(tmp_path),
                files=("app.py", "service.py"),
                fragments=(("app.py", 0, len(app_source)),),
                fragment_identities=(source.identity,),
                relationships=definition_relationships(plan),
                definition_plan=plan,
            )
        ],
        GroundingReviewer(),
        plan=review_plan("standard", max_rounds=1),
        fact_limitations=(
            FactLimitation(source="service.py", analyzer="python", reason="unparsable", line=1, column=1),
        ),
    )

    assert observed[0].files == ("app.py",)
    assert observed[0].coverage.limitations == ("facts:service.py:1:1",)
    assert any(item.identity == target.identity for item in observed[0].evidence)
    assert acc.outcome is not None
    assert acc.outcome.complete is False


class _RecoveringReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary rate limit")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_recovered_unit_failure_stays_on_the_retry_list():
    acc = run_passes(_U, _RecoveringReviewer(), concurrency=1, max_passes=3)

    assert acc.errors == 1
    assert acc.failed_units == {"u"}
    assert acc.unit_failures[0].reason == "RuntimeError: temporary rate limit"
    assert {c.title for c in acc.findings} == {"u"}


class _FailsLastReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("last attempt failed")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_latest_unit_failure_remains_open_for_resume():
    acc = run_passes(_U, _FailsLastReviewer(), concurrency=1, max_passes=2)

    assert acc.failed_units == {"u"}
    assert acc.unit_failures[0].reason == "RuntimeError: last attempt failed"


def test_failed_unit_identity_does_not_collapse_units_that_share_files(tmp_path):
    class OneFailure(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            if unit.name == "one":
                raise RuntimeError("failed")
            return []

    (tmp_path / "same.py").write_text("value = 1\n")
    units = [
        Unit(name="one", root=str(tmp_path), files=("same.py",)),
        Unit(name="two", root=str(tmp_path), files=("same.py",)),
    ]
    acc = run_passes(
        units,
        OneFailure(),
        plan=review_plan("standard", max_rounds=1),
        concurrency=1,
    )

    assert acc.failed_units == {"one"}


class _OneFindingReviewer(UnitReviewer):
    def __init__(self, title):
        self.title = title
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        return [Candidate(title=self.title, endpoint=f"GET /{self.title}")]


def test_multi_model_fanout_unions_what_each_model_finds():
    a = _OneFindingReviewer("a")
    b = _OneFindingReviewer("b")
    acc = run_passes(_U, [a, b], converge_after=2, max_passes=24)
    assert {c.title for c in acc.findings} == {"a", "b"}
    assert a.calls >= 1
    assert b.calls >= 1


class _FixedReviewer(UnitReviewer):
    def __init__(self, label, cand):
        self._model = label
        self._cand = cand

    @property
    def label(self):
        return self._model

    def review(self, unit, *, shared_context=""):
        return [self._cand]


def test_two_models_finding_the_same_issue_record_consensus():
    shared = Candidate(title="reentry", category="reentrancy", symbol="lend", file="V.sol")
    a = _FixedReviewer("claude", shared)
    b = _FixedReviewer("gpt", shared)
    acc = run_passes(_U, [a, b], converge_after=2, max_passes=24)
    (f,) = acc.findings
    assert set(f.found_by) == {"claude", "gpt"}
