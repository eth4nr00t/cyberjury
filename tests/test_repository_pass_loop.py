"""The pass loop runs deterministic unit review passes to convergence."""

import pytest

from cyberjury.domains.evm import EVM
from cyberjury.providers.mock import MockProvider
from cyberjury.review.engine import RoleJudgment
from cyberjury.review.repository.context import Unit
from cyberjury.review.repository.reviewer import (
    ModelReviewer,
    RepositoryReviewError,
    UnitChallenge,
    UnitReviewer,
    candidates_from_obj,
)
from cyberjury.review.repository.runner import run_passes
from cyberjury.review.repository.union import Candidate

_U = [Unit(name="u", root=".", files=())]


class StaticReviewer(UnitReviewer):
    """Returns the same candidates each round."""

    def __init__(self, candidates):
        """Store the fixed candidates and count calls."""
        self.candidates = candidates
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        self.calls += 1
        return list(self.candidates)


class NewEachPassReviewer(UnitReviewer):
    """Never converges: every call yields a brand-new finding."""

    def __init__(self):
        """Start the counter that keeps each pass from converging."""
        self.n = 0

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        self.n += 1
        return [Candidate(title=f"f{self.n}", endpoint=f"GET /{self.n}")]


class SecondRoundReviewer(UnitReviewer):
    """Finds the second issue only after another role round."""

    def __init__(self):
        """Start the counter used to observe the round floor."""
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        self.calls += 1
        if self.calls == 1:
            return [Candidate(title="A", endpoint="GET /a")]
        return [Candidate(title="B", endpoint="GET /b")]


def test_role_rounds_union_converges_then_stops_early():
    """Role rounds union findings and stop after convergence."""
    a = Candidate(title="a", endpoint="GET /1")
    reviewer = StaticReviewer([a])
    acc = run_passes(_U, reviewer, converge_after=2, max_passes=24)

    assert {c.title for c in acc.findings} == {"a"}
    assert acc.converged
    assert reviewer.calls == 3
    assert acc.new_per_pass == [1, 0, 0]


def test_runs_to_max_passes_when_never_converges():
    """Runs to max passes when never converges."""
    reviewer = NewEachPassReviewer()
    acc = run_passes(_U, reviewer, converge_after=2, max_passes=5)
    assert not acc.converged
    assert len(acc.new_per_pass) == 5
    assert len(acc.findings) == 5


def test_min_round_floor_keeps_a_run_from_one_shot():
    """The round floor keeps early convergence from ending depth work."""
    reviewer = SecondRoundReviewer()
    acc = run_passes(_U, reviewer, converge_after=2, min_rounds=2, max_passes=24)
    assert {c.title for c in acc.findings} == {"A", "B"}
    assert reviewer.calls >= 2


def test_one_round_floor_can_stop_after_convergence():
    """A one round floor leaves convergence as the stopping rule."""
    reviewer = StaticReviewer([Candidate(title="A", endpoint="GET /a")])
    acc = run_passes(_U, reviewer, converge_after=1, min_rounds=1, max_passes=24)
    assert {c.title for c in acc.findings} == {"A"}
    assert len(acc.new_per_pass) == 2


class FinderRoleReviewer(UnitReviewer):
    """Finder role returns one initial candidate."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return []

    def find(self, unit, *, shared_context="", known=None):
        """Handle finder role."""
        return [Candidate(title="finder", endpoint="GET /finder")]


class ChallengerRoleReviewer(UnitReviewer):
    """Challenger role contributes one missed candidate."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        """Handle challenger role."""
        return UnitChallenge(rebuttals=[], new_findings=[Candidate(title="challenger", endpoint="GET /challenger")])


class JudgeRoleReviewer(UnitReviewer):
    """Judge role keeps finder and challenger candidates."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        """Handle judge role."""
        return finder_findings + new_findings


def test_role_loop_unions_finder_and_challenger_candidates():
    """The repository pass loop uses the finder, challenger, and judge roles."""
    acc = run_passes(
        _U,
        FinderRoleReviewer(),
        challenger=ChallengerRoleReviewer(),
        judge=JudgeRoleReviewer(),
        converge_after=2,
        max_passes=3,
    )
    assert {c.title for c in acc.findings} == {"finder", "challenger"}
    labels = {c.title: set(c.found_by) for c in acc.findings}
    assert labels == {"finder": {"model-0"}, "challenger": {"challenger"}}


class FailingChallenger(UnitReviewer):
    """Challenger failure leaves finder provenance intact."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        """Handle challenger role."""
        raise RuntimeError("challenger failed")


def test_challenger_failure_keeps_finder_label_only_and_counts_error():
    """Challenger failure keeps finder label only and counts error."""
    acc = run_passes(
        _U,
        FinderRoleReviewer(),
        challenger=FailingChallenger(),
        judge=JudgeRoleReviewer(),
        converge_after=1,
        max_passes=1,
    )
    (finding,) = acc.findings
    assert finding.title == "finder"
    assert finding.found_by == ("model-0",)
    assert acc.errors == 1


class FailingJudge(UnitReviewer):
    """Judge failure exercises the shared recall-safe role fallback."""

    def review(self, unit, *, shared_context=""):
        """Leave direct review unused for this role."""
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        """Fail after both independent finding roles have completed."""
        raise RuntimeError("judge failed")


def test_judge_failure_keeps_finder_and_challenger_candidates():
    """Repository Review must use the shared pre-failure candidate preservation rule."""
    acc = run_passes(
        _U,
        FinderRoleReviewer(),
        challenger=ChallengerRoleReviewer(),
        judge=FailingJudge(),
        converge_after=1,
        max_passes=1,
    )

    assert {finding.title for finding in acc.findings} == {"finder", "challenger"}
    assert acc.errors == 1
    assert acc.unit_failures[0].reason == "RuntimeError: judge failed"


class PendingJudge(UnitReviewer):
    """A Judge leaves one item pending for dynamic investigation."""

    def review(self, unit, *, shared_context=""):
        """Leave direct review unused for this role."""
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        """Return no findings while keeping one investigation open."""
        return RoleJudgment(findings=[], pending=[{"target": "runtime"}])


def test_pending_judge_work_prevents_repository_convergence():
    """Repository Review uses the same pending-work convergence rule as Diff Review."""
    acc = run_passes(
        _U,
        FinderRoleReviewer(),
        challenger=ChallengerRoleReviewer(),
        judge=PendingJudge(),
        converge_after=1,
        max_passes=2,
    )

    assert acc.converged is False


class KnownAwareReviewer(UnitReviewer):
    """Records the known findings passed into each round."""

    def __init__(self):
        """Start the known findings record."""
        self.known_titles = []

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return []

    def find(self, unit, *, shared_context="", known=None):
        """Handle finder role."""
        self.known_titles.append([c.title for c in known or []])
        return [Candidate(title="A", endpoint="GET /a")]


def test_role_rounds_carry_known_findings_forward():
    """Known findings feed back into later repository role rounds."""
    reviewer = KnownAwareReviewer()
    run_passes(_U, reviewer, converge_after=2, min_rounds=2, max_passes=3)
    assert reviewer.known_titles[0] == []
    assert reviewer.known_titles[1] == ["A"]


class PerUnitReviewer(UnitReviewer):
    """One distinct finding per unit, so merge order is observable."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_concurrency_yields_same_union_as_serial():
    """Concurrency yields same union as serial."""
    units = [Unit(name=f"u{i}", root=".", files=()) for i in range(6)]
    serial = run_passes(units, PerUnitReviewer(), concurrency=1, max_passes=3)
    parallel = run_passes(units, PerUnitReviewer(), concurrency=4, max_passes=3)
    assert {c.key() for c in serial.findings} == {c.key() for c in parallel.findings}
    assert len(parallel.findings) == 6


class FlakyReviewer(UnitReviewer):
    """Raises on one unit, like a rate-limited call, returns findings on the others."""

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        if unit.name == "bad":
            raise RuntimeError("rate limited")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_unit_failures_are_counted_not_silent():
    """Failed units remain visible while sibling unit findings survive."""
    units = [
        Unit(name="ok1", root=".", files=()),
        Unit(name="bad", root=".", files=()),
        Unit(name="ok2", root=".", files=()),
    ]
    acc = run_passes(units, FlakyReviewer(), concurrency=2, max_passes=2)
    assert acc.errors >= 1
    assert len(acc.unit_failures) == 1
    assert acc.unit_failures[0].paths == ("bad",)
    assert acc.unit_failures[0].reason == "RuntimeError: rate limited"
    assert {c.title for c in acc.findings} == {"ok1", "ok2"}


class RecoveringReviewer(UnitReviewer):
    """Fails once, then completes the unit on a later pass."""

    def __init__(self):
        """Start the failure counter."""
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("temporary rate limit")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_recovered_unit_failure_is_not_final_failure():
    """A later clean unit pass clears the final failure snapshot."""
    acc = run_passes(_U, RecoveringReviewer(), concurrency=1, max_passes=3)

    assert acc.errors == 1
    assert acc.failed_units == set()
    assert acc.unit_failures == []
    assert {c.title for c in acc.findings} == {"u"}


class FailsLastReviewer(UnitReviewer):
    """Succeeds before failing the final unit attempt."""

    def __init__(self):
        """Track which attempt must fail."""
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        """Fail the second and final attempt."""
        self.calls += 1
        if self.calls == 2:
            raise RuntimeError("last attempt failed")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_latest_unit_failure_remains_open_for_resume():
    """An earlier success cannot hide a failure from the final unit attempt."""
    acc = run_passes(_U, FailsLastReviewer(), concurrency=1, max_passes=2)

    assert acc.failed_units == {"u"}
    assert acc.unit_failures[0].reason == "RuntimeError: last attempt failed"


def test_candidates_from_obj_is_tolerant():
    """Candidates from obj is tolerant."""
    obj = {
        "findings": [
            {"title": "real", "severity": "CRITICAL", "endpoint": "POST /t", "category": "idor"},
            {"no_title": 1},
            "junk",
        ]
    }
    cands = candidates_from_obj(obj)
    assert len(cands) == 1
    assert cands[0].severity == "CRITICAL"
    assert cands[0].endpoint == "POST /t"


def test_candidates_default_severity_is_medium_not_dropped():
    """Candidates default severity is medium not dropped."""
    cands = candidates_from_obj({"findings": [{"title": "x", "severity": "spicy"}]})
    assert len(cands) == 1
    assert cands[0].severity == "MEDIUM"


def test_model_reviewer_builds_prompt_and_parses(tmp_path):
    """Model reviewer builds prompt and parses."""
    (tmp_path / "app.py").write_text("def handler():\n    return 'ok'\n")
    reply = (
        '{"findings": [{"title": "idor", "category": "idor", '
        '"endpoint": "GET /x/<id>", "file": "app.py", "line": 2, '
        '"severity": "high", "status": "confirmed"}]}'
    )
    prov = MockProvider(default=reply)
    reviewer = ModelReviewer(provider=prov, model="mock")
    unit = Unit(name="wallets", root=str(tmp_path), files=("app.py",))

    cands = reviewer.review(unit, shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"

    sent = prov.calls[0]["messages"][0].content
    assert "Review every high-impact class" in sent
    assert "LENS" not in sent
    assert "Severity rubric" in sent
    assert "def handler" in sent

    cache_prefix = prov.calls[0]["cache_prefix"]
    assert sent.startswith(cache_prefix)
    assert "Severity rubric" in cache_prefix
    assert "stack: flask" in cache_prefix
    assert "def handler" in cache_prefix
    assert "Review every high-impact class" not in cache_prefix

    reviewer.review(unit, shared_context="stack: flask")
    assert prov.calls[1]["cache_prefix"] == cache_prefix


def test_model_reviewer_uses_the_same_unit_knowledge_for_every_role(tmp_path):
    """Role rounds must not reason from different vulnerability class definitions."""
    (tmp_path / "tokens.py").write_text("def issue_token():\n    return make_token()\n")
    provider = MockProvider(
        responses=[
            '{"findings": []}',
            '{"findings": []}',
            '{"rebuttals": [], "new_findings": []}',
            '{"findings": []}',
        ]
    )
    reviewer = ModelReviewer(
        provider=provider,
        model="mock",
        facts_by_file={"tokens.py": "Definition make_token\n  return uuid.uuid1().hex"},
    )
    unit = Unit(name="tokens", root=str(tmp_path), files=("tokens.py",))

    reviewer.review(unit)
    reviewer.find(unit)
    challenge = reviewer.challenge(unit, [])
    reviewer.judge(unit, [], challenge.rebuttals, challenge.new_findings)

    prefixes = [call["cache_prefix"] for call in provider.calls]
    assert all(prefix == prefixes[0] for prefix in prefixes)
    assert "UUIDv1 is not a secret generator" in prefixes[0]
    assert "SQL Injection" not in prefixes[0]


def test_model_reviewer_loads_knowledge_from_the_selected_domain(tmp_path):
    """Repository units must not fall back to web knowledge for another domain."""
    (tmp_path / "Proxy.sol").write_text(
        "contract Proxy { function run(address target) external { target.delegatecall(msg.data); } }\n"
    )
    provider = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=provider, model="mock", content=EVM.paths)

    reviewer.review(Unit(name="proxy", root=str(tmp_path), files=("Proxy.sol",)))

    prefix = provider.calls[0]["cache_prefix"]
    assert "Proxy, Delegatecall, and Initializer Flaws" in prefix
    assert "SQL Injection" not in prefix


def test_model_reviewer_raises_on_unparseable_reply():
    """Model reviewer raises on unparseable reply."""
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = ModelReviewer(provider=prov, model="mock")
    with pytest.raises(RepositoryReviewError, match="failed review"):
        reviewer.review(Unit(name="u", root=".", files=()))


def test_model_reviewer_empty_findings_is_not_an_error():
    """Model reviewer empty findings is not an error."""
    prov = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=prov, model="mock")
    assert reviewer.review(Unit(name="u", root=".", files=())) == []


def test_run_passes_counts_an_unparseable_reply_as_an_error():
    """Run passes counts an unparseable reply as an error."""
    prov = MockProvider(default="sorry, no JSON here")
    acc = run_passes(_U, ModelReviewer(provider=prov, model="mock"), max_passes=2)
    assert acc.errors >= 1
    assert acc.findings == []


class OneFindingReviewer(UnitReviewer):
    """A reviewer returns only its own single issue."""

    def __init__(self, title):
        """Store one title and count review calls."""
        self.title = title
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        self.calls += 1
        return [Candidate(title=self.title, endpoint=f"GET /{self.title}")]


def test_multi_model_fanout_unions_what_each_model_finds():
    """Multi model fanout unions what each model finds."""
    a = OneFindingReviewer("a")
    b = OneFindingReviewer("b")
    acc = run_passes(_U, [a, b], converge_after=2, max_passes=24)
    assert {c.title for c in acc.findings} == {"a", "b"}
    assert a.calls >= 1
    assert b.calls >= 1


class FixedReviewer(UnitReviewer):
    """A model that always returns the one finding it is given, labelled by its model name."""

    def __init__(self, label, cand):
        """Store the label and candidate this reviewer always returns."""
        self._model = label
        self._cand = cand

    @property
    def label(self):
        """Handle label."""
        return self._model

    def review(self, unit, *, shared_context=""):
        """Handle review."""
        return [self._cand]


def test_two_models_finding_the_same_issue_record_consensus():
    """Two models finding the same issue record consensus."""
    shared = Candidate(title="reentry", category="reentrancy", symbol="lend", file="V.sol")
    a = FixedReviewer("claude", shared)
    b = FixedReviewer("gpt", shared)
    acc = run_passes(_U, [a, b], converge_after=2, max_passes=24)
    (f,) = acc.findings
    assert set(f.found_by) == {"claude", "gpt"}
