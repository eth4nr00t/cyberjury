"""The pass-loop orchestration and the per-unit reviewer.

The pass-loop is the deterministic core: it runs the whole worklist every pass, cycles
lenses, unions, and stops on convergence. Tested with a mock reviewer so the
orchestration is verified without a model. The default ModelReviewer's parsing is tested
with a mock provider.
"""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.pass_loop import run_passes
from cyberjury.review.repository.reviewer import ModelReviewer, RepositoryReviewError, UnitReviewer, candidates_from_obj
from cyberjury.review.repository.shapes import Unit
from cyberjury.review.repository.union import Candidate

_U = [Unit(name="u", root=".", files=())]


class LensReviewer(UnitReviewer):
    """Returns a fixed candidate set per lens, so the union is what the lenses cover."""

    def __init__(self, by_lens):
        """Store findings by lens and record the lenses requested."""
        self.by_lens = by_lens
        self.lenses_seen = []

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        self.lenses_seen.append(lens)
        return list(self.by_lens.get(lens, []))


class NewEachPassReviewer(UnitReviewer):
    """Never converges: every call yields a brand-new finding."""

    def __init__(self):
        """Start the counter that keeps each pass from converging."""
        self.n = 0

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        self.n += 1
        return [Candidate(title=f"f{self.n}", endpoint=f"GET /{self.n}")]


class SecondShotReviewer(UnitReviewer):
    """The easy lens finds its issue at once, the hard lens generates only on its second firing.

    the way a hard class is a coin flip the first shot misses and the second catches. Used
    to prove the coverage gate holds the run open for that second shot.
    """

    def __init__(self):
        """Start the hard lens counter used to converge on the second shot."""
        self.hard_shots = 0
        self.lenses_seen = []

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        self.lenses_seen.append(lens)
        if lens == "easy":
            return [Candidate(title="A", endpoint="GET /a")]
        if lens == "hard":
            self.hard_shots += 1
            if self.hard_shots >= 2:
                return [Candidate(title="B", endpoint="GET /b")]
        return []


def test_lenses_cycle_and_union_converges_then_stops_early():
    """Lenses cycle and union converges then stops early."""
    a = Candidate(title="a", endpoint="GET /1")
    b = Candidate(title="b", endpoint="GET /2")
    reviewer = LensReviewer({"x": [a], "y": [b]})
    acc = run_passes(_U, reviewer, lenses=("x", "y"), converge_after=2, max_passes=24)

    assert {c.title for c in acc.findings} == {"a", "b"}
    assert acc.converged
    assert reviewer.lenses_seen == ["x", "y", "x", "y"]
    assert acc.new_per_pass == [1, 1, 0, 0]


def test_runs_to_max_passes_when_never_converges():
    """Runs to max passes when never converges."""
    reviewer = NewEachPassReviewer()
    acc = run_passes(_U, reviewer, lenses=("",), converge_after=2, max_passes=5)
    assert not acc.converged
    assert len(acc.new_per_pass) == 5
    assert len(acc.findings) == 5


def test_coverage_gate_keeps_a_hard_lens_from_one_shot():
    """Coverage gate keeps a hard lens from one shot."""
    reviewer = SecondShotReviewer()
    acc = run_passes(_U, reviewer, lenses=("easy", "hard", ""), converge_after=2, min_lens_shots=2, max_passes=24)
    assert {c.title for c in acc.findings} == {"A", "B"}
    assert reviewer.lenses_seen.count("hard") >= 2


def test_one_shot_floor_stops_before_a_hard_lens_second_shot():
    """One shot floor stops before a hard lens second shot."""
    reviewer = SecondShotReviewer()
    acc = run_passes(_U, reviewer, lenses=("easy", "hard", ""), converge_after=2, min_lens_shots=1, max_passes=24)
    assert {c.title for c in acc.findings} == {"A"}


class PerUnitReviewer(UnitReviewer):
    """One distinct finding per unit, so merge order is observable."""

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_concurrency_yields_same_union_as_serial():
    """Concurrency yields same union as serial."""
    units = [Unit(name=f"u{i}", root=".", files=()) for i in range(6)]
    serial = run_passes(units, PerUnitReviewer(), lenses=("",), concurrency=1, max_passes=3)
    parallel = run_passes(units, PerUnitReviewer(), lenses=("",), concurrency=4, max_passes=3)
    assert {c.key() for c in serial.findings} == {c.key() for c in parallel.findings}
    assert len(parallel.findings) == 6


class FlakyReviewer(UnitReviewer):
    """Raises on one unit, like a rate-limited call, returns findings on the others."""

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        if unit.name == "bad":
            raise RuntimeError("rate limited")
        return [Candidate(title=unit.name, endpoint=f"GET /{unit.name}")]


def test_unit_failures_are_counted_not_silent():
    """Unit failures are counted not silent."""
    units = [
        Unit(name="ok1", root=".", files=()),
        Unit(name="bad", root=".", files=()),
        Unit(name="ok2", root=".", files=()),
    ]
    acc = run_passes(units, FlakyReviewer(), lenses=("",), concurrency=2, max_passes=2)
    assert acc.errors >= 1
    assert {c.title for c in acc.findings} == {"ok1", "ok2"}


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

    cands = reviewer.review(unit, "authorization", shared_context="stack: flask")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"

    sent = prov.calls[0]["messages"][0].content
    assert "AUTHORIZATION LENS" in sent
    assert "Severity rubric" in sent
    assert "def handler" in sent

    cache_prefix = prov.calls[0]["cache_prefix"]
    assert sent.startswith(cache_prefix)
    assert "Severity rubric" in cache_prefix
    assert "stack: flask" in cache_prefix
    assert "def handler" in cache_prefix
    assert "AUTHORIZATION LENS" not in cache_prefix
    assert sent[len(cache_prefix) :].startswith("This pass LEADS WITH THE AUTHORIZATION LENS")

    reviewer.review(unit, "injection", shared_context="stack: flask")
    assert prov.calls[1]["cache_prefix"] == cache_prefix


def test_model_reviewer_raises_on_unparseable_reply():
    """Model reviewer raises on unparseable reply."""
    prov = MockProvider(default="sorry, no JSON here")
    reviewer = ModelReviewer(provider=prov, model="mock")
    with pytest.raises(RepositoryReviewError):
        reviewer.review(Unit(name="u", root=".", files=()), "")


def test_model_reviewer_empty_findings_is_not_an_error():
    """Model reviewer empty findings is not an error."""
    prov = MockProvider(default='{"findings": []}')
    reviewer = ModelReviewer(provider=prov, model="mock")
    assert reviewer.review(Unit(name="u", root=".", files=()), "") == []


def test_run_passes_counts_an_unparseable_reply_as_an_error():
    """Run passes counts an unparseable reply as an error."""
    prov = MockProvider(default="sorry, no JSON here")
    acc = run_passes(_U, ModelReviewer(provider=prov, model="mock"), lenses=("",), max_passes=2)
    assert acc.errors >= 1
    assert acc.findings == []


class OneFindingReviewer(UnitReviewer):
    """A model that only ever finds its own single issue.

    so two such models cover different issues and the union needs both, the recall ceiling a
    single model cannot reach alone.
    """

    def __init__(self, title):
        """Store one title and count review calls."""
        self.title = title
        self.calls = 0

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        self.calls += 1
        return [Candidate(title=self.title, endpoint=f"GET /{self.title}")]


def test_multi_model_fanout_unions_what_each_model_finds():
    """Multi model fanout unions what each model finds."""
    a = OneFindingReviewer("a")
    b = OneFindingReviewer("b")
    acc = run_passes(_U, [a, b], lenses=("x",), converge_after=2, max_passes=24)
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

    def review(self, unit, lens, *, shared_context=""):
        """Handle review."""
        return [self._cand]


def test_two_models_finding_the_same_issue_record_consensus():
    """Two models finding the same issue record consensus."""
    shared = Candidate(title="reentry", category="reentrancy", symbol="lend", file="V.sol")
    a = FixedReviewer("claude", shared)
    b = FixedReviewer("gpt", shared)
    acc = run_passes(_U, [a, b], lenses=("x",), converge_after=2, max_passes=24)
    (f,) = acc.findings
    assert set(f.found_by) == {"claude", "gpt"}
