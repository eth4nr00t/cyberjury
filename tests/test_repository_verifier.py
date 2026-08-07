"""The single verification route.

refute candidates, drop only when every independent confirmer upholds the refutation,
never drop a finding on a failed call, decide by majority when multiple votes are cast.
"""

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verifier import (
    ModelRefutationChecker,
    ModelVerifier,
    RefutationChecker,
    Verdict,
    Verifier,
    VerifyError,
    _read_file,
    verify_findings,
)


class StubVerifier(Verifier):
    """Hold the StubVerifier contract."""

    def __init__(self, refute_titles):
        """Store the titles this verifier should refute."""
        self.refute = set(refute_titles)

    def verify(self, candidate, root):
        """Handle verify."""
        bad = candidate.title in self.refute
        return Verdict(real=not bad, reason="controlling fact holds" if bad else "")


class StubChecker(RefutationChecker):
    """Confirms the refutation only for the named titles.

    so a deletion needs this independent second read to agree, mirroring the production
    checker.
    """

    def __init__(self, holds_titles):
        """Store the titles whose refutations should hold."""
        self.h = set(holds_titles)

    def holds(self, candidate, reason, root):
        """Handle holds."""
        return candidate.title in self.h


def _judge(checker):
    """The dedicated confirmer seat, empty label so it always applies, mirroring the CLI."""
    return [("", checker)]


def test_a_refutation_alone_never_drops_a_finding_without_a_confirmer():
    """Refutation alone never drops a finding without a confirmer."""
    cands = [Candidate(title="real1", endpoint="GET /a"), Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "fp"}
    assert not vr.refuted


def test_drops_only_when_an_independent_confirmer_upholds_the_refutation():
    """Drops only when an independent confirmer upholds the refutation."""
    cands = [
        Candidate(title="real1", endpoint="GET /a"),
        Candidate(title="fp", endpoint="GET /b"),
        Candidate(title="real2", endpoint="GET /c"),
    ]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=_judge(StubChecker(["fp"])), concurrency=2)
    assert {c.title for c in vr.confirmed} == {"real1", "real2"}
    assert [c.title for c, _ in vr.refuted] == ["fp"]


def test_a_rejected_refutation_keeps_the_finding():
    """Rejected refutation keeps the finding."""
    cands = [Candidate(title="fp", endpoint="GET /b")]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=_judge(StubChecker([])), concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert not vr.refuted


def test_a_drop_needs_every_applicable_confirmer_to_uphold_the_refutation():
    """Drop needs every applicable confirmer to uphold the refutation."""
    cands = [Candidate(title="fp", endpoint="GET /b")]
    confirmers = [("c1", StubChecker(["fp"])), ("c2", StubChecker([]))]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=confirmers, concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert not vr.refuted


def test_a_confirmer_that_found_the_finding_is_skipped_as_not_independent():
    """Confirmer that found the finding is skipped as not independent."""
    cands = [Candidate(title="fp", endpoint="GET /b", found_by=("c1",))]
    vr = verify_findings(cands, StubVerifier(["fp"]), ".", confirmers=[("c1", StubChecker(["fp"]))], concurrency=1)
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert not vr.refuted
    vr2 = verify_findings(
        cands,
        StubVerifier(["fp"]),
        ".",
        confirmers=[("c1", StubChecker(["fp"])), ("c2", StubChecker(["fp"]))],
        concurrency=1,
    )
    assert [c.title for c, _ in vr2.refuted] == ["fp"]


class FlakyVerifier(Verifier):
    """Hold the FlakyVerifier contract."""

    def verify(self, candidate, root):
        """Handle verify."""
        if candidate.title == "boom":
            raise RuntimeError("rate limited")
        return Verdict(real=False, reason="would refute")


def test_error_keeps_finding_and_is_counted_never_silently_refuted():
    """Error keeps finding and is counted never silently refuted."""
    vr = verify_findings([Candidate(title="boom", endpoint="GET /a")], FlakyVerifier(), ".", votes=1, concurrency=1)
    assert vr.errors >= 1
    assert [c.title for c in vr.confirmed] == ["boom"]
    assert not vr.refuted
    assert [c.title for c in vr.incomplete] == ["boom"]


def test_a_confirmer_error_keeps_the_finding_incomplete_not_frozen():
    """Confirmer error keeps the finding incomplete not frozen."""

    class BoomChecker(StubChecker):
        def holds(self, candidate, reason, root):
            raise RuntimeError("rate limited")

    vr = verify_findings(
        [Candidate(title="fp", endpoint="GET /b")],
        StubVerifier(["fp"]),
        ".",
        confirmers=_judge(BoomChecker([])),
        concurrency=1,
    )
    assert [c.title for c in vr.confirmed] == ["fp"]
    assert [c.title for c in vr.incomplete] == ["fp"]
    assert vr.errors >= 1


class SequenceVerifier(Verifier):
    """Returns real, real, refuted in sequence, so 3 votes are 2-1 in favour of real."""

    def __init__(self):
        """Start at the first vote in the fixed real, real, refuted sequence."""
        self.i = 0

    def verify(self, candidate, root):
        """Handle verify."""
        self.i += 1
        return Verdict(real=(self.i % 3 != 0))


def test_majority_vote_keeps_when_only_a_minority_refutes():
    """Majority vote keeps when only a minority refutes."""
    vr = verify_findings([Candidate(title="x", endpoint="GET /a")], SequenceVerifier(), ".", votes=3, concurrency=1)
    assert [c.title for c in vr.confirmed] == ["x"]


def test_every_vote_refuting_and_an_upholding_confirmer_drops_at_votes_above_one():
    """Every vote refuting and an upholding confirmer drops at votes above one."""
    vr = verify_findings(
        [Candidate(title="fp", endpoint="GET /b")],
        StubVerifier(["fp"]),
        ".",
        votes=3,
        confirmers=_judge(StubChecker(["fp"])),
        concurrency=1,
    )
    assert [c.title for c, _ in vr.refuted] == ["fp"]
    assert not vr.confirmed


class RefuteThenKeepVerifier(Verifier):
    """Refutes the first two votes then keeps on the third, so one keep sits among three votes."""

    def __init__(self):
        """Start at the first vote in the refute, refute, keep sequence."""
        self.i = 0

    def verify(self, candidate, root):
        """Handle verify."""
        self.i += 1
        return Verdict(real=(self.i == 3))


def test_one_keep_vote_saves_the_finding_even_with_an_upholding_confirmer():
    """One keep vote saves the finding even with an upholding confirmer."""
    vr = verify_findings(
        [Candidate(title="x", endpoint="GET /a")],
        RefuteThenKeepVerifier(),
        ".",
        votes=3,
        confirmers=_judge(StubChecker(["x"])),
        concurrency=1,
    )
    assert [c.title for c in vr.confirmed] == ["x"]
    assert not vr.refuted


def _repo(tmp_path, *rels):
    for rel in rels:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("placeholder\n", encoding="utf-8")
    return str(tmp_path)


def test_model_verifier_parses_a_refutation(tmp_path):
    """The model verifier parses a refutation response."""
    prov = MockProvider(default='{"real": false, "reason": "the lock holds on a real RDBMS"}')
    root = _repo(tmp_path, "t.py")
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="race", endpoint="POST /t", file="t.py"), root
    )
    assert verdict.real is False
    assert "lock holds" in verdict.reason
    assert prov.calls[0]["cache"] is True
    cache_prefix = prov.calls[0]["cache_prefix"]
    assert prov.calls[0]["messages"][0].content.startswith(cache_prefix)
    assert "Traps to check against" in cache_prefix
    assert "Proposed finding" not in cache_prefix


def test_model_verifier_keeps_a_refutation_citing_a_same_named_file_in_another_dir(tmp_path):
    """The model verifier keeps a refutation that cites a same named file elsewhere."""
    prov = MockProvider(default='{"real": false, "control_file": "services/config.py"}')
    root = _repo(tmp_path, "models/config.py")
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="x", endpoint="GET /a", file="models/config.py"), root
    )
    assert verdict.real is True


def test_model_verifier_treats_a_bare_filename_control_as_on_file(tmp_path):
    """The model verifier treats a bare filename control as on file."""
    prov = MockProvider(default='{"real": false, "control_file": "config.py"}')
    root = _repo(tmp_path, "models/config.py")
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="x", endpoint="GET /a", file="models/config.py"), root
    )
    assert verdict.real is False


def test_model_verifier_raises_on_unparseable_reply(tmp_path):
    """The model verifier raises on an unparseable reply."""
    prov = MockProvider(default="no json here")
    root = _repo(tmp_path, "t.py")
    with pytest.raises(VerifyError):
        ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x", file="t.py"), root)


def test_verify_findings_keeps_but_flags_an_unparseable_verification(tmp_path):
    """Finding verification keeps and flags an unparseable verification."""
    prov = MockProvider(default="no json here")
    root = _repo(tmp_path, "t.py")
    vr = verify_findings(
        [Candidate(title="x", endpoint="GET /a", file="t.py")], ModelVerifier(provider=prov, model="mock"), root
    )
    assert [c.title for c in vr.confirmed] == ["x"]
    assert [c.title for c in vr.incomplete] == ["x"]
    assert vr.errors == 1


def test_a_refutation_on_a_location_that_does_not_resolve_never_drops_the_finding(tmp_path):
    """Refutation on a location that does not resolve never drops the finding."""
    prov = MockProvider(default='{"real": false, "reason": "no owner check needed"}')
    checker = ModelRefutationChecker(provider=MockProvider(default='{"holds": true}'), model="mock")
    vr = verify_findings(
        [Candidate(title="ghost", endpoint="GET /a", file="gone.py")],
        ModelVerifier(provider=prov, model="mock"),
        _repo(tmp_path, "t.py"),
        confirmers=[("mock", checker)],
    )
    assert [c.title for c in vr.confirmed] == ["ghost"]
    assert not vr.refuted


def test_model_verifier_keeps_a_refutation_that_rests_on_an_unshown_file(tmp_path):
    """The model verifier keeps a refutation that rests on an unshown file."""
    prov = MockProvider(
        default='{"real": false, "reason": "the service checks the owner", '
        '"control_file": "internal/service/answer_service.go"}'
    )
    rel = "internal/repository/activity/answer_repository.go"
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="accept", file=rel), _repo(tmp_path, rel)
    )
    assert verdict.real is True
    assert "answer_service.go" in verdict.reason


def test_model_verifier_refutes_on_a_fact_in_the_shown_file(tmp_path):
    """The model verifier refutes on a fact in the shown file."""
    prov = MockProvider(default='{"real": false, "reason": "owner filter present", "control_file": "models/item.go"}')
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="idor", file="models/item.go"), _repo(tmp_path, "models/item.go")
    )
    assert verdict.real is False


def test_model_checker_confirms_a_holding_refutation(tmp_path):
    """The model checker confirms a refutation that holds."""
    prov = MockProvider(default='{"holds": true, "reason": "the guard dominates the only path"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    root = _repo(tmp_path, "t.py")
    assert checker.holds(Candidate(title="x", file="t.py"), "owner check present", root) is True


def test_model_checker_keeps_the_finding_on_an_unparseable_audit(tmp_path):
    """The model checker keeps the finding on an unparseable audit."""
    prov = MockProvider(default="not json")
    checker = ModelRefutationChecker(provider=prov, model="mock")
    root = _repo(tmp_path, "t.py")
    assert checker.holds(Candidate(title="x", file="t.py"), "some reason", root) is False


def test_model_checker_cannot_confirm_a_refutation_it_could_not_read(tmp_path):
    """The model checker cannot confirm a refutation it could not read."""
    prov = MockProvider(default='{"holds": true, "reason": "the guard dominates"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    assert checker.holds(Candidate(title="x", file="gone.py"), "owner check present", _repo(tmp_path, "t.py")) is False
    assert prov.calls == []


def test_read_file_returns_empty_for_an_out_of_root_path(tmp_path):
    """Reading a file outside the root returns empty text."""
    secret = tmp_path / "secret.py"
    secret.write_text("token = 'sk-live'")
    root = tmp_path / "repository"
    root.mkdir()
    assert _read_file(str(root), "../secret.py") == ""
    assert _read_file(str(root), str(secret)) == ""


def test_verify_findings_reports_progress_per_candidate():
    """Finding verification reports progress per candidate."""
    cands = [Candidate(title=f"c{i}", endpoint="GET /x") for i in range(4)]
    seen = []
    verify_findings(
        cands, StubVerifier([]), ".", concurrency=2, on_verify=lambda done, total, secs: seen.append((done, total))
    )
    assert sorted(seen) == [(1, 4), (2, 4), (3, 4), (4, 4)]
