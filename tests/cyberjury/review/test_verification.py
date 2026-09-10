"""The verification route preserves candidates unless refutations are confirmed."""

import json

import pytest

from cyberjury.profiles.registry import get_profile
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.union import Candidate
from cyberjury.review.verification import (
    ModelRefutationChecker,
    ModelVerifier,
    RefutationCheck,
    RefutationChecker,
    Verdict,
    VerificationActorFingerprint,
    VerificationReceipt,
    Verifier,
    VerifyError,
    _read_file,
    verify_findings,
)
from cyberjury.sources.snapshot import SourceSnapshot

_CANDIDATE_FILE = "cyberjury/review/verification.py"


class _StubVerifier(Verifier):
    def __init__(self, refute_titles):
        self.refute = set(refute_titles)
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        bad = candidate.title in self.refute
        return Verdict(
            real=not bad,
            reason="controlling fact holds" if bad else "candidate remains exploitable",
            control_file=candidate.file if bad else "",
            control_line=(candidate.line or 1) if bad else None,
        )


class _StubChecker(RefutationChecker):
    """Confirms refutations only for named titles."""

    def __init__(self, holds_titles, *, seat="checker"):
        self.h = set(holds_titles)
        self.seat = seat

    def checkpoint_fingerprint(self):
        return VerificationActorFingerprint(actor="test checker", settings=(("model", self.seat),))

    def holds(self, candidate, reason, root):
        holds = candidate.title in self.h
        return RefutationCheck(holds=holds, reason="control covers path" if holds else "control misses path")


def _judge(checker):
    """The dedicated confirmer seat with explicit provenance."""
    return [("confirmer", checker)]


def test_model_verification_wrappers_close_their_bound_provider():

    class ProviderWithClose(MockProvider):
        def __init__(self):
            super().__init__(default='{"real": true, "reason": ""}')
            self.closed = 0

        def close(self):
            self.closed += 1

    verifier_provider = ProviderWithClose()
    checker_provider = ProviderWithClose()
    ModelVerifier(provider=verifier_provider, model="m").close()
    ModelRefutationChecker(provider=checker_provider, model="m").close()
    assert verifier_provider.closed == 1
    assert checker_provider.closed == 1


def test_a_refutation_alone_never_drops_a_finding_without_a_confirmer():
    cands = [Candidate(title="real1", endpoint="GET /a"), Candidate(title="fp", endpoint="GET /b")]
    verifier = _StubVerifier(["fp"])
    vr = verify_findings(cands, verifier, ".", concurrency=2)
    assert {c.title for c in vr.retained} == {"real1", "fp"}
    assert not vr.refuted
    assert verifier.calls == 0
    assert {record.reason for record in vr.records} == {"no independent confirmer can authorize deletion"}


@pytest.mark.parametrize(
    ("field", "value"),
    [("votes", 0), ("votes", -1), ("votes", True), ("concurrency", 0), ("concurrency", -1), ("concurrency", True)],
)
def test_verification_rejects_nonpositive_policy(field, value):
    options = {"votes": 1, "concurrency": 1, field: value}

    with pytest.raises(ValueError, match="must be positive"):
        verify_findings([Candidate(title="x", endpoint="GET /x")], _StubVerifier([]), ".", **options)


def test_drops_only_when_an_independent_confirmer_upholds_the_refutation():
    cands = [
        Candidate(title="real1", endpoint="GET /a", file=_CANDIDATE_FILE, line=1),
        Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1),
        Candidate(title="real2", endpoint="GET /c", file=_CANDIDATE_FILE, line=1),
    ]
    vr = verify_findings(cands, _StubVerifier(["fp"]), ".", confirmers=_judge(_StubChecker(["fp"])), concurrency=2)
    assert {c.title for c in vr.retained} == {"real1", "real2"}
    assert [c.title for c, _ in vr.refuted] == ["fp"]
    record = next(record for record in vr.records if record.candidate.title == "fp")
    assert record.outcome == "refuted"
    assert [vote.role for vote in record.votes] == ["skeptic", "confirmer"]
    assert [vote.verdict for vote in record.votes] == ["refuted", "upheld"]
    assert all(vote.actor_id and vote.seat_id and vote.reason for vote in record.votes)


def test_a_rejected_refutation_keeps_the_finding():
    cands = [Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1)]
    vr = verify_findings(cands, _StubVerifier(["fp"]), ".", confirmers=_judge(_StubChecker([])), concurrency=1)
    assert [c.title for c in vr.retained] == ["fp"]
    assert not vr.refuted


def test_a_drop_needs_every_applicable_confirmer_to_uphold_the_refutation():
    cands = [Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1)]
    confirmers = [("c1", _StubChecker(["fp"], seat="c1")), ("c2", _StubChecker([], seat="c2"))]
    vr = verify_findings(cands, _StubVerifier(["fp"]), ".", confirmers=confirmers, concurrency=1)
    assert [c.title for c in vr.retained] == ["fp"]
    assert not vr.refuted


def test_verification_rejects_duplicate_confirmer_seats_before_work():
    with pytest.raises(ValueError, match="distinct model seats"):
        verify_findings(
            [Candidate(title="fp", endpoint="GET /b")],
            _StubVerifier(["fp"]),
            ".",
            confirmers=[("c1", _StubChecker(["fp"])), ("c2", _StubChecker(["fp"]))],
            concurrency=1,
        )


def test_a_confirmer_that_found_the_finding_is_skipped_as_not_independent():
    cands = [Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1, found_by=("c1",))]
    vr = verify_findings(cands, _StubVerifier(["fp"]), ".", confirmers=[("c1", _StubChecker(["fp"]))], concurrency=1)
    assert [c.title for c in vr.retained] == ["fp"]
    assert not vr.refuted
    vr2 = verify_findings(
        cands,
        _StubVerifier(["fp"]),
        ".",
        confirmers=[
            ("c1", _StubChecker(["fp"], seat="c1")),
            ("c2", _StubChecker(["fp"], seat="c2")),
        ],
        concurrency=1,
    )
    assert [c.title for c, _ in vr2.refuted] == ["fp"]


class _FlakyVerifier(Verifier):
    def verify(self, candidate, root):
        if candidate.title == "boom":
            raise RuntimeError("rate limited")
        return Verdict(real=False, reason="would refute", control_file=candidate.file or "source.py", control_line=1)


def test_error_keeps_finding_and_is_counted_never_silently_refuted():
    vr = verify_findings(
        [Candidate(title="boom", endpoint="GET /a", file=_CANDIDATE_FILE, line=1)],
        _FlakyVerifier(),
        ".",
        votes=1,
        confirmers=_judge(_StubChecker([])),
        concurrency=1,
    )
    assert vr.errors >= 1
    assert [c.title for c in vr.retained] == ["boom"]
    assert vr.verified == []
    assert not vr.refuted
    assert [c.title for c in vr.incomplete] == ["boom"]
    assert vr.error_details == ["RuntimeError: rate limited"]


def test_source_mutation_during_verification_keeps_the_candidate_incomplete(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("before\n", encoding="utf-8")
    snapshot = SourceSnapshot.capture(tmp_path, ("app.py",))
    candidate = Candidate(
        title="candidate",
        category="missing-authorization",
        file="app.py",
        line=1,
        attack_path="request reaches an unguarded operation",
    )

    class MutatingVerifier(Verifier):
        def verify(self, candidate, root):
            source.write_text("after\n", encoding="utf-8")
            return Verdict(real=False, reason="safe", control_file="app.py", control_line=1)

    result = verify_findings(
        [candidate],
        MutatingVerifier(),
        str(tmp_path),
        votes=1,
        confirmers=_judge(_StubChecker([])),
        concurrency=1,
        source_snapshot=snapshot,
    )

    assert result.retained == [candidate]
    assert result.incomplete == [candidate]
    assert result.refuted == []
    assert "source changed after the reviewed evidence revision" in result.error_details[0]


def test_one_failed_vote_keeps_a_finding_incomplete_even_when_later_votes_refute():
    class FailedThenRefuted(Verifier):
        def __init__(self):
            self.calls = 0

        def verify(self, candidate, root):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("rate limited")
            return Verdict(
                real=False, reason="claimed control", control_file=candidate.file or "source.py", control_line=1
            )

    candidate = Candidate(title="real", endpoint="GET /a", file=_CANDIDATE_FILE, line=1)
    vr = verify_findings(
        [candidate],
        FailedThenRefuted(),
        ".",
        votes=3,
        confirmers=_judge(_StubChecker(["real"])),
        concurrency=1,
    )

    assert vr.retained == [candidate]
    assert vr.verified == []
    assert vr.incomplete == [candidate]
    assert not vr.refuted
    assert vr.errors == 1


def test_a_confirmer_error_keeps_the_finding_incomplete_not_frozen():

    class BoomChecker(_StubChecker):
        def holds(self, candidate, reason, root):
            raise RuntimeError("rate limited")

    vr = verify_findings(
        [Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1)],
        _StubVerifier(["fp"]),
        ".",
        confirmers=_judge(BoomChecker([])),
        concurrency=1,
    )
    assert [c.title for c in vr.retained] == ["fp"]
    assert [c.title for c in vr.incomplete] == ["fp"]
    assert vr.errors == 1
    assert vr.error_details == ["RuntimeError: rate limited"]


class _SequenceVerifier(Verifier):
    """Returns real, real, refuted in sequence, so 3 votes are 2-1 in favour of real."""

    def __init__(self):
        self.i = 0

    def verify(self, candidate, root):
        self.i += 1
        if self.i % 3 != 0:
            return Verdict(real=True, reason="candidate remains exploitable")
        return Verdict(
            real=False,
            reason="control applies",
            control_file=candidate.file,
            control_line=candidate.line,
        )


def test_one_real_vote_keeps_without_spending_remaining_attempts():
    verifier = _SequenceVerifier()
    vr = verify_findings(
        [Candidate(title="x", endpoint="GET /a", file=_CANDIDATE_FILE, line=1)],
        verifier,
        ".",
        votes=3,
        confirmers=_judge(_StubChecker(["x"])),
        concurrency=1,
    )
    assert [c.title for c in vr.retained] == ["x"]
    assert verifier.i == 1


def test_every_vote_refuting_and_an_upholding_confirmer_drops_at_votes_above_one():
    vr = verify_findings(
        [Candidate(title="fp", endpoint="GET /b", file=_CANDIDATE_FILE, line=1)],
        _StubVerifier(["fp"]),
        ".",
        votes=3,
        confirmers=_judge(_StubChecker(["fp"])),
        concurrency=1,
    )
    assert [c.title for c, _ in vr.refuted] == ["fp"]
    assert not vr.retained


class _RefuteThenKeepVerifier(Verifier):
    """Refutes the first two votes then keeps on the third, so one keep sits among three votes."""

    def __init__(self):
        self.i = 0

    def verify(self, candidate, root):
        self.i += 1
        if self.i == 3:
            return Verdict(real=True, reason="candidate remains exploitable")
        return Verdict(
            real=False,
            reason="control applies",
            control_file=candidate.file,
            control_line=candidate.line,
        )


def test_one_keep_vote_saves_the_finding_even_with_an_upholding_confirmer():
    vr = verify_findings(
        [Candidate(title="x", endpoint="GET /a", file=_CANDIDATE_FILE, line=1)],
        _RefuteThenKeepVerifier(),
        ".",
        votes=3,
        confirmers=_judge(_StubChecker(["x"])),
        concurrency=1,
    )
    assert [c.title for c in vr.retained] == ["x"]
    assert not vr.refuted


def _repo(tmp_path, *rels):
    for rel in rels:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("placeholder\n", encoding="utf-8")
    return str(tmp_path)


def test_model_verifier_parses_a_refutation(tmp_path):
    prov = MockProvider(
        default=(
            '{"real": false, "reason": "the lock holds on a real RDBMS", "control_file": "t.py", "control_line": 1}'
        )
    )
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


def test_model_verifier_receives_the_candidates_exact_decision_rule(tmp_path):
    meter = UsageMeter()
    inner = MockProvider(
        default='{"real": true, "reason": "the authorization path is exposed", "control_file": "", "control_line": 0}'
    )
    provider = MeteringProvider(
        inner,
        meter,
    )
    root = _repo(tmp_path, "t.py")

    ModelVerifier(provider=provider, model="mock").verify(
        Candidate(
            title="missing authority",
            category="missing-authorization",
            decision_rule_id="missing-authorization-action",
            file="t.py",
        ),
        root,
    )

    prompt = inner.calls[0]["messages"][0].content
    assert "## missing-authorization-action" in prompt
    assert "Required evidence:" in prompt
    assert "Refuting evidence:" in prompt
    assert "Report boundary:" in prompt
    call = meter.call_snapshot()[0]
    assert call["decision_rule_ids"] == ["missing-authorization-action"]
    assert len(call["review_brief_sha256"]) == 64
    assert call["candidate_id"].startswith("candidate-")
    assert call["unit_id"] == ""


def test_model_verifier_rejects_an_invalid_decision_rule_binding(tmp_path):
    root = _repo(tmp_path, "t.py")

    with pytest.raises(VerifyError, match="belongs to"):
        ModelVerifier(provider=MockProvider(default='{"real": true}'), model="mock").verify(
            Candidate(
                title="wrong rule",
                category="sql-injection",
                decision_rule_id="missing-authorization-action",
                file="t.py",
            ),
            root,
        )


def test_model_verifier_resolves_a_bare_path_with_the_selected_profile(tmp_path):
    source = tmp_path / "src" / "Foo.sol"
    source.parent.mkdir()
    source.write_text("contract Foo { uint256 selected; }\n")
    vendored = tmp_path / "lib" / "Foo.sol"
    vendored.parent.mkdir()
    vendored.write_text("contract Foo { uint256 vendored; }\n")
    provider = MockProvider(
        default='{"real": true, "reason": "candidate remains", "control_file": "", "control_line": 0}'
    )

    ModelVerifier(provider=provider, model="mock", content=get_profile("evm").paths).verify(
        Candidate(title="x", file="Foo.sol"),
        str(tmp_path),
    )

    prompt = provider.calls[0]["messages"][0].content
    assert "uint256 selected" in prompt
    assert "uint256 vendored" not in prompt


def test_model_verifier_rejects_a_refutation_citing_an_unshown_file(tmp_path):
    prov = MockProvider(
        default=(
            '{"real": false, "reason": "the other file owns the control", '
            '"control_file": "services/config.py", "control_line": 1}'
        )
    )
    root = _repo(tmp_path, "models/config.py")
    with pytest.raises(VerifyError, match="outside the shown candidate file"):
        ModelVerifier(provider=prov, model="mock").verify(
            Candidate(title="x", endpoint="GET /a", file="models/config.py"), root
        )


def test_model_verifier_treats_a_bare_filename_control_as_on_file(tmp_path):
    prov = MockProvider(
        default=(
            '{"real": false, "reason": "the shown file owns the control", '
            '"control_file": "config.py", "control_line": 1}'
        )
    )
    root = _repo(tmp_path, "models/config.py")
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="x", endpoint="GET /a", file="models/config.py"), root
    )
    assert verdict.real is False


def test_model_verifier_raises_on_unparseable_reply(tmp_path):
    prov = MockProvider(default="no json here")
    root = _repo(tmp_path, "t.py")
    with pytest.raises(VerifyError, match="unparseable verification reply"):
        ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x", file="t.py"), root)


def test_model_verifier_rejects_a_non_boolean_real_field(tmp_path):
    prov = MockProvider(default='{"real": "false", "reason": "invalid", "control_file": "", "control_line": 0}')
    root = _repo(tmp_path, "t.py")
    with pytest.raises(VerifyError, match=r"\$response.real must be boolean"):
        ModelVerifier(provider=prov, model="mock").verify(Candidate(title="x", file="t.py"), root)


def test_model_verifier_rejects_unknown_response_fields(tmp_path):
    provider = MockProvider(
        default=('{"real": true, "reason": "candidate remains", "control_file": "", "control_line": 0, "extra": true}')
    )
    root = _repo(tmp_path, "t.py")

    with pytest.raises(VerifyError, match="unknown fields: extra"):
        ModelVerifier(provider=provider, model="mock").verify(Candidate(title="x", file="t.py"), root)


def test_model_verifier_records_semantic_response_failure(tmp_path):
    meter = UsageMeter()
    provider = MeteringProvider(
        MockProvider(default='{"real": true, "reason": "", "control_file": "", "control_line": 0}'),
        meter,
    )
    root = _repo(tmp_path, "t.py")

    with pytest.raises(VerifyError, match="nonempty reason"):
        ModelVerifier(provider=provider, model="mock").verify(Candidate(title="x", file="t.py"), root)

    call = meter.call_snapshot()[0]
    assert call["status"] == "failed"
    assert call["failure_reason"] == "verification reply requires a nonempty reason"


def test_verify_findings_keeps_but_flags_an_unparseable_verification(tmp_path):
    prov = MockProvider(default="no json here")
    root = _repo(tmp_path, "t.py")
    vr = verify_findings(
        [Candidate(title="x", endpoint="GET /a", file="t.py")],
        ModelVerifier(provider=prov, model="mock"),
        root,
        confirmers=_judge(_StubChecker([])),
    )
    assert [c.title for c in vr.retained] == ["x"]
    assert [c.title for c in vr.incomplete] == ["x"]
    assert vr.errors == 1


def test_a_refutation_on_a_location_that_does_not_resolve_never_drops_the_finding(tmp_path):
    prov = MockProvider(default='{"real": false, "reason": "no owner check needed"}')
    checker = ModelRefutationChecker(
        provider=MockProvider(default='{"holds": true, "reason": "control covers path"}'),
        model="mock-confirmer",
    )
    vr = verify_findings(
        [Candidate(title="ghost", endpoint="GET /a", file="gone.py")],
        ModelVerifier(provider=prov, model="mock-skeptic"),
        _repo(tmp_path, "t.py"),
        confirmers=[("mock", checker)],
    )
    assert [c.title for c in vr.retained] == ["ghost"]
    assert not vr.refuted


def test_model_verifier_rejects_a_refutation_that_rests_on_an_unshown_file(tmp_path):
    prov = MockProvider(
        default='{"real": false, "reason": "the service checks the owner", '
        '"control_file": "internal/service/answer_service.go", "control_line": 1}'
    )
    rel = "internal/repository/activity/answer_repository.go"
    root = _repo(tmp_path, rel, "internal/service/answer_service.go")
    with pytest.raises(VerifyError, match="outside the shown candidate file"):
        ModelVerifier(provider=prov, model="mock").verify(Candidate(title="accept", file=rel), root)


def test_model_verifier_refutes_on_a_fact_in_the_shown_file(tmp_path):
    prov = MockProvider(
        default=(
            '{"real": false, "reason": "owner filter present", "control_file": "models/item.go", "control_line": 1}'
        )
    )
    verdict = ModelVerifier(provider=prov, model="mock").verify(
        Candidate(title="idor", file="models/item.go"), _repo(tmp_path, "models/item.go")
    )
    assert verdict.real is False


def test_model_checker_confirms_a_holding_refutation(tmp_path):
    prov = MockProvider(default='{"holds": true, "reason": "the guard dominates the only path"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    root = _repo(tmp_path, "t.py")
    refutation = Verdict(
        real=False,
        reason="owner check present",
        control_file="t.py",
        control_line=1,
    )
    result = checker.holds(Candidate(title="x", file="t.py"), refutation, root)
    assert result.holds is True
    assert result.reason == "the guard dominates the only path"


def test_model_checker_raises_on_an_unparseable_audit(tmp_path):
    prov = MockProvider(default="not json")
    checker = ModelRefutationChecker(provider=prov, model="mock")
    root = _repo(tmp_path, "t.py")
    with pytest.raises(VerifyError, match="unparseable refutation check reply"):
        checker.holds(
            Candidate(title="x", file="t.py"),
            Verdict(real=False, reason="some reason", control_file="t.py", control_line=1),
            root,
        )


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        ('{"real": false', "verifier"),
        ('{"holds": true', "checker"),
    ],
)
def test_verification_rejects_repaired_truncated_verdicts(tmp_path, reply, kind):
    root = _repo(tmp_path, "t.py")
    if kind == "verifier":
        with pytest.raises(VerifyError, match="unparseable verification reply"):
            ModelVerifier(provider=MockProvider(default=reply), model="m").verify(
                Candidate(title="x", file="t.py"), root
            )
    else:
        with pytest.raises(VerifyError, match="unparseable refutation check reply"):
            ModelRefutationChecker(provider=MockProvider(default=reply), model="m").holds(
                Candidate(title="x", file="t.py"),
                Verdict(real=False, reason="control", control_file="t.py", control_line=1),
                root,
            )


def test_model_checker_rejects_a_non_boolean_holds_field(tmp_path):
    prov = MockProvider(default='{"holds": "false", "reason": "invalid"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    root = _repo(tmp_path, "t.py")
    with pytest.raises(VerifyError, match=r"\$response.holds must be boolean"):
        checker.holds(
            Candidate(title="x", file="t.py"),
            Verdict(real=False, reason="some reason", control_file="t.py", control_line=1),
            root,
        )


def test_model_checker_cannot_confirm_a_refutation_it_could_not_read(tmp_path):
    prov = MockProvider(default='{"holds": true, "reason": "the guard dominates"}')
    checker = ModelRefutationChecker(provider=prov, model="mock")
    result = checker.holds(
        Candidate(title="x", file="gone.py"),
        Verdict(real=False, reason="owner check present", control_file="gone.py", control_line=1),
        _repo(tmp_path, "t.py"),
    )
    assert result.holds is False
    assert result.reason == "the controlling fact is outside the candidate file"
    assert prov.calls == []


def test_read_file_returns_empty_for_an_out_of_root_path(tmp_path):
    secret = tmp_path / "secret.py"
    secret.write_text("token = 'sk-live'")
    root = tmp_path / "repository"
    root.mkdir()
    assert _read_file(str(root), "../secret.py") == ""
    assert _read_file(str(root), str(secret)) == ""


def test_model_verifier_reads_a_window_centered_on_the_finding_line(tmp_path):
    lines = [f"line_{index} = {'x' * 700}\n" for index in range(1, 101)]
    root = _repo(tmp_path, "large.py")
    (tmp_path / "large.py").write_text("".join(lines), encoding="utf-8")
    provider = MockProvider(
        default='{"real": true, "reason": "candidate remains", "control_file": "", "control_line": 0}'
    )

    ModelVerifier(provider=provider, model="m").verify(
        Candidate(title="late finding", file="large.py", line=90),
        root,
    )

    prompt = provider.calls[0]["messages"][0].content
    assert "line_90" in prompt
    assert "line_1 =" not in prompt


def test_a_refutation_citing_a_missing_control_line_is_incomplete(tmp_path):
    class InvalidControl(Verifier):
        def verify(self, candidate, root):
            return Verdict(real=False, reason="claimed guard", control_file="app.py", control_line=2)

    root = _repo(tmp_path, "app.py")
    candidate = Candidate(title="candidate", file="app.py", line=1)
    result = verify_findings(
        [candidate],
        InvalidControl(),
        root,
        confirmers=_judge(_StubChecker(["candidate"])),
        concurrency=1,
    )

    assert result.retained == [candidate]
    assert result.incomplete == [candidate]
    assert "control line does not exist" in result.error_details[0]


def test_a_boolean_control_line_from_an_injected_verifier_is_incomplete(tmp_path):
    class BooleanControl(Verifier):
        def verify(self, candidate, root):
            return Verdict(real=False, reason="claimed guard", control_file="app.py", control_line=True)

    root = _repo(tmp_path, "app.py")
    candidate = Candidate(title="candidate", file="app.py", line=1)
    result = verify_findings(
        [candidate],
        BooleanControl(),
        root,
        confirmers=_judge(_StubChecker(["candidate"])),
        concurrency=1,
    )

    assert result.retained == [candidate]
    assert result.incomplete == [candidate]
    assert "controlling file, line, and reason" in result.error_details[0]


def test_verification_receipt_round_trips_every_candidate_decision():
    candidate = Candidate(title="candidate", file=_CANDIDATE_FILE, line=1)
    result = verify_findings(
        [candidate],
        _StubVerifier(["candidate"]),
        ".",
        confirmers=_judge(_StubChecker(["candidate"])),
        concurrency=1,
    )
    receipt = VerificationReceipt.create(
        request_sha256="a" * 64,
        enabled=True,
        candidate_ids=result.candidate_ids,
        records=tuple(result.records),
    )

    assert VerificationReceipt.from_dict(json.loads(json.dumps(receipt.to_dict()))) == receipt
    assert receipt.decisions[0].outcome == "refuted"
    assert receipt.decisions[0].required_confirmer_seat_ids
    changed = receipt.to_dict()
    changed["content_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="content hash"):
        VerificationReceipt.from_dict(changed)


def test_verify_findings_reports_progress_per_candidate():
    cands = [Candidate(title=f"c{i}", endpoint="GET /x") for i in range(4)]
    seen = []
    verify_findings(
        cands, _StubVerifier([]), ".", concurrency=2, on_verify=lambda done, total, secs: seen.append((done, total))
    )
    assert sorted(seen) == [(1, 4), (2, 4), (3, 4), (4, 4)]
