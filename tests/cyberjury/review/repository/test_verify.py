"""Repository verification tests cover candidate retention and checkpoint reuse."""

import json
from dataclasses import replace

import pytest

from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verify import apply_verification
from cyberjury.review.verification import RefutationCheck, RefutationChecker, Verdict, Verifier


class _IndependentChecker(RefutationChecker):
    def holds(self, candidate, refutation, root):
        return RefutationCheck(holds=False, reason="the candidate remains exploitable")


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True, reason="candidate remains exploitable")


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {"schema": 7, "candidates": []},
        {"schema": 7, "candidates": {"candidate": {"outcome": "refuted"}}},
        {"schema": 7, "candidates": {"candidate": {"real": False, "reason": "corrupt", "record": {}}}},
    ],
)
def test_structurally_corrupt_verified_checkpoint_raises_loud(tmp_path, checkpoint):
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    (ws / "_verified.json").write_text(json.dumps(checkpoint))
    findings = [Candidate(title="x", endpoint="GET /x", file="a.py", line=1)]

    with pytest.raises(ValueError, match="corrupt"):
        apply_verification(
            ws,
            findings,
            root=str(tmp_path),
            verifier=_CountingVerifier(),
            concurrency=1,
            fresh=False,
        )


def test_failed_verification_is_kept_for_the_run_but_not_frozen_for_resume(tmp_path):
    class _Boom(Verifier):
        def verify(self, c, root):
            raise RuntimeError("rate limited")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = [Candidate(title="boom", endpoint="GET /a", file="a.py", line=1)]
    confirmed, vr = apply_verification(
        ws,
        findings,
        root=str(tmp_path),
        verifier=_Boom(),
        confirmers=[("independent", _IndependentChecker())],
        concurrency=1,
        fresh=True,
    )
    assert [c.title for c in confirmed] == ["boom"]
    assert vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {"schema": 7, "candidates": {}}
    assert [c.title for c in vr.incomplete] == ["boom"]
    assert vr.error_details == ["RuntimeError: rate limited"]


def test_retention_without_an_independent_confirmer_is_not_frozen_as_verified(tmp_path):
    class _NeverCalled(Verifier):
        def verify(self, c, root):
            raise AssertionError("no verifier should run without an independent confirmer")

    workspace = tmp_path / "ws"
    workspace.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    finding = Candidate(title="retained", endpoint="GET /a", file="a.py", line=1)

    retained, result = apply_verification(
        workspace,
        [finding],
        root=str(tmp_path),
        verifier=_NeverCalled(),
        confirmers=None,
        concurrency=1,
        fresh=True,
    )

    assert retained == [finding]
    assert result.verified == []
    assert result.records[0].reason == "no independent confirmer can authorize deletion"
    assert json.loads((workspace / "_verified.json").read_text()) == {"schema": 7, "candidates": {}}


def test_incomplete_checkpoint_can_never_be_loaded_as_a_refutation(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    checkpoint = {
        "schema": 7,
        "candidates": {
            "verify-v7-tampered": {
                "outcome": "incomplete",
                "reason": "provider failed",
                "required_confirmer_seat_ids": ["seat-confirmer"],
                "votes": [
                    {
                        "role": "skeptic",
                        "actor_id": "actor-skeptic",
                        "seat_id": "seat-skeptic",
                        "verdict": "error",
                        "reason": "provider failed",
                        "control_file": "",
                        "control_line": None,
                    }
                ],
            }
        },
    }
    (ws / "_verified.json").write_text(json.dumps(checkpoint), encoding="utf-8")

    with pytest.raises(ValueError, match="corrupt"):
        apply_verification(
            ws,
            [Candidate(title="candidate", file="a.py", line=1)],
            root=str(tmp_path),
            verifier=_CountingVerifier(),
            confirmers=[("independent", _IndependentChecker())],
            concurrency=1,
            fresh=False,
        )


@pytest.mark.parametrize("schema", [2, 3, 4, 5, 6])
def test_older_checkpoint_schema_is_rejected_with_a_clear_error(tmp_path, schema):
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    (ws / "_verified.json").write_text(
        json.dumps({"schema": schema, "candidates": {"legacy": {"untrusted": True}}}),
        encoding="utf-8",
    )
    verifier = _CountingVerifier()

    with pytest.raises(ValueError, match=r"schema is unsupported.*Remove the workspace"):
        apply_verification(
            ws,
            [Candidate(title="candidate", file="a.py", line=1)],
            root=str(tmp_path),
            verifier=verifier,
            confirmers=[("independent", _IndependentChecker())],
            concurrency=1,
            fresh=False,
        )

    assert verifier.calls == 0


def test_verification_record_round_trips_through_the_checkpoint(tmp_path):
    from cyberjury.review.repository.verify import _record_from_data, _record_to_data
    from cyberjury.review.verification import VerificationRecord, VerificationVote

    candidate = Candidate(title="candidate", file="app.py", line=1)
    record = VerificationRecord(
        candidate=candidate,
        outcome="retained",
        reason="candidate remains exploitable",
        votes=(
            VerificationVote(
                role="skeptic",
                actor_id="actor-skeptic",
                seat_id="seat-skeptic",
                verdict="real",
                reason="candidate remains exploitable",
            ),
        ),
        required_confirmer_seat_ids=("seat-confirmer",),
    )

    assert _record_from_data(_record_to_data(record), candidate) == record


def test_changed_candidate_content_does_not_reuse_a_refutation_checkpoint(tmp_path):
    class Refute(Verifier):
        def __init__(self):
            self.calls = 0
            self.real = False

        def verify(self, candidate, root):
            self.calls += 1
            if self.real:
                return Verdict(real=True, reason="candidate remains exploitable")
            return Verdict(
                real=False,
                reason="old control",
                control_file=candidate.file,
                control_line=candidate.line,
            )

    class Uphold(RefutationChecker):
        def holds(self, candidate, refutation, root):
            return RefutationCheck(holds=True, reason="control covers the candidate path")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    original = Candidate(
        title="old path",
        category="idor",
        file="a.py",
        line=1,
        evidence="old evidence",
    )
    refuter = Refute()
    _kept, first_result = apply_verification(
        ws,
        [original],
        root=str(tmp_path),
        verifier=refuter,
        confirmers=[("checker", Uphold())],
        concurrency=1,
        fresh=True,
    )
    _kept, cached_result = apply_verification(
        ws,
        [original],
        root=str(tmp_path),
        verifier=refuter,
        confirmers=[("checker", Uphold())],
        concurrency=1,
        fresh=False,
    )
    assert refuter.calls == 1
    assert first_result.records[0].votes == cached_result.records[0].votes
    assert [vote.verdict for vote in cached_result.records[0].votes] == ["refuted", "upheld"]
    changed = replace(original, title="new path", evidence="new evidence")
    refuter.real = True

    kept, result = apply_verification(
        ws,
        [changed],
        root=str(tmp_path),
        verifier=refuter,
        confirmers=[("checker", Uphold())],
        concurrency=1,
        fresh=False,
    )

    assert refuter.calls == 2
    assert kept == [changed]
    assert result.refuted == []


def test_multi_source_finding_still_runs_verification(tmp_path):
    class _Refute(Verifier):
        def __init__(self):
            self.calls = 0

        def verify(self, c, root):
            self.calls += 1
            return Verdict(real=False, reason="guard at a.py:1", control_file=c.file, control_line=1)

    class _Confirm(RefutationChecker):
        def holds(self, candidate, reason, root):
            return RefutationCheck(holds=True, reason="control covers the candidate path")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    verifier = _Refute()
    findings = [Candidate(title="fp", endpoint="GET /a", file="a.py", line=1, found_by=("claude", "gpt"))]
    confirmed, vr = apply_verification(
        ws,
        findings,
        root=str(tmp_path),
        verifier=verifier,
        confirmers=[("confirmer", _Confirm())],
        concurrency=1,
        fresh=True,
    )
    assert verifier.calls == 1
    assert confirmed == []
    assert [c.title for c, _reason in vr.refuted] == ["fp"]


def test_a_location_matching_no_file_stays_incomplete_and_unreported(tmp_path):
    class _NeverCalled(Verifier):
        def verify(self, c, root):
            raise AssertionError("a location matching no file must never reach the skeptic")

    ws = tmp_path / "ws"
    ws.mkdir()
    findings = [Candidate(title="ghost", endpoint="GET /a", file="gone.py", line=1)]
    confirmed, vr = apply_verification(
        ws,
        findings,
        root=str(tmp_path),
        verifier=_NeverCalled(),
        concurrency=1,
        fresh=True,
    )
    assert confirmed == []
    assert [c.title for c in vr.unlocatable] == ["ghost"]
    assert not vr.refuted
    assert json.loads((ws / "_verified.json").read_text()) == {"schema": 7, "candidates": {}}
