"""Repository finalization reconciles candidates, verification, metadata, and status."""

import json

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.union import Candidate
from cyberjury.review.verification import RefutationChecker, Verdict, Verifier
from cyberjury.sources.metadata import SourceError
from tests.cyberjury.review.repository.engine.factories import finalize_review as _finalize_review
from tests.cyberjury.review.repository.engine.factories import finalize_workspace as _finalize_ws
from tests.cyberjury.review.repository.engine.factories import mark_workspace as _mark_workspace


def test_finalize_dedups_verifies_and_reports(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "a2.md").write_text(
        "# idor again\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/{id}`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "b.md").write_text(
        "# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n"
    )
    (candidates / "fp.md").write_text(
        "# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n"
    )

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            return "/r" in c.endpoint

    fr = _finalize_review(target, ws, verifier=_V(), confirmers=[("", _C())], concurrency=1)
    assert fr.parsed == 4
    assert fr.deduped == 3
    assert len(fr.verify.confirmed) == 2
    assert len(fr.verify.refuted) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    entries = {f["entry"] for f in data["findings"]}
    assert any("/x/" in e for e in entries)
    assert any("/t" in e for e in entries)
    assert not any("/r" in e for e in entries)


def test_finalize_records_its_completeness_and_spend_so_a_later_gate_can_read_them(tmp_path):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter

    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "b.md").write_text(
        "# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n"
    )

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(real=not bad, reason="lock holds on prod" if bad else "")

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            return "/r" in c.endpoint

    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default='{"findings": []}'), meter)
    fr = _finalize_review(
        target, ws, verifier=_V(), confirmers=[("", _C())], concurrency=1, provider=provider, meter=meter
    )
    status = json.loads((fr.workspace / "_finalize.json").read_text())
    assert status["parsed"] == 2
    assert status["deduped"] == 2
    assert status["confirmed"] == 1
    assert status["refuted"] == 1
    assert status["verify_errors"] == 0
    assert status["incomplete"] == 0
    assert status["unlocatable"] == 0
    assert status["usage"] == meter.snapshot()


def test_finalize_without_a_meter_records_completeness_and_omits_usage(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    fr = _finalize_review(target, ws, verify=False)
    status = json.loads((fr.workspace / "_finalize.json").read_text())
    assert status["deduped"] == 1
    assert "usage" not in status
    assert "confirmed" not in status


def test_finalize_requires_a_scaffolded_workspace(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"

    with pytest.raises(ValueError, match="Run --scaffold or --run"):
        _finalize_review(target, ws, verify=False)


def test_finalize_falls_back_to_the_union_when_no_workspace_candidates(tmp_path):
    from cyberjury.review.repository.engine import _save_union

    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    (target / "app" / "v.py").write_text("def read():\n    return 1\n")
    ws = tmp_path / "work"
    project = ws / "proj"
    (project / "candidates").mkdir(parents=True)
    _mark_workspace(project)
    _save_union(project, [Candidate(title="idor read", category="idor", file="app/v.py", line=10)])

    fr = _finalize_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    assert fr.parsed == 1
    assert len(fr.verify.confirmed) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1


class _AllReal(Verifier):
    def verify(self, c, root):
        return Verdict(real=True, reason="")


def _seed_one_candidate(target, ws):
    candidates = ws / target.name / "candidates"
    candidates.mkdir(parents=True)
    _mark_workspace(ws / target.name)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )


def test_finalize_adds_target_metadata_without_changing_findings(tmp_path):
    meta = {
        "chain": "bsc",
        "chain_id": 56,
        "address": "0x" + "ab" * 20,
        "source_url": "https://bscscan.com/address/x#code",
        "contract_name": "Token",
    }

    plain_t = tmp_path / "plain"
    plain_t.mkdir()
    plain_ws = tmp_path / "plain_ws"
    _seed_one_candidate(plain_t, plain_ws)
    plain = _finalize_review(plain_t, plain_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    plain_report = json.loads((plain.workspace / "findings.json").read_text())

    meta_t = tmp_path / "meta"
    meta_t.mkdir()
    (meta_t / "cyberjury-source.json").write_text(json.dumps(meta))
    meta_ws = tmp_path / "meta_ws"
    _seed_one_candidate(meta_t, meta_ws)
    withmeta = _finalize_review(meta_t, meta_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    meta_report = json.loads((withmeta.workspace / "findings.json").read_text())

    assert meta_report["findings"] == plain_report["findings"]
    assert "target" not in plain_report
    assert meta_report["target"]["chain"] == "bsc"
    assert (withmeta.workspace / "_target.md").read_text().startswith("## Target")
    assert not (plain.workspace / "_target.md").exists()


def test_finalize_fails_loud_on_malformed_source_metadata(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    (target / "cyberjury-source.json").write_text("{not valid json")
    ws = tmp_path / "work"
    _seed_one_candidate(target, ws)
    with pytest.raises(SourceError, match="malformed"):
        _finalize_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)


def test_multi_source_finding_still_runs_verification(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

    class _Refute(Verifier):
        def __init__(self):
            self.calls = 0

        def verify(self, c, root):
            self.calls += 1
            return Verdict(real=False, reason="guard at a.py:1")

    class _Confirm(RefutationChecker):
        def holds(self, candidate, reason, root):
            return True

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
        confirmers=[("judge", _Confirm())],
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    assert verifier.calls == 1
    assert confirmed == []
    assert [c.title for c, _reason in vr.refuted] == ["fp"]


def test_a_location_matching_no_file_stays_incomplete_and_unreported(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

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
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    assert confirmed == []
    assert [c.title for c in vr.unlocatable] == ["ghost"]
    assert not vr.refuted
    assert json.loads((ws / "_verified.json").read_text()) == {}


def test_finalize_drops_issue_with_no_file_location(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "noloc.md").write_text(
        "# missing location\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n"
        "## Analysis\nno concrete location was cited.\n"
    )
    fr = _finalize_review(target, ws, verify=False)
    assert fr.parsed == 0
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert data["findings"] == []


def test_finalize_preserves_blocked_status(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "blocked.md").write_text(
        "# needs poc\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n- Status: blocked\n"
        "## Analysis\napp/s.py:5 no nonce, a PoC needs credentials.\n"
    )
    fr = _finalize_review(target, ws, verify=False)
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["status"] == "blocked"
