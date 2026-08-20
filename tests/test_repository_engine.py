"""Repository review run, resume, finalize, and output lifecycle tests."""

import json

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryFinalizeOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    _parse_candidate,
)
from cyberjury.review.repository.engine import (
    finalize_repository_review as _finalize_repository_review,
)
from cyberjury.review.repository.engine import (
    run_repository_review as _run_repository_review,
)
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.repository.reviewer import UnitChallenge, UnitReviewer
from cyberjury.review.repository.scaffold import WORKSPACE_MARKER, unit_slug
from cyberjury.review.repository.union import Candidate
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.verification import RefutationChecker, Verdict, Verifier
from cyberjury.sources.metadata import SourceError

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 11, '
    '"severity": "HIGH", "evidence": "wallet.py:11 no owner check", "status": "confirmed"}]}'
)


def _run_review(target, workspace, **values):
    """Build grouped run options from the policy values relevant to each test."""
    concurrency = values.pop("concurrency", DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency)
    roles = RepositoryRoleOptions(
        **{
            key: values.pop(key)
            for key in (
                "mode",
                "provider",
                "model",
                "challenger_provider",
                "challenger_model",
                "judge_provider",
                "judge_model",
                "reviewer",
                "challenger_reviewer",
                "judge_reviewer",
                "extra_finder_backends",
            )
            if key in values
        }
    )
    verification = RepositoryVerificationOptions(
        concurrency=concurrency,
        **{
            ("enabled" if key == "verify" else key): values.pop(key)
            for key in ("verify", "verifier", "confirmers", "votes", "on_verify")
            if key in values
        },
    )
    execution = RepositoryExecutionOptions(
        concurrency=concurrency,
        **{
            key: values.pop(key)
            for key in ("max_passes", "converge_after", "min_rounds", "on_pass", "on_judgment")
            if key in values
        },
    )
    output = RepositoryOutputOptions(
        **{key: values.pop(key) for key in ("profile", "poc_backend", "meter") if key in values}
    )
    lifecycle = RepositoryLifecycleOptions(fresh=values.pop("fresh", False))
    assert not values
    return _run_repository_review(
        target,
        workspace,
        options=RepositoryRunOptions(
            roles=roles,
            verification=verification,
            execution=execution,
            lifecycle=lifecycle,
            output=output,
        ),
    )


def _finalize_review(target, workspace, **values):
    """Build grouped finalize options from the policy values relevant to each test."""
    verification = RepositoryVerificationOptions(
        **{
            ("enabled" if key == "verify" else key): values.pop(key)
            for key in (
                "verify",
                "verifier",
                "confirmers",
                "provider",
                "model",
                "votes",
                "concurrency",
                "on_verify",
            )
            if key in values
        }
    )
    output = RepositoryOutputOptions(
        **{key: values.pop(key) for key in ("profile", "poc_backend", "meter") if key in values}
    )
    assert not values
    return _finalize_repository_review(
        target,
        workspace,
        options=RepositoryFinalizeOptions(verification=verification, output=output),
    )


def _mark_workspace(project):
    marker = project / WORKSPACE_MARKER
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps({"project": project.name, "profile": "web"}) + "\n",
        encoding="utf-8",
    )


def test_standard_run_completes_writes_findings_and_marks_units(custody_repository, tmp_path):
    prov = MockProvider(default=_REPLY)
    res = _run_review(
        custody_repository,
        tmp_path / "ws",
        provider=prov,
        model="mock",
        converge_after=2,
        max_passes=12,
        verify=False,
    )
    ws = res.scaffold.workspace

    assert res.outcome.complete
    assert res.accumulator.converged is False
    assert len(res.accumulator.findings) == 1
    assert res.outcome is not None
    assert res.outcome.complete is True

    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    findings = list((ws / "findings").glob("*.md"))
    assert findings
    assert "Risk: HIGH" in findings[0].read_text()

    units = list((ws / "units").glob("*.md"))
    assert units
    assert all("Status: reviewed" in u.read_text() for u in units)
    assert not any("Status: open" in u.read_text() for u in units)

    assert not (ws / "_pocs.md").exists()

    status = json.loads((ws / "_run.json").read_text())
    assert status["converged"] is False
    assert status["complete"] is True
    assert status["errors"] == 0
    assert status["units_reviewed"] == status["units_total"] == len(units)
    assert status["failed_units"] == []


def test_run_writes_pocs_when_a_backend_is_bound(custody_repository, tmp_path):

    class WritePoC:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return type("Artifact", (), {"source": "import requests\n", "run_hint": "python poc.py", "note": ""})()

    res = _run_review(
        custody_repository,
        tmp_path / "ws",
        provider=MockProvider(default=_REPLY),
        model="mock",
        verify=False,
        converge_after=2,
        max_passes=12,
        poc_backend=WritePoC(),
    )
    pocs = sorted((res.scaffold.workspace / "pocs").glob("*.py"))
    assert len(pocs) == 1
    assert "import requests" in pocs[0].read_text()
    finding = next((res.scaffold.workspace / "findings").glob("*.md")).read_text()
    assert "PoC written, run it manually" in finding


class _CountingReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        return [
            Candidate(
                title="wallet idor",
                category="idor",
                endpoint="GET /wallets/<id>",
                file="app/services/wallet.py",
                severity="HIGH",
            )
        ]


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True)


class _EmptyChallenger(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def challenge(self, unit, finder_findings, *, shared_context="", known=None):
        return UnitChallenge(rebuttals=[], new_findings=[])


class _PassingJudge(UnitReviewer):
    def review(self, unit, *, shared_context=""):
        return []

    def judge(self, unit, finder_findings, rebuttals, new_findings, *, shared_context="", known=None):
        return finder_findings + new_findings


def test_resume_skips_reviewed_units_and_verified_findings(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    r1v = _CountingVerifier()
    _run_review(custody_repository, ws, reviewer=_CountingReviewer(), verifier=r1v, converge_after=1, max_passes=4)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1
    assert r1v.calls >= 1

    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    _run_review(custody_repository, ws, reviewer=r2, verifier=r2v, converge_after=1, max_passes=4, fresh=False)
    assert r2.calls == 0
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entry"] for f in findings_after_2} == {f["entry"] for f in findings_after_1}


def test_completed_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    _run_review(
        custody_repository,
        workspace,
        reviewer=_CountingReviewer(),
        verify=False,
        max_passes=1,
    )
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _CountingReviewer()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        _run_review(
            custody_repository,
            workspace,
            reviewer=resumed,
            verify=False,
            max_passes=1,
        )

    assert resumed.calls == 0


def test_nonconverged_adversarial_resume_replays_open_units_and_can_complete(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 1,
        "min_rounds": 1,
        "max_passes": 1,
        "concurrency": 1,
    }
    first_reviewer = _CountingReviewer()

    first = _run_review(custody_repository, ws, reviewer=first_reviewer, **shared)
    project = first.scaffold.workspace

    assert first.outcome.complete is False
    assert first.accumulator.converged is False
    first_finding_keys = {candidate.key() for candidate in first.accumulator.findings}
    assert first_finding_keys
    assert first_reviewer.calls > 0
    assert all("Status: open" in unit.read_text() for unit in (project / "units").glob("*.md"))
    first_status = json.loads((project / "_run.json").read_text())
    assert first_status["state"] == "incomplete"
    assert first_status["units_reviewed"] == 0

    second_reviewer = _CountingReviewer()
    second = _run_review(custody_repository, ws, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls > 0
    assert second.outcome.complete is True
    assert second.accumulator.converged is True
    assert {candidate.key() for candidate in second.accumulator.findings} == first_finding_keys
    assert all("Status: reviewed" in unit.read_text() for unit in (project / "units").glob("*.md"))
    second_status = json.loads((project / "_run.json").read_text())
    assert second_status["state"] == "converged"
    assert second_status["units_reviewed"] == second_status["units_total"]


def test_partial_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 2,
        "min_rounds": 1,
        "max_passes": 1,
        "concurrency": 1,
    }
    first = _run_review(custody_repository, workspace, reviewer=_CountingReviewer(), **shared)
    assert first.outcome.complete is False
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _CountingReviewer()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        _run_review(custody_repository, workspace, reviewer=resumed, **shared)

    assert resumed.calls == 0


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    _run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match=r"no _union\.json"):
        _run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )


def test_parse_candidate_captures_file_and_line_from_a_range(tmp_path):
    p = tmp_path / "i.md"
    p.write_text(
        "# freshness gap\n- Risk: HIGH\n- Type: replay\n- Source: `POST /v1/check`\n"
        "## Analysis\n`authorizer/controllers/registrar.py:58-75` no nonce.\n"
    )
    c = _parse_candidate(p)
    assert c.file == "authorizer/controllers/registrar.py"
    assert c.line == 58
    assert c.severity == "HIGH"


def test_parse_candidate_strips_a_finding_title_prefix(tmp_path):
    p = tmp_path / "i.md"
    p.write_text(
        "# Finding: Signing Key Committed to Source\n- Risk: LOW\n- Type: secret\n"
        "- Source: `GET /v1/key`\n## Analysis\n`app/keys.py:3` hardcoded.\n"
    )
    c = _parse_candidate(p)
    assert c.title == "Signing Key Committed to Source"


def test_parse_candidate_drops_an_out_of_root_cited_path(tmp_path):
    traversing = tmp_path / "t.md"
    traversing.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `../../etc/secret.py:1` for the key.\n")
    assert _parse_candidate(traversing) is None
    absolute = tmp_path / "a.md"
    absolute.write_text("# leak\n- Risk: HIGH\n- Type: idor\n## Analysis\nsee `/home/user/secret.py:1` for the key.\n")
    assert _parse_candidate(absolute) is None


def test_parse_candidate_drops_a_cleared_or_refuted_record(tmp_path):
    refuted = tmp_path / "r.md"
    refuted.write_text(
        "# Attachment IDOR, refuted\n- Status: refuted (no finding)\n- Type: idor\n"
        "## Why\n`pkg/models/task_attachment.go:111` xorm scopes the fetch.\n"
    )
    assert _parse_candidate(refuted) is None
    cleared = tmp_path / "c.md"
    cleared.write_text(
        "# Permission methods cleared\n- Status: cleared\n- Type: idor\n"
        "## Scope\n`pkg/models/task_attachment_permissions.go:25` holds.\n"
    )
    assert _parse_candidate(cleared) is None
    titled = tmp_path / "t.md"
    titled.write_text(
        "# Cleared controls and paths checked\n- Type:\n"
        "## Blacklist gate\n`pkg/models/token.go:82` adminSanity enforces it.\n"
    )
    assert _parse_candidate(titled) is None
    confirmed = tmp_path / "k.md"
    confirmed.write_text(
        "# real leak\n- Status: confirmed\n- Type: idor\n## Analysis\n`pkg/models/link_sharing.go:272` leaks hashes.\n"
    )
    assert _parse_candidate(confirmed) is not None


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


def _finalize_ws(tmp_path):
    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    for name in ("v.py", "s.py", "d.py"):
        (target / "app" / name).write_text("x = 1\n")
    ws = tmp_path / "work"
    candidates = ws / "proj" / "candidates"
    candidates.mkdir(parents=True)
    _mark_workspace(ws / "proj")
    return target, ws, candidates


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


class _RaisingReviewer(UnitReviewer):
    """Raises for marked units and reviews the rest cleanly."""

    def __init__(self, fail_substr):
        self.fail_substr = fail_substr

    def review(self, unit, *, shared_context=""):
        if self.fail_substr in unit.name:
            raise RuntimeError("provider rate limited")
        return [
            Candidate(
                title="ok", category="idor", endpoint=f"GET /{unit.name}", file=unit.name, line=1, severity="HIGH"
            )
        ]


class _RecoveringUnitReviewer(UnitReviewer):
    def __init__(self):
        self.calls = 0
        self.failed = False

    def review(self, unit, *, shared_context=""):
        self.calls += 1
        if unit.name == "beta/routes.py" and not self.failed:
            self.failed = True
            raise RuntimeError("temporary rate limit")
        return [
            Candidate(
                title=unit.name,
                category="idor",
                endpoint=f"GET /{unit.name}",
                file=unit.name,
                line=1,
                severity="HIGH",
            )
        ]


def _two_entrypoint_repository(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n'
        )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_failed_unit_stays_open_and_fails_the_gate(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"
    res = _run_review(
        repository, ws, reviewer=_RaisingReviewer("beta/routes.py"), verify=False, converge_after=1, max_passes=4
    )
    proj = ws / "twop"

    assert "beta/routes.py" in res.accumulator.failed_units
    assert res.accumulator.errors > 0

    units = {u.stem: u.read_text() for u in (proj / "units").glob("*.md")}
    assert "Status: open" in units[unit_slug("beta/routes.py")]
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]

    surface = (proj / "inventory" / "_surface.md").read_text()
    beta_row = next(line for line in surface.splitlines() if "beta/routes.py" in line)
    assert "open" in beta_row
    assert "reviewed" not in beta_row

    status = json.loads((proj / "_run.json").read_text())
    assert status["complete"] is False
    assert status["state"] == "incomplete"
    assert status["unit_failures"][0]["paths"] == ["beta/routes.py"]
    assert status["unit_failures"][0]["reason"] == "RuntimeError: provider rate limited"

    assert check_gate(proj).passed is False


def test_nonconverged_adversarial_run_keeps_successful_siblings_open(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    result = _run_review(
        repository,
        tmp_path / "ws",
        mode="adversarial",
        reviewer=_RaisingReviewer("beta/routes.py"),
        challenger_reviewer=_EmptyChallenger(),
        judge_reviewer=_PassingJudge(),
        verify=False,
        converge_after=1,
        min_rounds=1,
        max_passes=1,
        concurrency=1,
    )

    assert result.outcome.complete is False
    assert result.accumulator.converged is False
    assert result.accumulator.failed_units == {"beta/routes.py"}
    units = list((result.scaffold.workspace / "units").glob("*.md"))
    assert units
    assert all("Status: open" in unit.read_text() for unit in units)
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["units_reviewed"] == 0


def test_recovered_failure_stays_open_until_a_clean_resume(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    workspace = tmp_path / "ws"
    shared = {
        "mode": "adversarial",
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "converge_after": 1,
        "min_rounds": 1,
        "max_passes": 3,
        "concurrency": 1,
    }

    first_reviewer = _RecoveringUnitReviewer()
    first = _run_review(repository, workspace, reviewer=first_reviewer, **shared)
    project = first.scaffold.workspace

    assert first.accumulator.converged is True
    assert first.outcome.complete is False
    assert first.accumulator.failed_units == {"beta/routes.py"}
    units = {unit.stem: unit.read_text() for unit in (project / "units").glob("*.md")}
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]
    assert "Status: open" in units[unit_slug("beta/routes.py")]

    second_reviewer = _CountingReviewer()
    second = _run_review(repository, workspace, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls > 0
    assert second.outcome.complete is True
    assert all("Status: reviewed" in unit.read_text() for unit in (project / "units").glob("*.md"))


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    _run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=4,
    )
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        _run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=4,
            fresh=False,
        )
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_finalize_raises_loud(tmp_path):
    target, ws, candidates = _finalize_ws(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (ws / "proj" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    class _V(Verifier):
        def verify(self, c, root):
            return Verdict(real=True)

    with pytest.raises(ValueError, match="corrupt"):
        _finalize_review(target, ws, verifier=_V(), concurrency=1)


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {"candidate": {"real": 0, "reason": "corrupt"}},
        {"candidate": {"real": False, "reason": 1}},
        {"candidate": {"real": False}},
    ],
)
def test_structurally_corrupt_verified_checkpoint_raises_loud(tmp_path, checkpoint):
    from cyberjury.review.repository.verify import apply_verification

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
            provider=None,
            model="m",
            votes=1,
            concurrency=1,
            fresh=False,
        )


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {},
        {"findings": {}},
        {"findings": ["bad"]},
        {"findings": [{}]},
        {"findings": [{"title": 1}]},
        {"findings": [{"title": "x", "severity": "URGENT"}]},
        {"findings": [{"title": "x", "status": "maybe"}]},
        {"findings": [{"line": True}]},
        {"findings": [{"found_by": [1]}]},
    ],
)
def test_structurally_corrupt_union_checkpoint_raises_loud(tmp_path, checkpoint):
    from cyberjury.review.repository.engine import _load_union

    (tmp_path / "_union.json").write_text(json.dumps(checkpoint))

    with pytest.raises(ValueError, match="corrupt"):
        _load_union(tmp_path)


def test_failed_verification_is_kept_for_the_run_but_not_frozen_for_resume(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

    class _Boom(Verifier):
        def verify(self, c, root):
            raise RuntimeError("rate limited")

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = [Candidate(title="boom", endpoint="GET /a", file="a.py", line=1)]
    confirmed, vr = apply_verification(
        ws, findings, root=str(tmp_path), verifier=_Boom(), provider=None, model="m", votes=1, concurrency=1, fresh=True
    )
    assert [c.title for c in confirmed] == ["boom"]
    assert vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {}
    assert [c.title for c in vr.incomplete] == ["boom"]
    assert vr.error_details == ["RuntimeError: rate limited"]


def test_repository_outcome_and_status_preserve_verification_failure_reason(custody_repository, tmp_path):

    class _Boom(Verifier):
        def verify(self, candidate, root):
            raise RuntimeError("rate limited")

    result = _run_review(
        custody_repository,
        tmp_path / "ws",
        reviewer=_CountingReviewer(),
        verifier=_Boom(),
        converge_after=1,
        max_passes=1,
        concurrency=1,
    )

    assert result.outcome is not None
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["failure_reason"] == "verification failed: RuntimeError: rate limited"


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


def test_parse_candidate_accepts_data_driven_extensions(tmp_path):
    go = tmp_path / "go.md"
    go.write_text(
        "# go handler idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x`\n"
        "- Status: confirmed\n## Analysis\nsrc/handler.go:42 no owner check\n"
    )
    c = _parse_candidate(go)
    assert c is not None
    assert c.file == "src/handler.go"
    assert c.line == 42

    tsx = tmp_path / "tsx.md"
    tsx.write_text(
        "# react xss\n- Risk: MEDIUM\n- Type: xss\n- Source: `x`\n"
        "- Status: confirmed\n## Analysis\nweb/App.tsx:10 dangerouslySetInnerHTML\n"
    )
    c2 = _parse_candidate(tsx)
    assert c2 is not None
    assert c2.file == "web/App.tsx"
    assert c2.line == 10


def test_run_fails_loud_on_zero_units(tmp_path):
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no candidate entrypoints"):
        _run_review(repository, tmp_path / "ws")
