"""Repository engine tests cover its complete persistent lifecycle."""

import json
from dataclasses import replace

import pytest

from cyberjury.profiles.base import PoCArtifact
from cyberjury.providers.mock import MockProvider
from cyberjury.review.engine import RoleJudgment
from cyberjury.review.paths import repository_files
from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryFinalizeOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    _migrate_role_provenance,
    _parse_candidate,
    finalize_repository_review,
    run_repository_review,
)
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.repository.reviewer import UnitChallenge, UnitReviewer
from cyberjury.review.repository.scaffold import WORKSPACE_MARKER, unit_slug
from cyberjury.review.repository.union import Candidate
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.verification import RefutationCheck, RefutationChecker, Verdict, Verifier
from cyberjury.sources.metadata import SourceError, SourceMeta
from cyberjury.sources.snapshot import SourceSnapshot


class _IndependentChecker(RefutationChecker):
    def holds(self, candidate, refutation, root):
        return RefutationCheck(holds=False, reason="the candidate remains exploitable")


def run_review(target, workspace, **values):
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
        },
    )
    if "verifier" in values and "confirmers" not in values:
        values["confirmers"] = (("independent", _IndependentChecker()),)
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
    return run_repository_review(
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


def finalize_review(target, workspace, **values):
    if "verifier" in values and "confirmers" not in values:
        values["confirmers"] = (("independent", _IndependentChecker()),)
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
    return finalize_repository_review(
        target,
        workspace,
        options=RepositoryFinalizeOptions(verification=verification, output=output),
    )


def mark_workspace(project, target=None):
    source_root = target or project.parent.parent / project.name
    snapshot = SourceSnapshot.capture(source_root, repository_files(source_root))
    marker = project / WORKSPACE_MARKER
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            {
                "project": project.name,
                "profile": "web",
                "source_snapshot_id": snapshot.snapshot_id,
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_legacy_model_provenance_maps_to_every_matching_current_seat():
    legacy = Candidate(title="legacy", file="app.py", line=1, found_by=("shared-model",))
    current = Candidate(title="current", file="app.py", line=2, found_by=("seat-current",))
    roles = RepositoryRoleOptions(
        model="shared-model",
        finder_label="seat-finder",
        challenger_model="other-model",
        challenger_label="seat-challenger",
        judge_model="shared-model",
        judge_label="seat-judge",
    )

    migrated = _migrate_role_provenance([legacy, current], roles)

    assert migrated[0].found_by == ("seat-finder", "seat-judge")
    assert migrated[1] is current


def finalize_workspace(tmp_path):
    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    for name in ("v.py", "s.py", "d.py"):
        (target / "app" / name).write_text("x = 1\n" * 12)
    workspace = tmp_path / "work"
    candidates = workspace / "proj" / "candidates"
    candidates.mkdir(parents=True)
    mark_workspace(workspace / "proj")
    return target, workspace, candidates


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
                line=2,
                severity="HIGH",
            )
        ]


class _ChangingReviewer(_CountingReviewer):
    def review(self, unit, *, shared_context=""):
        findings = super().review(unit, shared_context=shared_context)
        return [replace(findings[0], endpoint=f"GET /wallets/{self.calls}", line=self.calls)]


class _RecordingEmptyReviewer(UnitReviewer):
    def __init__(self):
        self.units = []

    def review(self, unit, *, shared_context=""):
        self.units.append(unit.name)
        return []


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True, reason="candidate remains exploitable")


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


class _PendingJudge(UnitReviewer):
    supports_pending_work = True

    def review(self, unit, *, shared_context=""):
        return []

    def judge(
        self,
        unit,
        finder_findings,
        rebuttals,
        new_findings,
        *,
        shared_context="",
        known=None,
        pending=(),
    ):
        return RoleJudgment(findings=[], pending=[{"reason": "needs runtime evidence"}])


class _ResolvingJudge(UnitReviewer):
    supports_pending_work = True

    def __init__(self):
        self.seen_pending = []

    def review(self, unit, *, shared_context=""):
        return []

    def judge(
        self,
        unit,
        finder_findings,
        rebuttals,
        new_findings,
        *,
        shared_context="",
        known=None,
        pending=(),
    ):
        self.seen_pending.extend(pending)
        return RoleJudgment(
            findings=[],
            resolved_pending=tuple(item["id"] for item in pending),
        )


_FLASK_APP = """
from flask import Flask, request
app = Flask(__name__)

@app.route("/wallets/<wallet_id>", methods=["GET"])
def get_wallet(wallet_id):
    return request.args.get("x", "")

@app.route("/transfers", methods=["POST"])
def create_transfer():
    return "", 201
"""


@pytest.fixture
def custody_repository(tmp_path):
    """A tiny Flask app seeds a stable workspace path for engine tests."""
    d = tmp_path / "custody"
    (d / "app" / "services").mkdir(parents=True)
    (d / "app" / "routes.py").write_text(_FLASK_APP)
    (d / "app" / "services" / "wallet.py").write_text("def get_wallet(wid):\n    return {'id': wid}\n")
    (d / "requirements.txt").write_text("Flask==3.0\n")
    return d


def test_seed_run_units_seeds_split_units_and_prunes_orphan(tmp_path):
    from cyberjury.profiles.registry import default_profile
    from cyberjury.review.repository.context import Unit
    from cyberjury.review.repository.engine import _seed_run_units
    from cyberjury.review.repository.scaffold import unit_slug

    (tmp_path / "units").mkdir()
    (tmp_path / "units" / "foo.md").write_text("# Unit: foo.py\n- Status: open\n", encoding="utf-8")
    units = [
        Unit(name="foo.py#1", root=str(tmp_path), files=("foo.py",)),
        Unit(name="foo.py#2", root=str(tmp_path), files=("foo.py",)),
    ]
    _seed_run_units(tmp_path, units, default_profile().paths)
    got = {p.name for p in (tmp_path / "units").glob("*.md")}
    assert got == {f"{unit_slug('foo.py#1')}.md", f"{unit_slug('foo.py#2')}.md"}


_EMPTY_REPLY = (
    '{"findings": [], "decision_rule_assessments": [], "decision_rule_requests": [], '
    '"evidence_requests": [], "source_queries": []}'
)

_REPLY = (
    '{"findings": [{"title": "wallet idor", "category": "insecure-direct-object-reference", '
    '"decision_rule_id": "idor-object-scope", "symbol": "get_wallet", '
    '"endpoint": "GET /wallets/<wallet_id>", "file": "app/services/wallet.py", "line": 2, '
    '"severity": "HIGH", "attack_path": "request reads another user wallet without ownership", '
    '"evidence": "wallet.py:2 no owner check", "evidence_refs": ["seed"]}], '
    '"decision_rule_assessments": [], "decision_rule_requests": [], "evidence_requests": [], '
    '"source_queries": []}'
)


def _standard_provider(reply: str) -> MockProvider:
    def respond(_system, messages):
        prompt = messages[-1].content
        if "Do not decide whether a vulnerability exists" in prompt:
            return '{"evidence_requests": [], "source_queries": []}'
        if "Requested decision rule details:" in prompt and reply == _REPLY:
            payload = json.loads(_REPLY)
            payload["decision_rule_requests"] = []
            payload["evidence_requests"] = []
            payload["source_queries"] = []
            payload["decision_rule_assessments"] = [
                {
                    "decision_rule_id": "idor-object-scope",
                    "decision": "finding",
                    "reason": "the complete rule and source establish the exploit",
                    "evidence_refs": ["seed"],
                }
            ]
            return json.dumps(payload)
        selected_reply = reply if reply != _REPLY or "app/services/wallet.py" in prompt else _EMPTY_REPLY
        return selected_reply

    return MockProvider(responder=respond)


def test_standard_run_completes_writes_findings_and_marks_units(custody_repository, tmp_path):
    prov = _standard_provider(_REPLY)
    res = run_review(
        custody_repository,
        tmp_path / "ws",
        provider=prov,
        model="mock",
        converge_after=2,
        max_passes=1,
        verify=False,
    )
    ws = res.scaffold.workspace

    assert res.outcome.complete
    assert res.accumulator.converged is False
    assert len(res.accumulator.findings) == 1
    assert res.outcome is not None
    assert res.outcome.complete is True

    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entrypoint"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    assert not list((ws / "findings").glob("*.md"))

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


def test_repository_reviews_raw_source_and_stays_incomplete_when_facts_are_limited(tmp_path):
    target = tmp_path / "opaque"
    target.mkdir()
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef broken(:\n")
    (target / "requirements.txt").write_text("Flask==3.0\n")
    reviewer = _RecordingEmptyReviewer()

    result = run_review(
        target,
        tmp_path / "ws",
        reviewer=reviewer,
        max_passes=1,
        verify=False,
    )

    assert reviewer.units
    assert result.outcome.errors == 0
    assert result.outcome.complete is False
    assert result.outcome.grounding.limitations
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["state"] == "incomplete"
    assert status["complete"] is False
    assert status["facts_limitations"] == 1
    gate = check_gate(result.scaffold.workspace, root=target)
    assert gate.passed is False
    assert any("incomplete review" in failure for failure in gate.failures)
    assert result.outcome_artifact.limitations == 1

    resumed_reviewer = _RecordingEmptyReviewer()
    resumed = run_review(
        target,
        tmp_path / "ws",
        reviewer=resumed_reviewer,
        max_passes=1,
        verify=False,
    )

    assert resumed_reviewer.units == []
    assert resumed.outcome.complete is False
    assert resumed.outcome.grounding.limitations == result.outcome.grounding.limitations


def test_finalize_preserves_persisted_facts_limitations(tmp_path):
    target, workspace, _candidates = finalize_workspace(tmp_path)
    project = workspace / target.name
    (project / "_facts_limitations.json").write_text(
        json.dumps(
            [
                {
                    "source": "app/v.py",
                    "analyzer": "python",
                    "reason": "unparsable",
                    "line": 1,
                    "column": 1,
                }
            ]
        ),
        encoding="utf-8",
    )

    result = finalize_review(target, workspace, verify=False)

    assert result.outcome.complete is False
    assert result.outcome.grounding.limitations == ("facts:app/v.py:1:1",)
    assert result.outcome_artifact.complete is False
    assert result.outcome_artifact.limitations == 1


def test_run_writes_pocs_when_a_backend_is_bound(custody_repository, tmp_path):

    class WritePoC:
        executes = False
        ext = "py"

        def available(self):
            return False

        def generate(self, **kw):
            return type("Artifact", (), {"source": "import requests\n", "run_hint": "python poc.py", "note": ""})()

    res = run_review(
        custody_repository,
        tmp_path / "ws",
        provider=_standard_provider(_REPLY),
        model="mock",
        verify=False,
        converge_after=2,
        max_passes=1,
        poc_backend=WritePoC(),
    )
    pocs = sorted((res.scaffold.workspace / "pocs").glob("*.py"))
    assert len(pocs) == 1
    assert "import requests" in pocs[0].read_text()
    finding = json.loads((res.scaffold.workspace / "findings.json").read_text())["findings"][0]
    assert "PoC written, run it manually" in finding["evidence"]


def test_run_fails_loud_on_zero_units(tmp_path):
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no candidate entrypoints"):
        run_review(repository, tmp_path / "ws", reviewer=_RecordingEmptyReviewer(), verify=False)


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


def test_resume_skips_reviewed_units_and_verified_findings(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    r1v = _CountingVerifier()
    run_review(custody_repository, ws, reviewer=_CountingReviewer(), verifier=r1v, converge_after=1, max_passes=1)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1
    assert r1v.calls >= 1

    r2 = _CountingReviewer()
    r2v = _CountingVerifier()
    run_review(custody_repository, ws, reviewer=r2, verifier=r2v, converge_after=1, max_passes=1, fresh=False)
    assert r2.calls == 0
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert {f["entrypoint"] for f in findings_after_2} == {f["entrypoint"] for f in findings_after_1}


def test_completed_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    run_review(
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
        run_review(
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
        "converge_after": 2,
        "min_rounds": 1,
        "max_passes": 2,
        "concurrency": 1,
    }
    first_reviewer = _ChangingReviewer()

    first = run_review(custody_repository, ws, reviewer=first_reviewer, **shared)
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
    second = run_review(custody_repository, ws, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls > 0
    assert second.outcome.complete is True
    assert second.accumulator.converged is True
    assert {candidate.key() for candidate in second.accumulator.findings}.issuperset(first_finding_keys)
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
        "max_passes": 2,
        "concurrency": 1,
    }
    first = run_review(custody_repository, workspace, reviewer=_ChangingReviewer(), **shared)
    assert first.outcome.complete is False
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _CountingReviewer()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        run_review(custody_repository, workspace, reviewer=resumed, **shared)

    assert resumed.calls == 0


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=1,
    )
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match=r"no _union\.json"):
        run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=1,
            fresh=False,
        )


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
    res = run_review(
        repository, ws, reviewer=_RaisingReviewer("beta/routes.py"), verify=False, converge_after=1, max_passes=1
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
    result = run_review(
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


def test_recovered_failure_closes_within_the_same_run(tmp_path):
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
    first = run_review(repository, workspace, reviewer=first_reviewer, **shared)
    project = first.scaffold.workspace

    assert first.accumulator.converged is True
    assert first.outcome.complete is True
    assert first.accumulator.failed_units == set()
    assert first.outcome.recovered_failures[0].paths == ("beta/routes.py",)
    units = {unit.stem: unit.read_text() for unit in (project / "units").glob("*.md")}
    assert "Status: reviewed" in units[unit_slug("alpha/routes.py")]
    assert "Status: reviewed" in units[unit_slug("beta/routes.py")]

    second_reviewer = _CountingReviewer()
    second = run_review(repository, workspace, reviewer=second_reviewer, **shared)

    assert second_reviewer.calls == 0
    assert second.outcome.complete is True
    assert all("Status: reviewed" in unit.read_text() for unit in (project / "units").glob("*.md"))


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    run_review(
        custody_repository,
        ws,
        reviewer=_CountingReviewer(),
        verifier=_CountingVerifier(),
        converge_after=1,
        max_passes=1,
    )
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        run_review(
            custody_repository,
            ws,
            reviewer=_CountingReviewer(),
            verifier=_CountingVerifier(),
            converge_after=1,
            max_passes=1,
            fresh=False,
        )
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_finalize_raises_loud(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (ws / "proj" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    class _V(Verifier):
        def verify(self, c, root):
            return Verdict(real=True)

    with pytest.raises(ValueError, match="corrupt"):
        finalize_review(target, ws, verifier=_V(), concurrency=1)


def test_finalize_rejects_source_changed_after_scaffold_revision(tmp_path):
    from cyberjury.detection import load_detection
    from cyberjury.profiles.registry import default_profile
    from cyberjury.review.paths import repository_files
    from cyberjury.sources.snapshot import SourceSnapshot

    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:1\n"
    )
    profile = default_profile()
    detection = load_detection(profile.paths.detection_file)
    snapshot = SourceSnapshot.capture(
        target,
        repository_files(target, detection),
    )
    marker = ws / "proj" / WORKSPACE_MARKER
    identity = json.loads(marker.read_text(encoding="utf-8"))
    identity["source_snapshot_id"] = snapshot.snapshot_id
    marker.write_text(json.dumps(identity), encoding="utf-8")
    (target / "app" / "v.py").write_text("x = 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="source changed after the workspace evidence revision"):
        finalize_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)


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
        ws,
        findings,
        root=str(tmp_path),
        verifier=_Boom(),
        confirmers=[("independent", _IndependentChecker())],
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    assert [c.title for c in confirmed] == ["boom"]
    assert vr.errors >= 1
    assert json.loads((ws / "_verified.json").read_text()) == {"schema": 3, "candidates": {}}
    assert [c.title for c in vr.incomplete] == ["boom"]
    assert vr.error_details == ["RuntimeError: rate limited"]


def test_incomplete_checkpoint_can_never_be_loaded_as_a_refutation(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    checkpoint = {
        "schema": 3,
        "candidates": {
            "verify-v4-tampered": {
                "real": False,
                "reason": "failed",
                "record": {
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
                },
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
            provider=None,
            model="m",
            votes=1,
            concurrency=1,
            fresh=False,
        )


def test_legacy_checkpoint_is_reverified_under_the_current_contract(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    (ws / "_verified.json").write_text(
        json.dumps({"schema": 2, "candidates": {"legacy": {"untrusted": True}}}),
        encoding="utf-8",
    )
    verifier = _CountingVerifier()

    kept, result = apply_verification(
        ws,
        [Candidate(title="candidate", file="a.py", line=1)],
        root=str(tmp_path),
        verifier=verifier,
        confirmers=[("independent", _IndependentChecker())],
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=False,
    )

    assert verifier.calls == 1
    assert kept == result.verified
    assert json.loads((ws / "_verified.json").read_text())["schema"] == 3


def test_changed_candidate_content_does_not_reuse_a_refutation_checkpoint(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

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
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=True,
    )
    _kept, cached_result = apply_verification(
        ws,
        [original],
        root=str(tmp_path),
        verifier=refuter,
        confirmers=[("checker", Uphold())],
        provider=None,
        model="m",
        votes=1,
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
        provider=None,
        model="m",
        votes=1,
        concurrency=1,
        fresh=False,
    )

    assert refuter.calls == 2
    assert kept == [changed]
    assert result.refuted == []


def test_repository_outcome_and_status_preserve_verification_failure_reason(custody_repository, tmp_path):

    class _Boom(Verifier):
        def verify(self, candidate, root):
            raise RuntimeError("rate limited")

    result = run_review(
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
    assert "coverage_analysis_errors" not in status
    assert "coverage_suggestions" not in status


def test_finalize_dedups_verifies_and_reports(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
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
            return Verdict(
                real=not bad,
                reason="lock holds on prod" if bad else "candidate remains exploitable",
                control_file=c.file if bad else "",
                control_line=c.line if bad else None,
            )

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            holds = "/r" in c.endpoint
            return RefutationCheck(holds=holds, reason="lock covers route" if holds else "different route")

    fr = finalize_review(target, ws, verifier=_V(), confirmers=[("independent", _C())], concurrency=1)
    assert fr.parsed == 4
    assert fr.deduped == 3
    assert len(fr.verify.retained) == 2
    assert len(fr.verify.refuted) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    entries = {f["entrypoint"] for f in data["findings"]}
    assert any("/x/" in e for e in entries)
    assert any("/t" in e for e in entries)
    assert not any("/r" in e for e in entries)


def test_finalize_removes_the_retired_coverage_suggestions_artifact(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    legacy = ws / "proj" / "_coverage_suggestions.md"
    legacy.write_text("stale model suggestion\n", encoding="utf-8")

    finalize_review(target, ws, verify=False)

    assert not legacy.exists()


def test_finalize_preserves_verification_failure_reason(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "a.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )

    class BrokenVerifier(Verifier):
        def verify(self, candidate, root):
            raise RuntimeError("rate limited")

    result = finalize_review(target, ws, verifier=BrokenVerifier(), concurrency=1)

    assert result.outcome.degraded is True
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"


def test_finalize_records_its_completeness_and_spend_so_a_later_gate_can_read_them(tmp_path):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter

    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (candidates / "b.md").write_text(
        "# race fp\n- Risk: HIGH\n- Type: race\n- Source: `POST /r`\n## Analysis\napp/d.py:3\n"
    )

    class _V(Verifier):
        def verify(self, c, root):
            bad = "/r" in c.endpoint
            return Verdict(
                real=not bad,
                reason="lock holds on prod" if bad else "candidate remains exploitable",
                control_file=c.file if bad else "",
                control_line=c.line if bad else None,
            )

    class _C(RefutationChecker):
        def holds(self, c, reason, root):
            holds = "/r" in c.endpoint
            return RefutationCheck(holds=holds, reason="lock covers route" if holds else "different route")

    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=_EMPTY_REPLY), meter)
    fr = finalize_review(
        target,
        ws,
        verifier=_V(),
        confirmers=[("independent", _C())],
        concurrency=1,
        provider=provider,
        meter=meter,
    )
    assert fr.parsed == 2
    assert fr.deduped == 2
    assert len(fr.verify.retained) == 1
    assert len(fr.verify.verified) == 1
    assert len(fr.verify.refuted) == 1
    assert fr.verify.errors == 0
    assert fr.outcome_artifact.complete is True
    assert meter.snapshot()["model_requests"] == 0


def test_finalize_does_not_write_a_redundant_status_projection(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    legacy = ws / target.name / "_finalize.json"
    legacy.write_text('{"complete":true}')
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    fr = finalize_review(target, ws, verify=False)
    assert fr.outcome_artifact.complete is True
    assert not legacy.exists()


def test_finalize_requires_a_scaffolded_workspace(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"

    with pytest.raises(ValueError, match="Run --scaffold or --run"):
        finalize_review(target, ws, verify=False)


def test_finalize_falls_back_to_the_union_when_no_workspace_candidates(tmp_path):
    from cyberjury.review.repository.engine import _save_union

    target = tmp_path / "proj"
    (target / "app").mkdir(parents=True)
    (target / "app" / "v.py").write_text("def read():\n    return 1\n")
    ws = tmp_path / "work"
    project = ws / "proj"
    (project / "candidates").mkdir(parents=True)
    mark_workspace(project)
    _save_union(project, [Candidate(title="idor read", category="idor", file="app/v.py", line=10)])

    fr = finalize_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    assert fr.parsed == 1
    assert len(fr.verify.retained) == 1
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1


def test_union_checkpoint_preserves_identity_attack_path_and_evidence_receipts(tmp_path):
    from cyberjury.review.repository.engine import _load_union_checkpoint, _save_union

    candidate = Candidate(
        title="account export lacks authorization",
        category="missing-authorization",
        decision_rule_id="missing-authorization-action",
        source_operation_id="call-account-export",
        file="app/v.py",
        line=10,
        attack_path="request reaches unguarded account export",
        evidence="app/v.py:10 has no ownership check",
        evidence_refs=("seed", "src-control"),
    )

    _save_union(
        tmp_path,
        [candidate],
        severity_votes={candidate.key(): ["LOW", "HIGH", "CRITICAL"]},
    )
    checkpoint = _load_union_checkpoint(tmp_path)
    restored = list(checkpoint.pool.values())

    assert restored == [candidate]
    assert restored[0].candidate_id == candidate.candidate_id
    assert restored[0].decision_rule_id == candidate.decision_rule_id
    assert restored[0].source_operation_id == candidate.source_operation_id
    assert restored[0].attack_path == candidate.attack_path
    assert restored[0].evidence_refs == candidate.evidence_refs
    assert checkpoint.severity_votes[candidate.key()] == ["LOW", "HIGH", "CRITICAL"]


class _AllReal(Verifier):
    def verify(self, c, root):
        return Verdict(real=True, reason="")


def _seed_one_candidate(target, ws):
    (target / "app").mkdir(exist_ok=True)
    (target / "app" / "v.py").write_text("x = 1\n" * 12)
    candidates = ws / target.name / "candidates"
    candidates.mkdir(parents=True)
    mark_workspace(ws / target.name)
    (candidates / "a.md").write_text(
        "# idor read\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )


def test_finalize_adds_target_metadata_without_changing_findings(tmp_path):
    meta = SourceMeta(
        source="bscscan",
        chain="bsc",
        chain_id=56,
        address="0x" + "ab" * 20,
        source_url="https://bscscan.com/address/x#code",
        contract_name="Token",
        optimization_used=False,
        proxy=False,
    )

    plain_t = tmp_path / "plain"
    plain_t.mkdir()
    plain_ws = tmp_path / "plain_ws"
    _seed_one_candidate(plain_t, plain_ws)
    plain = finalize_review(plain_t, plain_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    plain_report = json.loads((plain.workspace / "findings.json").read_text())

    meta_t = tmp_path / "meta"
    meta_t.mkdir()
    (meta_t / "cyberjury-source.json").write_text(meta.to_json())
    meta_ws = tmp_path / "meta_ws"
    _seed_one_candidate(meta_t, meta_ws)
    withmeta = finalize_review(meta_t, meta_ws, verifier=_AllReal(), confirmers=[], concurrency=1)
    meta_report = json.loads((withmeta.workspace / "findings.json").read_text())

    assert meta_report["findings"] == plain_report["findings"]
    assert plain_report["target"] is None
    assert meta_report["target"]["chain"] == "bsc"
    assert not (withmeta.workspace / "_target.md").exists()
    assert not (plain.workspace / "_target.md").exists()


def test_finalize_fails_loud_on_malformed_source_metadata(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    (target / "cyberjury-source.json").write_text("{not valid json")
    ws = tmp_path / "work"
    _seed_one_candidate(target, ws)
    with pytest.raises(SourceError, match="malformed"):
        finalize_review(target, ws, verifier=_AllReal(), confirmers=[], concurrency=1)


def test_multi_source_finding_still_runs_verification(tmp_path):
    from cyberjury.review.repository.verify import apply_verification

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
    assert json.loads((ws / "_verified.json").read_text()) == {"schema": 3, "candidates": {}}


def test_finalize_drops_issue_with_no_file_location(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "noloc.md").write_text(
        "# missing location\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n"
        "## Analysis\nno concrete location was cited.\n"
    )
    fr = finalize_review(target, ws, verify=False)
    assert fr.parsed == 0
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert data["findings"] == []


def test_finalize_preserves_blocked_status(tmp_path):
    target, ws, candidates = finalize_workspace(tmp_path)
    (candidates / "blocked.md").write_text(
        "# needs poc\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n- Status: blocked\n"
        "## Analysis\napp/s.py:5 no nonce, a PoC needs credentials.\n"
    )
    fr = finalize_review(target, ws, verify=False)
    data = json.loads((fr.workspace / "findings.json").read_text())
    assert len(data["findings"]) == 1
    assert data["findings"][0]["status"] == "blocked"
    assert fr.outcome.complete is False
    assert fr.outcome_artifact.incomplete == 1


def test_write_findings_replaces_json_and_never_touches_candidates(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    (ws / "candidates").mkdir(parents=True)
    (ws / "findings").mkdir()
    legacy = ws / "findings" / "old.md"
    legacy.write_text("stale report")
    agent = ws / "candidates" / "agent-note.md"
    agent.write_text("# hand written\n- Risk: HIGH\n## Analysis\napp/x.py:1\n")

    two = [
        Candidate(title="A", endpoint="GET /a", file="a.py", line=1, severity="HIGH"),
        Candidate(title="B", endpoint="GET /b", file="b.py", line=2, severity="HIGH"),
    ]
    _write_findings(ws, two)
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 2
    assert not legacy.exists()

    _write_findings(ws, two[:1])
    assert agent.read_text().startswith("# hand written")
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 1


def test_write_findings_keeps_two_findings_that_share_an_endpoint(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    two = [
        Candidate(title="missing binding", category="idor", endpoint="POST /x", file="x.py", line=1),
        Candidate(title="token race", category="race-condition", endpoint="POST /x", file="x.py", line=2),
    ]
    _write_findings(ws, two)
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 2


def test_write_findings_dedupes_near_repeat_evidence_only_in_outputs(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    evidence = (
        "## Analysis\n"
        "main.py uses allow_origins star with allow_credentials true, so any attacker origin can read "
        "credentialed browser responses from the API.\n\n"
        "main.py configures allow_origins star with allow_credentials true, so an attacker origin can read "
        "credentialed browser responses from the API.\n\n"
        "The exploit is a browser request from evil.example with the victim session attached."
    )
    finding = Candidate(
        title="cors",
        category="cors-misconfiguration",
        file="main.py",
        line=10,
        severity="HIGH",
        evidence=evidence,
    )

    _write_findings(ws, [finding])

    report = json.loads((ws / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert report["evidence"].count("credentialed browser responses") == 1
    assert "evil.example" in report["evidence"]
    assert finding.evidence == evidence


def test_finalize_finding_carries_agent_analysis_not_a_filename(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    mark_workspace(proj)
    (proj / "candidates" / "key-leak.md").write_text(
        "# Hardcoded key gates the webhook lane\n"
        "- Risk: HIGH\n- Type: hardcoded-secrets\n- Source: `@auth0()`\n- Status: confirmed\n\n"
        "## Analysis\n`settings/08.py:11` ships a literal AUTH0_AUTH_KEY, no prod override.\n\n"
        "## Attack Path\nRead the repository, replay the Basic header.\n\n"
        "## Fix\nLoad the key from the environment.\n"
    )

    finalize_repository_review(
        target,
        ws,
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(enabled=False),
        ),
    )
    data = json.loads((proj / "findings.json").read_text())
    assert "candidate" not in data["findings"][0]
    assert "ships a literal AUTH0_AUTH_KEY" in data["findings"][0]["evidence"]
    assert "## Attack Path" in data["findings"][0]["evidence"]
    assert "## Fix" in data["findings"][0]["evidence"]
    assert "key-leak.md" not in data["findings"][0]["evidence"]


def test_candidate_key_respects_by_file_for_cross_file_findings():
    from cyberjury.review.repository.union import Candidate
    from cyberjury.review.repository.verify import candidate_key

    a = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="A.sol")
    b = Candidate(title="t", category="reentrancy", endpoint="withdraw", file="B.sol")
    assert candidate_key(a, True) != candidate_key(b, True)
    assert candidate_key(a, False) == candidate_key(b, False)


def test_poc_for_matches_a_multi_suffix_extension(tmp_path):
    from cyberjury.review.repository.engine import _poc_for

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    (ws / "pocs" / "oracle-setter.t.sol").write_text("contract T {}")
    (ws / "pocs" / "idor.py").write_text("x = 1\n")
    assert _poc_for(ws, "oracle-setter") == "pocs/oracle-setter.t.sol"
    assert _poc_for(ws, "idor") == "pocs/idor.py"
    assert _poc_for(ws, "missing") == ""
    assert _poc_for(ws, "oracle") == ""


def test_finalize_links_pocs_and_reconciles(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    ws = tmp_path / "work"
    proj = ws / "proj"
    (proj / "candidates").mkdir(parents=True)
    (proj / "pocs").mkdir(parents=True)
    mark_workspace(proj)
    (proj / "candidates" / "x.md").write_text(
        "# idor\n- Risk: HIGH\n- Type: idor\n- Source: `GET /x/<id>`\n## Analysis\napp/v.py:10\n"
    )
    (proj / "candidates" / "y.md").write_text(
        "# replay\n- Risk: HIGH\n- Type: replay\n- Source: `POST /t`\n## Analysis\napp/s.py:5\n"
    )
    (proj / "pocs" / "x.t.sol").write_text("contract T {}\n")
    (proj / "pocs" / "z.sh").write_text("#!/bin/sh\necho orphan\n")

    finalize_repository_review(
        target,
        ws,
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(enabled=False),
        ),
    )
    data = json.loads((proj / "findings.json").read_text())
    findings_by_entry = {f["entrypoint"]: f for f in data["findings"]}
    assert "poc" not in findings_by_entry["GET /x/<id>"]
    assert "candidate" not in findings_by_entry["GET /x/<id>"]

    report = (proj / "_pocs.md").read_text()
    assert "POST /t" in report
    assert "pocs/z.sh" in report
    assert "GET /x" not in report


def test_run_pocs_writes_the_poc_annotates_and_never_drops(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [
        Candidate(
            title="oracle",
            category="access-control",
            file="O.sol",
            line=5,
            symbol="setX",
            evidence="unprotected setter",
        )
    ]

    class FakeBackend:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

        def reproduce(self, **kw):
            return SimpleNamespace(reproduced=True, test_source="contract T {}", detail="passed")

    out = _run_pocs(ws, findings, FakeBackend(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "PoC reproduced" in out[0].evidence


def test_run_pocs_fails_loud_when_the_backend_errors(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1)]

    class Erroring:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

        def reproduce(self, **kw):
            raise RuntimeError("model down")

    with pytest.raises(RuntimeError, match="PoC generation or execution failed"):
        _run_pocs(ws, findings, Erroring(), root=str(tmp_path))


def test_run_pocs_rejects_an_executing_backend_without_reproduction(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    class InvalidBackend:
        executes = True
        ext = "t.sol"
        install_hint = ""

        def available(self):
            return True

    with pytest.raises(TypeError, match="must implement reproduce"):
        _run_pocs(tmp_path, [], InvalidBackend(), root=str(tmp_path))


def test_run_pocs_degrades_to_write_only_when_an_executing_toolchain_is_absent(tmp_path):
    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="x", category="idor", file="A.sol", line=1, symbol="f", evidence="unchecked")]

    class Unavailable:
        executes = True
        ext = "t.sol"
        install_hint = "install the toolchain from https://example.test"

        def available(self):
            return False

        def reproduce(self, **kw):
            raise AssertionError("must not run when the toolchain is absent")

        def generate(self, **kw):
            return PoCArtifact(source="contract T {}", run_hint="forge test")

    out = _run_pocs(ws, findings, Unavailable(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.t.sol").read_text() == "contract T {}"
    assert "not run" in out[0].evidence
    assert "install the toolchain from https://example.test" in out[0].evidence


def test_run_pocs_writes_only_for_a_backend_that_does_not_execute(tmp_path):
    from cyberjury.review.repository.engine import _finding_name, _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [
        Candidate(title="idor", category="idor", file="views.py", line=3, symbol="get_order", evidence="no owner check")
    ]

    class WriteOnly:
        executes = False
        ext = "py"
        install_hint = ""

        def available(self):
            return False

        def generate(self, **kw):
            return PoCArtifact(source="import requests\n", run_hint="python it")

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert len(out) == 1
    assert (ws / "pocs" / f"{_finding_name(findings[0])}.py").read_text() == "import requests\n"
    assert "run it manually" in out[0].evidence


def test_run_pocs_folds_a_writer_side_note_into_the_evidence(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    findings = [Candidate(title="idor", category="idor", file="v.py", line=3, symbol="g", evidence="no owner check")]

    class WriteOnly:
        executes = False
        ext = "py"
        install_hint = ""

        def available(self):
            return False

        def generate(self, **kw):
            return PoCArtifact(
                source="def broken(:",
                run_hint="python it",
                note="PoC does not parse as Python: invalid syntax",
            )

    out = _run_pocs(ws, findings, WriteOnly(), root=str(tmp_path))
    assert "does not parse" in out[0].evidence
    assert len(out) == 1


def test_execute_present_pocs_runs_an_agent_written_poc(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle", category="access-control", file="O.sol", line=5, symbol="setX", evidence="unprotected setter"
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    class Runner:
        executes = True
        ext = "t.sol"

        def execute(self, *, source, root):
            return SimpleNamespace(ran=True, ok=True, detail="passed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert "PoC reproduced" in out[0].evidence


def test_execute_present_pocs_leaves_a_web_profile_to_reconciliation(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(title="idor", category="idor", file="v.py", line=1, symbol="g", evidence="x")
    (ws / "pocs" / f"{_finding_name(c)}.py").write_text("import requests\n")

    class WebRunner:
        executes = False
        ext = "py"

    profile = SimpleNamespace(poc_backend=lambda: WebRunner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert out[0].evidence == "x"


def test_execute_present_pocs_does_not_run_a_finding_the_write_step_already_ran(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle",
        category="access-control",
        file="O.sol",
        line=5,
        symbol="setX",
        evidence="setter\n\n[PoC reproduced: passed]",
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    ran: list[str] = []

    class Runner:
        executes = True
        ext = "t.sol"

        def execute(self, *, source, root):
            ran.append(source)
            return SimpleNamespace(ran=True, ok=True, detail="passed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    out = _execute_present_pocs(ws, [c], profile, root=str(tmp_path))
    assert ran == []
    assert out[0].evidence.count("[PoC") == 1


def test_execute_present_pocs_fails_loud_on_runner_errors(tmp_path):
    from types import SimpleNamespace

    from cyberjury.review.repository.engine import _execute_present_pocs, _finding_name

    ws = tmp_path / "proj"
    (ws / "pocs").mkdir(parents=True)
    c = Candidate(
        title="oracle", category="access-control", file="O.sol", line=5, symbol="setX", evidence="unprotected setter"
    )
    (ws / "pocs" / f"{_finding_name(c)}.t.sol").write_text("contract T {}")

    class Runner:
        executes = True

        def execute(self, *, source, root):
            raise RuntimeError("forge failed")

    profile = SimpleNamespace(poc_backend=lambda: Runner())
    with pytest.raises(RuntimeError, match="PoC execution failed"):
        _execute_present_pocs(ws, [c], profile, root=str(tmp_path))


def _options(provider, *, execution=None, meter=None):
    return RepositoryRunOptions(
        roles=RepositoryRoleOptions(
            provider=provider,
            model="mock",
        ),
        verification=RepositoryVerificationOptions(enabled=False),
        execution=execution or RepositoryExecutionOptions(),
        lifecycle=RepositoryLifecycleOptions(),
        output=RepositoryOutputOptions(meter=meter),
    )


def test_run_writes_timing_and_state_to_run_json(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    (repo / "b.py").write_text("def other():\n    return 1\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = _standard_provider(_EMPTY_REPLY)
    run_repository_review(str(repo), str(ws), options=_options(provider))
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["state"] == "complete"
    timing = run["timing"]
    assert isinstance(timing["total_seconds"], (int, float))
    assert timing["per_pass"]
    assert all("seconds" in p for p in timing["per_pass"])
    names = [u["unit"] for u in timing["unit_seconds"]]
    assert names
    assert len(names) == len(set(names))
    assert set(names) <= {"a.py", "b.py", "relationships:combined"}


def test_standard_run_status_distinguishes_completion_from_convergence(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = _standard_provider(_EMPTY_REPLY)
    run_repository_review(
        str(repo),
        str(ws),
        options=_options(
            provider,
            execution=RepositoryExecutionOptions(max_passes=1, min_rounds=1),
        ),
    )
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["complete"] is True
    assert run["converged"] is False
    assert run["state"] == "complete"


def test_repository_resume_rejects_a_mode_change_without_fresh(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    run_review(
        custody_repository,
        workspace,
        reviewer=_RecordingEmptyReviewer(),
        verify=False,
        max_passes=1,
        min_rounds=1,
    )

    with pytest.raises(ValueError, match=r"review policy changed.*--fresh"):
        run_review(
            custody_repository,
            workspace,
            mode="adversarial",
            reviewer=_RecordingEmptyReviewer(),
            challenger_reviewer=_EmptyChallenger(),
            judge_reviewer=_PassingJudge(),
            verify=False,
            max_passes=2,
            min_rounds=1,
            converge_after=2,
        )


def test_completed_repository_resume_restores_the_prior_outcome(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    first = run_review(
        custody_repository,
        workspace,
        reviewer=_RecordingEmptyReviewer(),
        verify=False,
        max_passes=1,
        min_rounds=1,
    )
    second = run_review(
        custody_repository,
        workspace,
        reviewer=_RecordingEmptyReviewer(),
        verify=False,
        max_passes=1,
        min_rounds=1,
    )

    assert first.outcome.complete is True
    assert second.outcome.complete is True
    assert second.outcome.rounds == first.outcome.rounds == 1
    assert second.outcome.converged is first.outcome.converged is False


def test_repository_resume_retries_verification_without_reexecuting_reviewed_units(custody_repository, tmp_path):
    class SwitchingVerifier(Verifier):
        fail = True

        def verify(self, candidate, root):
            if self.fail:
                raise RuntimeError("temporary verification failure")
            return Verdict(real=True, reason="candidate remains exploitable")

    workspace = tmp_path / "ws"
    verifier = SwitchingVerifier()
    first_reviewer = _CountingReviewer()
    first = run_review(
        custody_repository,
        workspace,
        reviewer=first_reviewer,
        verifier=verifier,
        max_passes=1,
        min_rounds=1,
    )
    assert first.outcome.complete is False
    assert first_reviewer.calls > 0

    verifier.fail = False
    second_reviewer = _CountingReviewer()
    second = run_review(
        custody_repository,
        workspace,
        reviewer=second_reviewer,
        verifier=verifier,
        max_passes=1,
        min_rounds=1,
    )

    assert second_reviewer.calls == 0
    assert second.outcome.complete is True
    assert second.outcome.scheduling is not None
    assert second.outcome.scheduling.stop_reason == "no_open_units"


def test_completed_repository_resume_rejects_contradictory_status(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    first = run_review(
        custody_repository,
        workspace,
        reviewer=_RecordingEmptyReviewer(),
        verify=False,
        max_passes=1,
        min_rounds=1,
    )
    status_path = first.scaffold.workspace / "_run.json"
    status = json.loads(status_path.read_text())
    status["requires_convergence"] = True
    status["converged"] = True
    status_path.write_text(json.dumps(status))

    with pytest.raises(ValueError, match="content hash does not match"):
        run_review(
            custody_repository,
            workspace,
            reviewer=_RecordingEmptyReviewer(),
            verify=False,
            max_passes=1,
            min_rounds=1,
        )


def test_completed_repository_resume_rejects_hidden_errors(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    first = run_review(
        custody_repository,
        workspace,
        reviewer=_RecordingEmptyReviewer(),
        verify=False,
        max_passes=1,
        min_rounds=1,
    )
    status_path = first.scaffold.workspace / "_run.json"
    status = json.loads(status_path.read_text())
    status["errors"] = 1
    status_path.write_text(json.dumps(status))

    with pytest.raises(ValueError, match="content hash does not match"):
        run_review(
            custody_repository,
            workspace,
            reviewer=_RecordingEmptyReviewer(),
            verify=False,
            max_passes=1,
            min_rounds=1,
        )


def test_repository_resume_rejects_a_convergence_policy_change(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    common = {
        "mode": "adversarial",
        "reviewer": _RecordingEmptyReviewer(),
        "challenger_reviewer": _EmptyChallenger(),
        "judge_reviewer": _PassingJudge(),
        "verify": False,
        "min_rounds": 1,
    }
    run_review(custody_repository, workspace, converge_after=1, max_passes=1, **common)

    with pytest.raises(ValueError, match=r"review policy changed.*--fresh"):
        run_review(custody_repository, workspace, converge_after=2, max_passes=2, **common)


def test_repository_resume_preserves_pending_until_the_judge_resolves_it(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    common = {
        "mode": "adversarial",
        "reviewer": _RecordingEmptyReviewer(),
        "challenger_reviewer": _EmptyChallenger(),
        "verify": False,
        "min_rounds": 1,
        "converge_after": 1,
        "max_passes": 1,
        "concurrency": 1,
    }
    first = run_review(custody_repository, workspace, judge_reviewer=_PendingJudge(), **common)
    first_status = json.loads((first.scaffold.workspace / "_run.json").read_text())

    assert first.outcome.complete is False
    assert first.outcome.pending
    assert first_status["pending"] == list(first.outcome.pending)

    resolver = _ResolvingJudge()
    second = run_review(custody_repository, workspace, judge_reviewer=resolver, **common)
    second_status = json.loads((second.scaffold.workspace / "_run.json").read_text())

    assert resolver.seen_pending
    assert second.outcome.pending == ()
    assert second.outcome.complete is True
    assert second_status["pending"] == []
    assert second_status["complete"] is True


def test_repository_writes_running_state_before_the_first_unit(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "target")
    workspace = tmp_path / "ws"
    status_path = workspace / "target" / "_run.json"
    snapshots = []

    class ObserveRunning(UnitReviewer):
        def review(self, unit, *, shared_context=""):
            snapshots.append(json.loads(status_path.read_text()))
            return []

    run_review(
        repository,
        workspace,
        reviewer=ObserveRunning(),
        verify=False,
        max_passes=1,
        min_rounds=1,
        concurrency=1,
    )

    assert snapshots
    assert all(snapshot["state"] == "running" for snapshot in snapshots)
    assert all(snapshot["complete"] is False for snapshot in snapshots)


def _run_with_meter(tmp_path):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    meter = UsageMeter()
    provider = MeteringProvider(_standard_provider(_EMPTY_REPLY), meter)
    run_repository_review(
        str(repo),
        str(ws),
        options=_options(provider, meter=meter),
    )
    return json.loads((ws / "svc" / "_run.json").read_text()), meter


def test_run_writes_its_spend_to_run_json_so_cost_survives_uncaptured_stderr(tmp_path):
    run, meter = _run_with_meter(tmp_path)
    usage = run["usage"]
    assert usage["model_requests"] == meter.model_requests
    components = usage["uncached_input_tokens"] + usage["cache_read_tokens"] + usage["cache_write_tokens"]
    assert usage["total_input_tokens"] == components
    assert usage["unit_review_calls"] >= run["units_reviewed"]
    assert run["model_calls"]
    call = run["model_calls"][0]
    assert call["role"] == "finder"
    assert call["unit_id"]
    assert call["evidence_revision"].startswith("revision-")
    assert call["prompt_chars"] > 0
    assert call["duration_seconds"] >= 0
    assert call["parse_source"] == "direct"
    assert call["status"] == "ok"


def test_each_pass_records_its_own_spend_so_an_expensive_pass_can_be_named(tmp_path):
    run, _ = _run_with_meter(tmp_path)
    per_pass = run["timing"]["per_pass"]
    assert all("usage" in p for p in per_pass)
    assert sum(p["usage"]["model_requests"] for p in per_pass) == run["usage"]["model_requests"]


def test_a_run_without_a_meter_writes_no_usage_rather_than_zeros(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    provider = _standard_provider(_EMPTY_REPLY)
    run_repository_review(str(repo), str(ws), options=_options(provider))
    assert "usage" not in json.loads((ws / "svc" / "_run.json").read_text())
