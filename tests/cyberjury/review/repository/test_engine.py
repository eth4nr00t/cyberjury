"""Repository engine tests cover its complete persistent lifecycle."""

import json

import pytest

from cyberjury.profiles.base import PoCArtifact
from cyberjury.providers.mock import MockProvider
from cyberjury.review.repository.engine import (
    RepositoryExecutionOptions,
    RepositoryLifecycleOptions,
    RepositoryOutputOptions,
    RepositoryRoleOptions,
    RepositoryRunOptions,
    RepositoryVerificationOptions,
    _finding_record,
    run_repository_review,
)
from cyberjury.review.repository.gate import check_gate
from cyberjury.review.repository.union import Candidate
from cyberjury.review.verification import Verdict, Verifier
from cyberjury.sources.snapshot import SourceSnapshot
from tests.cyberjury.review.repository.support import (
    EMPTY_REPLY,
    finder_reply,
    finding,
    prompt_unit,
    run_review,
    unit_provider,
)


def test_repository_report_keeps_the_model_evidence_text():
    evidence = "The handler reads account A; the check covers only account B; the handler reads account A."
    candidate = Candidate(title="missing resource authorization", file="app.py", line=1, evidence=f"  {evidence}\n")

    record = _finding_record(candidate)

    assert record.evidence == evidence


def test_repository_review_accepts_an_unlisted_source_language(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "handler.rs").write_text("fn handle() {}\n", encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)

    result = run_review(target, tmp_path / "workspace", provider=provider)

    assert result.outcome.complete
    assert provider.calls


class _CountingVerifier(Verifier):
    def __init__(self):
        self.calls = 0

    def verify(self, candidate, root):
        self.calls += 1
        return Verdict(real=True, reason="candidate remains exploitable")


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


_WALLET_FINDING = finding(
    "app/services/wallet.py",
    2,
    title="wallet idor",
    symbol="get_wallet",
    endpoint="GET /wallets/<wallet_id>",
    attack_path="request reads another user wallet without ownership",
    evidence="wallet.py:2 no owner check",
)


def _wallet_provider() -> MockProvider:
    """Report the wallet finding from the wallet unit and nothing elsewhere."""
    return unit_provider(lambda name: [dict(_WALLET_FINDING)] if name == "app/services/wallet.py" else [])


def _reviewed_units(provider: MockProvider) -> list[str]:
    return [prompt_unit(call["messages"]) for call in provider.calls]


def test_repository_run_completes_writes_findings_and_records_reviewed_units(custody_repository, tmp_path):
    res = run_review(custody_repository, tmp_path / "ws", provider=_wallet_provider(), verify=False)
    ws = res.scaffold.workspace

    assert res.outcome.complete is True
    assert len(res.accumulator.findings) == 1

    data = json.loads((ws / "findings.json").read_text())
    assert any(f["entrypoint"] == "GET /wallets/<wallet_id>" for f in data["findings"])
    assert not (ws / "_pocs.md").exists()
    assert not (ws / "units").exists()
    assert not (ws / "inventory").exists()

    status = json.loads((ws / "_run.json").read_text())
    assert status["schema"] == "cyberjury.repository-run/v3"
    assert status["complete"] is True
    assert status["errors"] == 0
    assert status["reviewed_units"] == sorted(unit.name for unit in res.scaffold.units)
    assert status["units_total"] == len(status["reviewed_units"])
    assert status["failed_units"] == []


def test_repository_reviews_raw_source_and_stays_incomplete_when_facts_are_limited(tmp_path):
    target = tmp_path / "opaque"
    target.mkdir()
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef broken(:\n")
    (target / "requirements.txt").write_text("Flask==3.0\n")
    provider = MockProvider(default=EMPTY_REPLY)

    result = run_review(target, tmp_path / "ws", provider=provider, verify=False)

    assert provider.calls
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

    resumed_provider = MockProvider(default=EMPTY_REPLY)
    resumed = run_review(target, tmp_path / "ws", provider=resumed_provider, verify=False)

    assert resumed_provider.calls == []
    assert resumed.outcome.complete is False
    assert resumed.outcome.grounding.limitations == result.outcome.grounding.limitations


def test_run_writes_pocs_named_by_candidate_id(custody_repository, tmp_path):
    sources = []

    class WritePoC:
        ext = "py"

        def generate(self, *, source, **kw):
            sources.append(source)
            return PoCArtifact(source="import requests\n", run_hint="python poc.py")

    res = run_review(
        custody_repository,
        tmp_path / "ws",
        provider=_wallet_provider(),
        verify=False,
        poc_backend=WritePoC(),
    )

    ws = res.scaffold.workspace
    finding_record = json.loads((ws / "findings.json").read_text())["findings"][0]
    assert sorted(path.name for path in (ws / "pocs").glob("*.py")) == [f"{finding_record['id']}.py"]
    assert "PoC written, run it manually" in finding_record["evidence"]
    assert sources == [(custody_repository / "app" / "services" / "wallet.py").read_text()]
    assert res.poc_failures == ()


def test_run_records_a_failed_poc_and_keeps_the_finding(custody_repository, tmp_path):
    class Erroring:
        ext = "py"

        def generate(self, **kw):
            raise RuntimeError("model down")

    res = run_review(
        custody_repository,
        tmp_path / "ws",
        provider=_wallet_provider(),
        verify=False,
        poc_backend=Erroring(),
    )

    ws = res.scaffold.workspace
    assert res.outcome.complete is True
    assert len(res.poc_failures) == 1
    assert "RuntimeError: model down" in res.poc_failures[0]
    assert "model down" in (ws / "_pocs.md").read_text()
    finding_record = json.loads((ws / "findings.json").read_text())["findings"][0]
    assert finding_record["evidence"] == "wallet.py:2 no owner check"


def test_run_rejects_source_changed_during_poc_generation(custody_repository, tmp_path):
    routes = custody_repository / "app" / "routes.py"

    class MutatingPoC:
        ext = "py"

        def generate(self, **kw):
            routes.write_text("changed\n")
            return PoCArtifact(source="assert True\n")

    with pytest.raises(ValueError, match="source changed before review output"):
        run_review(
            custody_repository,
            tmp_path / "ws",
            provider=_wallet_provider(),
            verify=False,
            poc_backend=MutatingPoC(),
        )


def test_run_fails_loud_on_zero_units(tmp_path):
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no readable production source files"):
        run_review(repository, tmp_path / "ws", verify=False)


def test_resume_skips_reviewed_units_and_verified_findings(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    r1v = _CountingVerifier()
    run_review(custody_repository, ws, provider=_wallet_provider(), verifier=r1v)
    findings_after_1 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_1
    assert r1v.calls >= 1

    r2 = _wallet_provider()
    r2v = _CountingVerifier()
    run_review(custody_repository, ws, provider=r2, verifier=r2v, fresh=False)
    assert r2.calls == []
    assert r2v.calls == 0
    findings_after_2 = json.loads((ws / "custody" / "findings.json").read_text())["findings"]
    assert findings_after_2 == findings_after_1


def test_resume_rejects_an_older_run_status_schema(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    first = run_review(custody_repository, workspace, provider=_wallet_provider(), verify=False)
    status_path = first.scaffold.workspace / "_run.json"
    status = json.loads(status_path.read_text())
    status["schema"] = "cyberjury.repository-run/v2"
    status_path.write_text(json.dumps(status))
    resumed = _wallet_provider()

    with pytest.raises(ValueError, match=r"schema is unsupported.*Remove the workspace"):
        run_review(custody_repository, workspace, provider=resumed, verify=False)

    assert resumed.calls == []


def test_completed_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    run_review(custody_repository, workspace, provider=_wallet_provider(), verify=False)
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _wallet_provider()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        run_review(custody_repository, workspace, provider=resumed, verify=False)

    assert resumed.calls == []


def test_partial_review_rejects_resume_after_source_changes(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    shared = {"verify": False, "concurrency": 1}
    unavailable = unit_provider(lambda _name: RuntimeError("provider unavailable"))
    first = run_review(custody_repository, workspace, provider=unavailable, **shared)
    assert first.outcome.complete is False
    routes = custody_repository / "app" / "routes.py"
    routes.write_text(routes.read_text() + "\n@app.route('/new')\ndef new(): return 'new'\n")
    resumed = _wallet_provider()

    with pytest.raises(ValueError, match=r"source or profile changed.*--fresh"):
        run_review(custody_repository, workspace, provider=resumed, **shared)

    assert resumed.calls == []


def test_resume_with_reviewed_units_but_missing_union_fails_loud(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())
    (ws / "custody" / "_union.json").unlink()
    with pytest.raises(ValueError, match=r"no _union\.json"):
        run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())


def _two_entrypoint_repository(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n'
        )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def _raising_provider(fail_unit):
    return unit_provider(
        lambda name: (
            RuntimeError("provider rate limited")
            if name == fail_unit
            else [finding(name, 1, title="ok", endpoint=name)]
        )
    )


def test_failed_unit_stays_open_and_fails_the_gate(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"
    res = run_review(repository, ws, provider=_raising_provider("beta/routes.py"), verify=False)
    proj = ws / "twop"

    assert "beta/routes.py" in res.accumulator.failed_units
    assert res.accumulator.errors > 0

    status = json.loads((proj / "_run.json").read_text())
    assert status["reviewed_units"] == ["alpha/routes.py"]
    assert status["complete"] is False
    assert status["state"] == "incomplete"
    assert status["unit_failures"][0]["paths"] == ["beta/routes.py"]
    assert "provider rate limited" in status["unit_failures"][0]["reason"]

    assert check_gate(proj).passed is False

    resumed = _raising_provider("")
    retried = run_review(repository, ws, provider=resumed, verify=False)

    assert _reviewed_units(resumed) == ["beta/routes.py"]
    assert retried.outcome.complete is True
    assert json.loads((proj / "_run.json").read_text())["reviewed_units"] == ["alpha/routes.py", "beta/routes.py"]


def test_corrupt_union_on_resume_raises_loud_and_keeps_report(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())
    proj = ws / "custody"
    before = (proj / "findings.json").read_text()

    (proj / "_union.json").write_text("{ this is not valid json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())
    assert (proj / "findings.json").read_text() == before


def test_corrupt_verified_on_resume_raises_loud(custody_repository, tmp_path):
    ws = tmp_path / "ws"
    run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())
    (ws / "custody" / "_verified.json").write_text("{corrupt", encoding="utf-8")

    with pytest.raises(ValueError, match="corrupt"):
        run_review(custody_repository, ws, provider=_wallet_provider(), verifier=_CountingVerifier())


@pytest.mark.parametrize(
    "checkpoint",
    [
        [],
        {},
        {"schema": 4, "findings": [], "severity_votes": {}},
        {"schema": 5, "findings": {}, "severity_votes": {}},
        {"schema": 5, "findings": ["bad"], "severity_votes": {}},
        {"schema": 5, "findings": [{}], "severity_votes": {}},
        {"schema": 5, "findings": [{"title": 1}], "severity_votes": {}},
    ],
)
def test_structurally_corrupt_union_checkpoint_raises_loud(tmp_path, checkpoint):
    from cyberjury.review.repository.engine import _load_union_checkpoint

    (tmp_path / "_union.json").write_text(json.dumps(checkpoint))

    with pytest.raises(ValueError, match="corrupt"):
        _load_union_checkpoint(tmp_path)


def test_union_checkpoint_rejects_an_invalid_field_value(tmp_path):
    from cyberjury.review.repository.engine import _cand_to_dict, _load_union_checkpoint

    candidate = Candidate(title="x", file="a.py", line=1)
    for field, value in (("severity", "URGENT"), ("line", True), ("found_by", [1]), ("status", "confirmed")):
        record = {**_cand_to_dict(candidate), field: value}
        (tmp_path / "_union.json").write_text(
            json.dumps({"schema": 5, "findings": [record], "severity_votes": {candidate.candidate_id: ["HIGH"]}})
        )

        with pytest.raises(ValueError, match="corrupt"):
            _load_union_checkpoint(tmp_path)


def test_repository_outcome_and_status_preserve_verification_failure_reason(custody_repository, tmp_path):
    class _Boom(Verifier):
        def verify(self, candidate, root):
            raise RuntimeError("rate limited")

    result = run_review(
        custody_repository,
        tmp_path / "ws",
        provider=_wallet_provider(),
        verifier=_Boom(),
        concurrency=1,
    )

    assert result.outcome is not None
    assert result.outcome.failure_reason == "verification failed: RuntimeError: rate limited"
    status = json.loads((result.scaffold.workspace / "_run.json").read_text())
    assert status["failure_reason"] == "verification failed: RuntimeError: rate limited"


def test_union_checkpoint_preserves_identity_attack_path_and_evidence_receipts(tmp_path):
    from cyberjury.review.repository.engine import _load_union_checkpoint, _save_union

    candidate = Candidate(
        title="account export lacks authorization",
        category="missing-authorization",
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
    assert json.loads((tmp_path / "_union.json").read_text())["schema"] == 5
    checkpoint = _load_union_checkpoint(tmp_path)
    restored = list(checkpoint.pool.values())

    assert restored == [candidate]
    assert restored[0].candidate_id == candidate.candidate_id
    assert restored[0].source_operation_id == candidate.source_operation_id
    assert restored[0].attack_path == candidate.attack_path
    assert restored[0].evidence_refs == candidate.evidence_refs
    assert checkpoint.severity_votes[candidate.key()] == ["LOW", "HIGH", "CRITICAL"]


def test_write_findings_replaces_json(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    two = [
        Candidate(title="A", endpoint="GET /a", file="a.py", line=1, severity="HIGH"),
        Candidate(title="B", endpoint="GET /b", file="b.py", line=2, severity="HIGH"),
    ]
    _write_findings(ws, two)
    report = json.loads((ws / "findings.json").read_text())["findings"]
    assert len(report) == 2
    assert {item["status"] for item in report} == {"candidate"}

    _write_findings(ws, two[:1])
    assert len(json.loads((ws / "findings.json").read_text())["findings"]) == 1


def test_write_findings_marks_only_independently_verified_candidates_confirmed(tmp_path):
    from cyberjury.review.repository.engine import _write_findings

    ws = tmp_path / "ws"
    ws.mkdir()
    candidates = [
        Candidate(title="verified", file="a.py", line=1),
        Candidate(title="retained", file="b.py", line=2),
    ]

    artifact = _write_findings(ws, candidates, verified_ids=frozenset({candidates[0].candidate_id}))

    assert {item.file: item.status for item in artifact.findings} == {"a.py": "confirmed", "b.py": "candidate"}


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


def test_write_findings_preserves_distinct_similar_evidence(tmp_path):
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
    finding_value = Candidate(
        title="cors",
        category="cors-misconfiguration",
        file="main.py",
        line=10,
        severity="HIGH",
        evidence=evidence,
    )

    _write_findings(ws, [finding_value])

    report = json.loads((ws / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert report["evidence"].count("credentialed browser responses") == 2
    assert "evil.example" in report["evidence"]
    assert finding_value.evidence == evidence


def test_run_pocs_records_a_backend_error_without_changing_the_finding(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    (tmp_path / "views.py").write_text("def view():\n    return 1\n")
    snapshot = SourceSnapshot.capture(tmp_path, ("views.py",))
    ws = tmp_path / "proj"
    ws.mkdir()
    findings = [Candidate(title="x", category="idor", file="views.py", line=1)]

    class Erroring:
        ext = "py"

        def generate(self, **kw):
            raise RuntimeError("model down")

    out, failures = _run_pocs(ws, findings, Erroring(), str(tmp_path), snapshot)

    assert out == findings
    assert len(failures) == 1
    assert "model down" in failures[0]
    assert not list((ws / "pocs").iterdir())


def test_run_pocs_reads_only_source_that_matches_the_reviewed_snapshot(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    (tmp_path / "views.py").write_text("def view():\n    return 1\n")
    snapshot = SourceSnapshot.capture(tmp_path, ("views.py",))
    (tmp_path / "views.py").write_text("def view():\n    return 2\n")
    ws = tmp_path / "proj"
    ws.mkdir()
    calls = []

    class Recording:
        ext = "py"

        def generate(self, **kw):
            calls.append(kw)
            return PoCArtifact(source="assert True\n")

    out, failures = _run_pocs(ws, [Candidate(title="x", file="views.py", line=1)], Recording(), str(tmp_path), snapshot)

    assert calls == []
    assert "no longer matches the reviewed source snapshot" in failures[0]
    assert out[0].evidence == ""


def test_run_pocs_writes_the_artifact_named_by_candidate_id(tmp_path):
    from cyberjury.review.repository.engine import _run_pocs

    (tmp_path / "views.py").write_text("def get_order():\n    return 1\n    return 2\n")
    snapshot = SourceSnapshot.capture(tmp_path, ("views.py",))
    ws = tmp_path / "proj"
    ws.mkdir()
    findings = [
        Candidate(title="idor", category="idor", file="views.py", line=3, symbol="get_order", evidence="no owner check")
    ]

    class WriteOnly:
        ext = "py"

        def generate(self, **kw):
            return PoCArtifact(source="import requests\n", run_hint="python it")

    out, failures = _run_pocs(ws, findings, WriteOnly(), str(tmp_path), snapshot)
    assert failures == ()
    assert len(out) == 1
    assert (ws / "pocs" / f"{findings[0].candidate_id}.py").read_text() == "import requests\n"
    assert "run it manually" in out[0].evidence


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
    run_repository_review(str(repo), str(ws), options=_options(MockProvider(default=EMPTY_REPLY)))
    run = json.loads((ws / "svc" / "_run.json").read_text())
    assert run["state"] == "complete"
    timing = run["timing"]
    assert isinstance(timing["total_seconds"], (int, float))
    names = [u["unit"] for u in timing["unit_seconds"]]
    assert names
    assert len(names) == len(set(names))
    assert set(names) <= {"a.py", "b.py"}


def test_run_status_counts_incomplete_finder_candidates_without_verification(tmp_path):
    from cyberjury.review.engine import ReviewOutcome
    from cyberjury.review.repository.engine import _load_run_status, _save_run_status
    from cyberjury.review.repository.union import Accumulator

    candidate = Candidate(title="missing source receipt", file="app.py", line=7, evidence_refs=("seed",))
    outcome = ReviewOutcome(findings=(), incomplete=(candidate,))

    _save_run_status(
        tmp_path,
        units_total=1,
        reviewed_units={"app.py"},
        acc=Accumulator(),
        verify=None,
        outcome=outcome,
        state="incomplete",
    )

    saved = _load_run_status(tmp_path)
    assert saved is not None
    assert saved["complete"] is False
    assert saved["incomplete"] == 1
    assert saved["verify_errors"] == 0
    assert saved["reviewed_units"] == ["app.py"]


def test_repository_run_persists_the_same_finder_incomplete_count_as_outcome(tmp_path):
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("def get(request):\n    return 1\n", encoding="utf-8")
    provider = MockProvider(default=finder_reply([finding("app.py", 99, title="missing source receipt")]))

    result = run_review(repo, tmp_path / "ws", provider=provider, verify=False)
    status = json.loads((tmp_path / "ws" / "svc" / "_run.json").read_text())
    outcome = json.loads((tmp_path / "ws" / "svc" / "outcome.json").read_text())

    assert not result.outcome.complete
    assert status["incomplete"] == outcome["incomplete"] == 1
    assert status["state"] == "incomplete"


def test_completed_repository_resume_restores_the_prior_outcome(custody_repository, tmp_path):
    workspace = tmp_path / "ws"
    first = run_review(custody_repository, workspace, verify=False)
    second = run_review(custody_repository, workspace, verify=False)

    assert first.outcome.complete is True
    assert second.outcome.complete is True
    assert second.outcome.scheduling is not None
    assert second.outcome.scheduling.stop_reason == "no_open_units"


def test_repository_resume_retries_verification_without_reexecuting_reviewed_units(custody_repository, tmp_path):
    class SwitchingVerifier(Verifier):
        fail = True

        def verify(self, candidate, root):
            if self.fail:
                raise RuntimeError("temporary verification failure")
            return Verdict(real=True, reason="candidate remains exploitable")

    workspace = tmp_path / "ws"
    verifier = SwitchingVerifier()
    first_provider = _wallet_provider()
    first = run_review(custody_repository, workspace, provider=first_provider, verifier=verifier)
    assert first.outcome.complete is False
    assert first_provider.calls

    verifier.fail = False
    second_provider = _wallet_provider()
    second = run_review(custody_repository, workspace, provider=second_provider, verifier=verifier)

    assert second_provider.calls == []
    assert second.outcome.complete is True
    assert second.outcome.scheduling is not None
    assert second.outcome.scheduling.stop_reason == "no_open_units"


@pytest.mark.parametrize(("field", "value"), [("complete", False), ("errors", 1)])
def test_completed_repository_resume_rejects_tampered_status(custody_repository, tmp_path, field, value):
    workspace = tmp_path / "ws"
    first = run_review(custody_repository, workspace, verify=False)
    status_path = first.scaffold.workspace / "_run.json"
    status = json.loads(status_path.read_text())
    status[field] = value
    status_path.write_text(json.dumps(status))

    with pytest.raises(ValueError, match="content hash does not match"):
        run_review(custody_repository, workspace, verify=False)


def test_repository_writes_running_state_before_the_first_unit(tmp_path):
    repository = _two_entrypoint_repository(tmp_path / "target")
    workspace = tmp_path / "ws"
    status_path = workspace / "target" / "_run.json"
    snapshots = []

    def respond(_system, _messages):
        snapshots.append(json.loads(status_path.read_text()))
        return EMPTY_REPLY

    run_review(repository, workspace, provider=MockProvider(responder=respond), verify=False, concurrency=1)

    assert snapshots
    assert all(snapshot["state"] == "running" for snapshot in snapshots)
    assert all(snapshot["complete"] is False for snapshot in snapshots)
    assert all(snapshot["reviewed_units"] == [] for snapshot in snapshots)


def _run_with_meter(tmp_path):
    from cyberjury.providers.metering import MeteringProvider, UsageMeter
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    meter = UsageMeter()
    provider = MeteringProvider(MockProvider(default=EMPTY_REPLY), meter)
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
    assert usage["unit_review_calls"] >= len(run["reviewed_units"])
    assert run["model_calls"]
    call = run["model_calls"][0]
    assert call["role"] == "finder"
    assert call["unit_id"]
    assert call["evidence_revision"].startswith("revision-")
    assert call["prompt_chars"] > 0
    assert call["duration_seconds"] >= 0
    assert call["parse_source"] == "direct"
    assert call["status"] == "ok"


def test_a_run_without_a_meter_writes_no_usage_rather_than_zeros(tmp_path):
    from cyberjury.review.repository.scaffold import scaffold

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "a.py").write_text("def get(request, id):\n    return M.objects.get(id=id)\n")
    ws = tmp_path / "ws"
    scaffold(str(repo), str(ws))
    run_repository_review(str(repo), str(ws), options=_options(MockProvider(default=EMPTY_REPLY)))
    assert "usage" not in json.loads((ws / "svc" / "_run.json").read_text())
