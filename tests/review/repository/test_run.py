"""Repository Review through the shared run covers unit failures, issue grouping, and resume."""

import json
from pathlib import Path

import pytest

from cyberjury.providers.mock import MockProvider
from cyberjury.review.facts import FactLimitation
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.run import run_review
from cyberjury.review.seats import ReviewSeats
from tests.review.repository.support import (
    EMPTY_REPLY,
    finder_reply,
    finding,
    ground,
    prompt_unit,
    run_repository_review,
    source_unit,
    unit_provider,
)
from tests.review.support import StubIssueJudge, prepared_units


def _run(units, provider, *, concurrency=1):
    return run_review(
        prepared_units(units, Path(units[0].root)),
        target=REPOSITORY_TARGET,
        seats=ReviewSeats(finder=provider, finder_model="mock", finder_label="mock"),
        concurrency=concurrency,
    ).outcome


def _units(root, names):
    for name in names:
        (root / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
    return ground([source_unit(root, f"{name}.py", name=name) for name in names])


def test_concurrency_yields_same_union_as_serial(tmp_path):
    """Six units reviewed at concurrency 1 and 4 give the same six candidate ids in order, both complete."""
    units = _units(tmp_path, [f"u{i}" for i in range(6)])

    def provider():
        return unit_provider(lambda file: [finding(file, 1, title=file)])

    serial = _run(units, provider(), concurrency=1)
    parallel = _run(units, provider(), concurrency=4)

    assert [c.candidate_id for c in serial.findings] == [c.candidate_id for c in parallel.findings]
    assert len(parallel.findings) == 6
    assert serial.complete is True
    assert parallel.complete is True


def test_unit_failures_are_counted_not_silent(tmp_path):
    """A rate-limited bad.py unit is recorded as failure index 2 while ok1 and ok2 findings remain."""
    units = _units(tmp_path, ["ok1", "bad", "ok2"])
    provider = unit_provider(
        lambda file: RuntimeError("rate limited") if file == "bad.py" else [finding(file, 1, title=file[:-3])]
    )

    outcome = _run(units, provider, concurrency=2)

    assert outcome.errors == 1
    assert [(failure.index, failure.paths) for failure in outcome.failures] == [(2, ("bad.py",))]
    assert "rate limited" in outcome.failures[0].reason
    assert {c.title for c in outcome.findings} == {"ok1", "ok2"}


def test_repository_unit_grounding_is_materialized_once(tmp_path, monkeypatch):
    """Reviewing unit.py reads its text once and sends value = 1 in the finder prompt."""
    from cyberjury.review.repository import context as context_module

    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    reads = 0
    original = context_module._read_unit_text

    def counted(unit, rel):
        nonlocal reads
        reads += 1
        return original(unit, rel)

    monkeypatch.setattr(context_module, "_read_unit_text", counted)
    provider = MockProvider(default=EMPTY_REPLY)

    _run(ground([source_unit(tmp_path, "unit.py", name="unit")]), provider)

    assert "value = 1" in provider.calls[0]["messages"][0].content
    assert reads == 1


def test_a_unit_limitation_is_attached_to_its_rendered_source(tmp_path):
    """An unparsable broken.py limitation at 1:11 appears in the prompt and marks the outcome incomplete."""
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    provider = MockProvider(default=EMPTY_REPLY)
    limitation = FactLimitation(source="broken.py", analyzer="python", reason="unparsable", line=1, column=11)

    outcome = _run(ground([source_unit(tmp_path, "broken.py")], limitations=(limitation,)), provider)

    assert "broken.py at 1:11" in provider.calls[0]["messages"][0].content
    assert outcome.grounding.limitations == ("facts:broken.py:1:11",)
    assert outcome.complete is False


def test_one_source_operation_keeps_reports_at_different_lines_separate(tmp_path):
    """Findings at lines 63 and 64 sharing operation call-shared stay two separate findings."""

    class OperationNavigator:
        relationship_evidence = RelationshipEvidenceBundle()

        def session(self):
            return self

        def record_delivered(self, evidence, *, seed_spans=()):
            return None

        def source_operation_id(self, file, line):
            return "call-shared" if file == "matching.py" and line in {63, 64} else ""

    (tmp_path / "matching.py").write_text("value = 1\n" * 70, encoding="utf-8")
    provider = unit_provider(
        lambda _name: [finding("matching.py", line, title=f"regex operation {line}") for line in (63, 64)]
    )

    outcome = _run(
        ground([source_unit(tmp_path, "matching.py", name="matching")], navigator=OperationNavigator()),
        provider,
    )

    assert [(item.line, item.source_operation_id) for item in outcome.findings] == [
        (63, "call-shared"),
        (64, "call-shared"),
    ]


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
    """A tiny Flask app seeds a stable workspace path for run tests."""
    d = tmp_path / "custody"
    (d / "app" / "services").mkdir(parents=True)
    (d / "app" / "routes.py").write_text(_FLASK_APP)
    (d / "app" / "services" / "wallet.py").write_text("def get_wallet(wid):\n    return {'id': wid}\n")
    return d


_WALLET_FINDING = finding(
    "app/services/wallet.py",
    2,
    title="wallet idor",
    entrypoint="GET /wallets/<wallet_id>",
    attack_path="request reads another user wallet without ownership",
    evidence="wallet.py:2 no owner check",
)


def _wallet_provider() -> MockProvider:
    return unit_provider(lambda name: [dict(_WALLET_FINDING)] if name == "app/services/wallet.py" else [])


def _reviewed_units(provider: MockProvider) -> list[str]:
    return [prompt_unit(call["messages"]) for call in provider.calls]


def _unit_records(work: Path) -> list[dict]:
    return [json.loads(path.read_text())["value"] for path in sorted((work / "units").glob("*.json"))]


def test_repository_run_completes_and_checkpoints_each_unit(custody_repository, tmp_path):
    """The custody app run is complete with one wallet finding and two clean unit checkpoints."""
    result = run_repository_review(custody_repository, tmp_path / "ws", provider=_wallet_provider())

    assert result.outcome.complete is True
    assert [f.entrypoint for f in result.findings.findings] == ["GET /wallets/<wallet_id>"]
    records = _unit_records(tmp_path / "ws" / "custody")
    assert [record["clean"] for record in records] == [True, True]
    assert sorted(len(record["findings"]) for record in records) == [0, 1]


def test_repository_reviews_raw_source_and_stays_incomplete_when_facts_are_limited(tmp_path):
    """An unparsable app.py is still reviewed, stays incomplete, and resume makes no provider calls."""
    target = tmp_path / "opaque"
    target.mkdir()
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef broken(:\n")
    provider = MockProvider(default=EMPTY_REPLY)

    result = run_repository_review(target, tmp_path / "ws", provider=provider)

    assert provider.calls
    assert result.outcome.errors == 0
    assert result.outcome.complete is False
    assert result.outcome.grounding.limitations
    assert result.outcome_artifact.limitations == 1

    resumed_provider = MockProvider(default=EMPTY_REPLY)
    resumed = run_repository_review(target, tmp_path / "ws", provider=resumed_provider)

    assert resumed_provider.calls == []
    assert resumed.outcome.complete is False
    assert resumed.outcome.grounding.limitations == result.outcome.grounding.limitations


def test_run_fails_loud_on_zero_units(tmp_path):
    """A repository with only README.md raises ValueError about no readable production source files."""
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no readable production source files"):
        run_repository_review(repository, tmp_path / "ws")


def test_resume_skips_reviewed_units(custody_repository, tmp_path):
    """A second run in the same workspace makes no provider calls and returns the same findings."""
    ws = tmp_path / "ws"
    first = run_repository_review(custody_repository, ws, provider=_wallet_provider())
    assert first.findings.findings

    resumed = _wallet_provider()
    second = run_repository_review(custody_repository, ws, provider=resumed)

    assert resumed.calls == []
    assert second.findings == first.findings


def _two_entrypoint_repository(root):
    for pkg in ("alpha", "beta"):
        (root / pkg).mkdir(parents=True)
        (root / pkg / "routes.py").write_text(
            "from flask import Flask, request\napp = Flask(__name__)\n"
            f'@app.route("/{pkg}/<x>")\ndef h_{pkg}(x):\n    return request.args.get("y", "")\n'
        )
    return root


def _raising_provider(fail_unit, *, error=None):
    return unit_provider(
        lambda name: (
            (error or RuntimeError("provider rate limited"))
            if name == fail_unit
            else [finding(name, 1, title=f"ok {name}", entrypoint=name)]
        )
    )


def test_failed_unit_stays_open_and_is_retried_on_resume_keeping_its_findings(tmp_path):
    """A rate-limited beta/routes.py stays unclean, and resume reviews only it and keeps the alpha finding."""
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"
    first = run_repository_review(repository, ws, provider=_raising_provider("beta/routes.py"))

    assert first.outcome.complete is False
    assert first.outcome.failures[0].paths == ("beta/routes.py",)
    assert "provider rate limited" in first.outcome.failures[0].reason
    assert sorted(record["clean"] for record in _unit_records(ws / "twop")) == [False, True]

    resumed = _raising_provider("")
    retried = run_repository_review(repository, ws, provider=resumed)

    assert _reviewed_units(resumed) == ["beta/routes.py"]
    assert retried.outcome.complete is True
    assert [record["clean"] for record in _unit_records(ws / "twop")] == [True, True]
    assert sorted(f.file for f in retried.findings.findings) == ["alpha/routes.py", "beta/routes.py"]


class _Interrupted(BaseException):
    pass


def test_an_interrupted_run_resumes_only_open_units(tmp_path):
    """After a BaseException on beta/routes.py, resume reviews only beta and completes with both findings."""
    repository = _two_entrypoint_repository(tmp_path / "twop")
    ws = tmp_path / "ws"

    with pytest.raises(_Interrupted):
        run_repository_review(repository, ws, provider=_raising_provider("beta/routes.py", error=_Interrupted()))

    resumed = _raising_provider("")
    result = run_repository_review(repository, ws, provider=resumed)

    assert _reviewed_units(resumed) == ["beta/routes.py"]
    assert result.outcome.complete is True
    assert sorted(f.file for f in result.findings.findings) == ["alpha/routes.py", "beta/routes.py"]


@pytest.mark.parametrize(
    "record",
    ["{ this is not valid json", "{}", '{"schema": "cyberjury.unit-review/v0", "value": {}}', None],
)
def test_a_corrupt_unit_checkpoint_on_resume_raises_loud(custody_repository, tmp_path, record):
    """Invalid JSON, wrong schema, or malformed findings in a checkpoint raise before any provider call."""
    ws = tmp_path / "ws"
    run_repository_review(custody_repository, ws, provider=_wallet_provider())
    path = sorted((ws / "custody" / "units").glob("*.json"))[0]
    if record is None:
        document = json.loads(path.read_text())
        document["value"]["findings"] = [{"title": "missing fields"}]
        record = json.dumps(document)
    path.write_text(record, encoding="utf-8")
    resumed = _wallet_provider()

    with pytest.raises(ValueError, match=r"corrupt.*Remove the workspace"):
        run_repository_review(custody_repository, ws, provider=resumed)

    assert resumed.calls == []


def test_repository_run_counts_an_unreceipted_finder_candidate_as_incomplete(tmp_path):
    """A finding at app.py line 99 without a source receipt leaves the run incomplete and the unit unclean."""
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("def get(request):\n    return 1\n", encoding="utf-8")
    provider = MockProvider(default=finder_reply([finding("app.py", 99, title="missing source receipt")]))

    result = run_repository_review(repo, tmp_path / "ws", provider=provider)

    assert not result.outcome.complete
    assert result.outcome_artifact.incomplete == 1
    assert [record["clean"] for record in _unit_records(tmp_path / "ws" / "svc")] == [False]


_RECORDS = (
    "class Records:\n"
    "    table = 'records'\n"
    "\n"
    "    def save(self, record):\n"
    "        record.owner = None\n"
    "        return record.store()\n"
    "\n"
    "    def load(self, key):\n"
    "        return self.find(key)\n"
)


@pytest.mark.parametrize(("same_fix", "issues"), [(True, 1), (False, 2)])
def test_repository_review_folds_one_line_and_links_judged_issues(tmp_path, same_fix, issues):
    """Two line-5 findings fold by location, the judge links line 9 only when it says same fix, and resume reuses it."""
    target = tmp_path / "svc"
    target.mkdir()
    (target / "records.py").write_text(_RECORDS, encoding="utf-8")
    provider = unit_provider(
        lambda file: [
            finding(file, 5, title="save drops the owner"),
            finding(file, 5, title="stored record has no owner"),
            finding(file, 9, title="load skips the owner check"),
        ]
    )
    judge = StubIssueJudge(lambda pair: same_fix)

    result = run_repository_review(target, tmp_path / "ws", provider=provider, issue_judge=judge)
    resumed_judge = StubIssueJudge(lambda pair: not same_fix)
    resumed = run_repository_review(target, tmp_path / "ws", provider=provider, issue_judge=resumed_judge)

    artifact = result.findings
    assert len(artifact.findings) == 3
    assert len(artifact.issues) == issues
    save = next(issue for issue in artifact.issues if len(issue.members) >= 2)
    assert save.linked_by == (("judgment", "location") if same_fix else ("location",))
    assert len(judge.pairs) == 1
    assert resumed_judge.pairs == []
    assert resumed.findings == artifact
    assert (tmp_path / "ws" / "svc" / "issue-links").is_dir()


def test_a_failed_issue_link_judgment_keeps_the_review_complete_and_is_reported(tmp_path):
    """A judge raising down leaves two separate issues, a complete run, and the error in issue_link_errors."""
    target = tmp_path / "svc"
    target.mkdir()
    (target / "records.py").write_text(_RECORDS, encoding="utf-8")
    provider = unit_provider(
        lambda file: [finding(file, 5, title="save drops the owner"), finding(file, 9, title="load skips the check")]
    )

    result = run_repository_review(
        target, tmp_path / "ws", provider=provider, issue_judge=StubIssueJudge(error=RuntimeError("down"))
    )

    assert result.outcome.complete is True
    assert len(result.findings.issues) == 2
    assert "down" in result.issue_link_errors[0]
