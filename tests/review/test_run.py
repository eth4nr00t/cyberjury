"""The shared run reviews every unit, records and resumes unit work, and groups findings into issues."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from cyberjury.review.context import GroundingContext, SourceSpan
from cyberjury.review.repository import context as context_module
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.seats import ReviewSeats
from cyberjury.workspace import WorkspaceCorruptionError, read_record
from tests.review.diff import support as diff
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
from tests.review.support import StubIssueJudge, prepared_units, recorder, run_prepared
from tests.support import MockProvider


def _run(units, provider, *, concurrency=1):
    return run_prepared(
        prepared_units(units, Path(units[0].root)),
        target=REPOSITORY_TARGET,
        seats=ReviewSeats(finder=provider, finder_model="mock", issue_judge=StubIssueJudge(lambda _pair: False)),
        concurrency=concurrency,
    ).outcome


def _units(root, names):
    for name in names:
        (root / f"{name}.py").write_text("value = 1\n", encoding="utf-8")
    return ground([source_unit(root, f"{name}.py", name=name) for name in names])


def test_empty_diff_is_complete_without_model_work():
    """A whitespace-only diff is complete and the provider receives no calls."""
    provider = MockProvider(default="{}")

    result = diff.review("  \n", provider=provider)

    assert result.outcome.complete is True
    assert provider.calls == []


def test_run_fails_loud_on_zero_units(tmp_path):
    """A repository with only README.md raises ValueError about no readable production source files."""
    repository = tmp_path / "empty"
    repository.mkdir()
    (repository / "README.md").write_text("nothing to review here\n")
    with pytest.raises(ValueError, match="no readable production source files"):
        run_repository_review(repository, tmp_path / "ws")


def test_a_failed_unit_makes_the_outcome_incomplete_with_its_failure():
    """A non-JSON reply leaves the outcome incomplete with one recorded failure."""
    result = diff.review(diff.SQL_DIFF, provider=MockProvider(default="not json"))

    assert result.outcome.complete is False
    assert len(result.outcome.failures) == 1


def test_each_unit_is_sent_only_its_own_grounding():
    """Each of two per-file units sends only its own grounding text, once each across the two prompts."""
    provider = MockProvider(default=diff.reply([]))

    units = [
        replace(
            unit,
            grounding=GroundingContext(
                text="context for a.py" if "a.py" in unit.diff else "context for b.py",
            ),
        )
        for unit in diff.diff_units(diff.FILE_A_DIFF + diff.FILE_B_DIFF, max_chars=1)
    ]

    diff.review(units, provider=provider)

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert sum("context for a.py" in prompt for prompt in prompts) == 1
    assert sum("context for b.py" in prompt for prompt in prompts) == 1


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

    assert [(failure.index, failure.paths) for failure in outcome.failures] == [(2, ("bad.py",))]
    assert "rate limited" in outcome.failures[0].reason
    assert {c.title for c in outcome.findings} == {"ok1", "ok2"}


def test_a_failed_batch_keeps_the_findings_of_the_other_batches():
    """A large diff keeps completed batch results while surfacing failed batches."""
    finding_b = {
        "file": "b.py",
        "line": 1,
        "severity": "HIGH",
        "category": "missing-authorization",
        "evidence": "unguarded sink",
    }
    provider = MockProvider(responses=["not json", "still not json", diff.reply([finding_b])])

    result = diff.review(diff.FILE_A_DIFF + diff.FILE_B_DIFF, provider=provider, max_chars=1)

    assert [f.evidence for f in result.outcome.findings] == ["unguarded sink"]
    assert result.outcome.complete is False
    failure = result.outcome.failures[0]
    assert (failure.index, failure.total, failure.paths) == (1, 2, ("a.py",))
    assert "reply had no complete JSON object" in failure.reason


def test_repository_unit_grounding_is_materialized_once(tmp_path, monkeypatch):
    """Reviewing unit.py reads its text once and sends value = 1 in the finder prompt."""
    (tmp_path / "unit.py").write_text("value = 1\n", encoding="utf-8")
    reads = 0
    original = context_module.gather_context

    def counted(unit):
        nonlocal reads
        reads += 1
        return original(unit)

    monkeypatch.setattr(context_module, "gather_context", counted)
    provider = MockProvider(default=EMPTY_REPLY)

    _run(ground([source_unit(tmp_path, "unit.py", name="unit")]), provider)

    assert "value = 1" in provider.calls[0]["messages"][0].content
    assert reads == 1


def test_findings_are_located_before_duplicates_fold():
    """Duplicates anchored at unchanged line 10 and added line 11 fold to one finding anchored at 11."""
    diff_text = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,2 +10,3 @@\n"
        " existing()\n"
        "+expose()\n"
        " finish()\n"
    )
    base = {
        "file": "app.py",
        "line": 10,
        "severity": "HIGH",
        "category": "other",
        "evidence": "existing operation is exposed",
    }
    findings = [
        {**base, "change_anchor": {"file": "app.py", "line": 10, "side": "new"}},
        {**base, "change_anchor": {"file": "app.py", "line": 11, "side": "new"}},
    ]

    result = diff.review(diff_text, provider=MockProvider(default=diff.reply(findings)))

    assert [
        (item.line, item.change_anchor.line if item.change_anchor else None) for item in result.outcome.findings
    ] == [(10, 11)]
    assert result.outcome.complete is False


def test_diff_review_records_one_item_per_unit(tmp_path):
    """Two per-file units leave two ok review item records beside their findings payloads."""
    diff.review(
        diff.FILE_A_DIFF + diff.FILE_B_DIFF, provider=MockProvider(default=diff.reply([])), max_chars=1, review=tmp_path
    )

    records = [read_record(path) for path in sorted((tmp_path / "review" / "items").glob("*.json"))]
    assert [record.status for record in records] == ["ok", "ok"]


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
    """Write a two-file Flask repository and return its root."""
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


def _unit_records(review: Path) -> list[dict]:
    items = review / "review" / "items"
    return [
        {
            "clean": read_record(path).status == "ok",
            "findings": json.loads((review / "review" / "findings" / path.name).read_text())["findings"],
        }
        for path in sorted(items.glob("*.json"))
    ]


def test_repository_run_completes_and_records_each_unit(custody_repository, tmp_path):
    """The custody app run is complete with one wallet finding and two ok unit item records."""
    result = run_repository_review(custody_repository, tmp_path / "ws", provider=_wallet_provider())

    assert result.outcome.complete is True
    assert [f["entrypoint"] for f in result.findings.findings] == ["GET /wallets/<wallet_id>"]
    records = _unit_records(tmp_path / "ws")
    assert [record["clean"] for record in records] == [True, True]
    assert sorted(len(record["findings"]) for record in records) == [0, 1]


def test_repository_reviews_raw_source_and_completes_when_facts_are_limited(tmp_path):
    """A partially parsed app.py is reviewed and completes with its parse limitation in the finder prompt."""
    target = tmp_path / "opaque"
    target.mkdir()
    (target / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef broken(:\n")
    provider = MockProvider(default=EMPTY_REPLY)

    result = run_repository_review(target, tmp_path / "ws", provider=provider)

    assert result.outcome.complete is True
    assert "app.py at 3:12: python partially parsed" in provider.calls[0]["messages"][0].content


def test_repository_run_counts_an_unreceipted_finder_candidate_as_incomplete(tmp_path):
    """A finding at app.py line 99 without a source receipt leaves the run incomplete and the unit unclean."""
    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("def get(request):\n    return 1\n", encoding="utf-8")
    provider = MockProvider(default=finder_reply([finding("app.py", 99, title="missing source receipt")]))

    result = run_repository_review(repo, tmp_path / "ws", provider=provider)

    assert not result.outcome.complete
    assert len(result.outcome.incomplete) == 1
    assert [record["clean"] for record in _unit_records(tmp_path / "ws")] == [False]


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
    assert sorted(record["clean"] for record in _unit_records(ws)) == [False, True]

    resumed = _raising_provider("")
    retried = run_repository_review(repository, ws, provider=resumed)

    assert _reviewed_units(resumed) == ["beta/routes.py"]
    assert retried.outcome.complete is True
    assert [record["clean"] for record in _unit_records(ws)] == [True, True]
    assert sorted(f["file"] for f in retried.findings.findings) == ["alpha/routes.py", "beta/routes.py"]


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
    assert sorted(f["file"] for f in result.findings.findings) == ["alpha/routes.py", "beta/routes.py"]


@pytest.mark.parametrize(
    "payload",
    ["{ this is not valid json", "{}", '{"schema": "cyberjury.unit-findings/v0", "findings": []}', None],
)
def test_a_corrupt_unit_payload_on_resume_raises_loud(custody_repository, tmp_path, payload):
    """Invalid JSON, wrong schema, or malformed findings in a unit payload raise before any provider call."""
    ws = tmp_path / "ws"
    run_repository_review(custody_repository, ws, provider=_wallet_provider())
    path = sorted((ws / "review" / "findings").glob("*.json"))[0]
    if payload is None:
        document = json.loads(path.read_text())
        document["findings"] = [{"title": "missing fields"}]
        payload = json.dumps(document)
    path.write_text(payload, encoding="utf-8")
    resumed = _wallet_provider()

    with pytest.raises(WorkspaceCorruptionError, match=r"corrupt.*--fresh"):
        run_repository_review(custody_repository, ws, provider=resumed)

    assert resumed.calls == []


def test_diff_review_groups_its_findings_into_issues_through_the_shared_step(tmp_path):
    """Two same-line findings and one other-line finding form one issue linked by judgment and location."""
    (tmp_path / "app.py").write_text("first = 1\nsecond = 2\n", encoding="utf-8")
    diff_text = "+++ b/app.py\n@@ -0,0 +1,2 @@\n+first = 1\n+second = 2\n"
    provider = MockProvider(
        default=diff.reply(
            [
                {"file": "app.py", "line": 1, "title": "first claim", "severity": "HIGH", "category": "c"},
                {"file": "app.py", "line": 1, "title": "second claim", "severity": "HIGH", "category": "c"},
                {"file": "app.py", "line": 2, "title": "other line", "severity": "HIGH", "category": "c"},
            ]
        )
    )
    judge = StubIssueJudge()
    context = GroundingContext(text="context", source_spans=(SourceSpan(file="app.py", start_line=1, end_line=2),))

    result = diff.review(diff_text, provider=provider, context=context, issue_judge=judge, root=tmp_path)

    assert len(result.findings.findings) == 3
    assert len(judge.pairs) == 1
    (issue,) = result.findings.issues
    assert issue["linked_by"] == ["judgment", "location"]
    assert set(issue["members"]) == {record["id"] for record in result.findings.findings}
    assert result.outcome.complete


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


def _records_target(tmp_path):
    target = tmp_path / "svc"
    target.mkdir()
    (target / "records.py").write_text(_RECORDS, encoding="utf-8")
    return target


def _records_provider():
    return unit_provider(
        lambda file: [
            finding(file, 5, title="save drops the owner"),
            finding(file, 5, title="stored record has no owner"),
            finding(file, 9, title="load skips the owner check"),
        ]
    )


@pytest.mark.parametrize(("same_fix", "issues"), [(True, 1), (False, 2)])
def test_repository_review_groups_one_line_and_links_judged_issues(tmp_path, same_fix, issues):
    """Two line-5 findings group by location, and the judge links line 9 to them only when it says same fix."""
    judge = StubIssueJudge(lambda pair: same_fix)

    result = run_repository_review(
        _records_target(tmp_path), tmp_path / "ws", provider=_records_provider(), issue_judge=judge
    )

    artifact = result.findings
    assert len(artifact.findings) == 3
    assert len(artifact.issues) == issues
    save = next(issue for issue in artifact.issues if len(issue["members"]) >= 2)
    assert save["linked_by"] == (["judgment", "location"] if same_fix else ["location"])
    assert len(judge.pairs) == 1


@pytest.mark.parametrize("same_fix", [True, False])
def test_resume_reuses_recorded_issue_link_judgments(tmp_path, same_fix):
    """A resumed run with an opposite judge asks it nothing and returns the first run's findings and issues."""
    target = _records_target(tmp_path)
    first = run_repository_review(
        target, tmp_path / "ws", provider=_records_provider(), issue_judge=StubIssueJudge(lambda pair: same_fix)
    )
    resumed_judge = StubIssueJudge(lambda pair: not same_fix)

    resumed = run_repository_review(target, tmp_path / "ws", provider=_records_provider(), issue_judge=resumed_judge)

    assert resumed_judge.pairs == []
    assert resumed.findings == first.findings


def test_a_failed_issue_link_judgment_leaves_the_link_stage_incomplete(tmp_path):
    """A judge raising down keeps two separate issues and a complete review, and the link stage is incomplete."""
    target = _records_target(tmp_path)
    provider = unit_provider(
        lambda file: [finding(file, 5, title="save drops the owner"), finding(file, 9, title="load skips the check")]
    )

    stages = recorder()

    result = run_repository_review(
        target,
        tmp_path / "ws",
        provider=provider,
        issue_judge=StubIssueJudge(error=RuntimeError("down")),
        stages=stages,
    )

    link = next(record for record in stages.stages if record.id == "link")
    assert result.outcome.complete is True
    assert len(result.findings.issues) == 2
    assert link.status == "incomplete"
    assert "down" in link.error.message
    [item] = [read_record(path) for path in (tmp_path / "ws" / "link" / "items").glob("*.json")]
    assert set(item.attributes) == {"pair", "same_fix", "rationale"}
    assert (item.attributes["same_fix"], item.attributes["rationale"]) == (None, None)
