"""Review command tests cover the stage records each review writes and prints, and how its attempt ends."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.review.command as commandmod
from cyberjury.envfile import load_env_file
from cyberjury.providers import configuration as provider_configuration_module
from cyberjury.providers.base import ProviderAccessError
from cyberjury.record import STAGES, Record
from cyberjury.review.command import ReviewCommand, attempt_output, classify_error, run_review_command
from cyberjury.review.recorder import TERMINATED
from cyberjury.review.request import TargetInput
from cyberjury.review.result import findings_artifact
from cyberjury.workspace import SessionBusyError
from tests.support import MockProvider, git

_EMPTY_REPLY = '{"findings": [], "evidence_requests": [], "source_queries": []}'


@pytest.fixture(autouse=True)
def _no_env_file(monkeypatch):
    monkeypatch.setattr(commandmod, "load_env_file", lambda: [])


@pytest.fixture(autouse=True)
def _scripted_seat(monkeypatch):
    _live_provider(monkeypatch)


@dataclass(frozen=True)
class _Run:
    record: Record
    out: str
    err: str


def _review(
    target: TargetInput,
    state_dir: Path | None,
    *,
    fresh: bool | None = None,
) -> _Run:
    stdout, stderr = io.StringIO(), io.StringIO()
    command = ReviewCommand(target=target, fresh=fresh, state_dir=str(state_dir) if state_dir is not None else None)
    record = run_review_command(command, stdout=stdout, stderr=stderr)
    return _Run(record=record, out=stdout.getvalue(), err=stderr.getvalue())


def _diff(repository: Path, git_range: str) -> TargetInput:
    return TargetInput(kind="diff", repository=str(repository.resolve()), git_range=git_range)


def _repository(directory: Path) -> TargetInput:
    return TargetInput(kind="repository", repository=str(directory.resolve()))


def _records(output: str) -> list[dict]:
    decoder, position, records = json.JSONDecoder(), 0, []
    while position < len(output):
        record, position = decoder.raw_decode(output, position)
        records.append(record)
        while position < len(output) and output[position].isspace():
            position += 1
    return records


def _stage(records: list[dict], name: str) -> dict:
    return next(record for record in records if record["id"] == name)


def _review_dir(state: Path) -> Path:
    [review] = (state / "reviews").iterdir()
    return review


def _attempt_dir(state: Path) -> Path:
    [attempt] = (_review_dir(state) / "attempts").iterdir()
    return attempt


def _attempt_record(attempt: Path) -> dict:
    return json.loads((attempt / "record.json").read_text())


def _stub_review(*, incomplete: str = "", seen: dict | None = None):
    def review(prepared, *, recorder, **kwargs):
        if seen is not None:
            seen.update(kwargs, units=list(prepared.units), root=prepared.shared.root)
        with recorder.stage("review") as measure:
            measure.metrics.update(items=len(prepared.units))
            if incomplete:
                measure.incomplete(incomplete)
        with recorder.stage("link"):
            pass
        with recorder.stage("result") as measure:
            measure.bind(findings_artifact([], (), unfinished=frozenset()))

    return review


def _live_provider(monkeypatch, default: str = _EMPTY_REPLY) -> None:
    monkeypatch.setenv("CYBERJURY_API_KEY", "k")
    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default=default))


def _seed_source(repository: Path) -> Path:
    repository.mkdir(parents=True, exist_ok=True)
    source = repository / "app.py"
    if not source.exists():
        source.write_text("value = 1\n")
    return repository


def _git_change(repo: Path, base: dict[str, str], head: dict[str, str]) -> SimpleNamespace:
    repo.mkdir()
    git(repo, "init", "--quiet")
    for files, message in ((base, "base"), (head, "head")):
        for relative, text in files.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "--quiet", "--allow-empty", "-m", message)
        if message == "base":
            base_revision = git(repo, "rev-parse", "HEAD")
    return SimpleNamespace(
        target=_diff(repo, f"{base_revision}..HEAD"),
        repository=repo,
        base=base_revision,
    )


@pytest.fixture
def diff_target(tmp_path):
    """Commit one added file over an empty base and return its two-dot range target."""
    return _git_change(tmp_path / "repo", {}, {"a.py": "x = 1\n"})


def _flask_repository(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n'
    )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def _graphable(root):
    root.mkdir()
    (root / "app.py").write_text("def handle(req):\n    return lookup(req)\n")
    (root / "store.py").write_text("def lookup(key):\n    return key\n")
    return root


def test_a_review_prints_every_stage_record_file_and_then_the_attempt_record(diff_target, tmp_path):
    """Stdout is the stage record files in stage order and then record.json, byte for byte."""
    state = tmp_path / "state"

    run = _review(diff_target.target, state)

    attempt = _attempt_dir(state)
    records = _records(run.out)
    assert run.out == attempt_output(attempt)
    assert [record["id"] for record in records] == [*STAGES, attempt.name]
    assert [record["status"] for record in records] == ["ok"] * 11


def test_stderr_prints_the_line_of_every_record_it_writes(diff_target, tmp_path):
    """Each stage and the attempt record print their one-line view, and each review unit prints its item line."""
    state = tmp_path / "state"

    run = _review(diff_target.target, state)

    lines = run.err.splitlines()
    paths = sorted(_review_dir(state).glob("review/items/*.json"))
    items = [Record.from_dict(json.loads(path.read_text())) for path in paths]
    expected = [Record.from_dict(record).line() for record in _records(run.out)]
    assert [line for line in lines if not line.startswith("review/")] == expected
    assert sorted(line for line in lines if line.startswith("review/")) == sorted(item.line() for item in items)


def test_every_record_kind_carries_its_fixed_metrics_and_attributes(diff_target, tmp_path):
    """Stages, review items, and the attempt each carry one fixed metric set in vocabulary order and attribute set."""
    state = tmp_path / "state"
    usage = ["calls", "input_tokens", "cache_read_tokens", "cache_write_tokens", "output_tokens"]

    records = _records(_review(diff_target.target, state).out)

    item = next((_review_dir(state) / "review" / "items").glob("*.json"))
    assert {record["id"]: list(record["metrics"]) for record in records[:-1]} == {
        "config": [],
        "target": [],
        "session": [],
        "source": ["files", "bytes"],
        "facts": ["limitations"],
        "plan": ["skipped_files", "items"],
        "grounding": ["items"],
        "review": ["items", "restored", "failed", "findings", "unlocated", *usage],
        "link": ["items", "restored", "failed", *usage],
        "result": ["findings", "issues", "critical", "high", "medium", "low"],
    }
    assert {record["id"]: list(record["attributes"]) for record in records[:-1]} == {
        "config": ["provider", "model", "version"],
        "target": ["kind", "repository", "range"],
        "session": ["path"],
        "source": ["snapshot"],
        "facts": [],
        "plan": [],
        "grounding": [],
        "review": [],
        "link": [],
        "result": [],
    }
    item_record = json.loads(item.read_text())
    assert list(item_record["metrics"]) == ["findings", "unlocated", *usage]
    assert list(item_record["attributes"]) == ["paths"]
    assert list(records[-1]["metrics"]) == ["failed", *usage]
    assert records[-1]["attributes"] == {"source_changed": False}


def test_the_attempt_record_sums_failures_and_the_usage_of_every_call(diff_target, tmp_path):
    """The attempt metrics carry the summed failed count and the model usage of every recorded call."""
    state = tmp_path / "state"

    attempt = _records(_review(diff_target.target, state).out)[-1]

    calls = json.loads((_attempt_dir(state) / "model-calls.json").read_text())["calls"]
    assert attempt["metrics"]["failed"] == 0
    assert attempt["metrics"]["calls"] == len(calls) > 0
    assert attempt["artifacts"] == [f"attempts/{attempt['id']}/model-calls.json"]


def test_a_missing_api_key_fails_the_config_stage_before_any_state_directory_exists(monkeypatch, diff_target, tmp_path):
    """Without CYBERJURY_API_KEY the config record fails with a config error and no state directory is created."""
    monkeypatch.delenv("CYBERJURY_API_KEY")
    state = tmp_path / "state"

    run = _review(diff_target.target, state)

    records = _records(run.out)
    assert [record["status"] for record in records] == ["failed", "failed"]
    assert records[0]["id"] == "config"
    assert records[-1]["error"] == records[0]["error"]
    assert records[0]["error"]["code"] == "config"
    assert records[0]["error"]["message"] == "the openai provider has no API key, set CYBERJURY_API_KEY"
    assert not state.exists()


def test_an_invalid_git_range_fails_the_target_stage_before_any_state_directory_exists(diff_target, tmp_path):
    """A bare HEAD range fails the target record with an input error and no state directory is created."""
    state = tmp_path / "state"

    run = _review(_diff(diff_target.repository, "HEAD"), state)

    target = _stage(_records(run.out), "target")
    assert target["error"] == {"code": "input", "message": "Git range must use A..B or A...B"}
    assert not state.exists()


@pytest.mark.parametrize("value", ["0", "two"])
def test_an_invalid_concurrency_setting_fails_the_config_stage(monkeypatch, diff_target, tmp_path, value):
    """A CYBERJURY_CONCURRENCY of 0 or two fails the config record with a config error naming the setting."""
    monkeypatch.setenv("CYBERJURY_CONCURRENCY", value)
    state = tmp_path / "state"

    run = _review(diff_target.target, state)

    config = _stage(_records(run.out), "config")
    assert config["error"] == {"code": "config", "message": f"CYBERJURY_CONCURRENCY is not a positive integer: {value}"}
    assert not state.exists()


@pytest.mark.parametrize(
    ("variables", "expected"),
    [
        ({"CYBERJURY_STATE_DIR": "state", "XDG_DATA_HOME": "data"}, "state"),
        ({"XDG_DATA_HOME": "data"}, "data/cyberjury"),
        ({}, "home/.local/share/cyberjury"),
    ],
)
def test_the_state_directory_comes_from_the_environment_or_the_user_data_directory(
    monkeypatch, diff_target, tmp_path, variables, expected
):
    """The session goes under CYBERJURY_STATE_DIR, else $XDG_DATA_HOME/cyberjury, else ~/.local/share/cyberjury."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review())
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    for name, value in variables.items():
        monkeypatch.setenv(name, str(tmp_path / value))

    assert _review(diff_target.target, None).record.status == "ok"

    assert _attempt_dir(tmp_path / expected).is_dir()


def test_a_state_directory_inside_the_repository_is_rejected_before_it_is_created(tmp_path):
    """A state directory inside the repository fails the target stage with an input error and is never created."""
    repository = tmp_path / "repo"
    repository.mkdir()
    state = repository / ".state"

    run = _review(_repository(repository), state)

    target = _stage(_records(run.out), "target")
    assert target["error"]["code"] == "input"
    assert "state directory cannot be inside" in target["error"]["message"]
    assert not state.exists()


def test_diff_review_materializes_the_revision_once_and_closes_it(monkeypatch, diff_target, tmp_path):
    """A diff review checks out its revision exactly once and deletes that checkout afterwards."""
    original = commandmod.materialize_diff_target
    roots = []

    @contextlib.contextmanager
    def counted(target):
        with original(target) as root:
            roots.append(root)
            yield root

    monkeypatch.setattr(commandmod, "materialize_diff_target", counted)

    assert _review(diff_target.target, tmp_path / "state").record.status == "ok"
    assert len(roots) == 1
    assert not roots[0].exists()


def test_a_dangling_symlink_outside_the_change_does_not_fail_a_diff_review(monkeypatch, tmp_path):
    """A committed test/tool link to an untracked build output leaves the review ok with app.py as its one unit."""
    seen = {}
    monkeypatch.setattr(commandmod, "run_review", _stub_review(seen=seen))
    repo = tmp_path / "repo"
    (repo / "test").mkdir(parents=True)
    git(repo, "init", "--quiet")
    (repo / "test" / "tool").symlink_to("../build/bin/tool")
    (repo / "app.py").write_text("def f(x):\n    return x\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "base")
    (repo / "app.py").write_text("import os\n\ndef f(x):\n    return os.system(x)\n")
    git(repo, "commit", "--quiet", "-am", "change")

    run = _review(_diff(repo, "HEAD~1...HEAD"), tmp_path / "state")

    assert run.record.status == "ok"
    assert [unit.paths for unit in seen["units"]] == [("app.py",)]


def test_hunkless_diff_sections_are_listed_as_skipped_files(tmp_path):
    """Mode-only, rename-only, and empty new files are skipped with reasons while the attempt stays ok."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / "app.py").write_text("def run():\n    return True\n")
    (repo / "run.sh").write_text("echo run\n")
    (repo / "old.py").write_text("def old():\n    return 1\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "run.sh").chmod(0o755)
    git(repo, "mv", "old.py", "renamed.py")
    (repo / "empty.py").write_text("")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "hunkless")
    state = tmp_path / "state"

    assert _review(_diff(repo, f"{base}..HEAD"), state).record.status == "ok"

    skipped = json.loads((_review_dir(state) / "plan" / "skipped-files.json").read_text())["files"]
    assert sorted(skipped, key=lambda item: item["path"]) == [
        {"path": "empty.py", "reason": "empty_new_file"},
        {"path": "renamed.py", "reason": "rename_only"},
        {"path": "run.sh", "reason": "mode_only"},
    ]


def test_review_diff_grounds_units_and_judges_issue_links_on_the_finder(monkeypatch, diff_target, tmp_path):
    """The single diff unit carries +x = 1 and a.py source, with an issue judge and concurrency 8."""
    seen = {}
    monkeypatch.setattr(commandmod, "run_review", _stub_review(seen=seen))

    assert _review(diff_target.target, tmp_path / "state").record.status == "ok"

    [unit] = seen["units"]
    assert "+x = 1" in unit.diff
    assert "# file: a.py lines 1-1" in unit.grounding.prompt.source
    assert Path(seen["root"]).name == diff_target.repository.name
    assert not Path(seen["root"]).exists()
    assert seen["seats"].issue_judge is not None
    assert seen["concurrency"] == 8


def test_review_diff_empty_git_range_is_ok(monkeypatch, diff_target, tmp_path):
    """A HEAD..HEAD range ends ok with no findings."""
    _live_provider(monkeypatch, '{"findings": []}')
    state = tmp_path / "state"

    run = _review(_diff(diff_target.repository, "HEAD..HEAD"), state)

    assert run.record.status == "ok"
    assert json.loads((_attempt_dir(state) / "findings.json").read_text())["findings"] == []


def test_an_incomplete_review_makes_the_attempt_incomplete_with_its_reason(monkeypatch, diff_target, tmp_path):
    """An incomplete review stage makes the attempt incomplete with that stage's reason."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review(incomplete="review unit 1/1 failed for a.py: blocked"))
    state = tmp_path / "state"

    attempt = _records(_review(diff_target.target, state).out)[-1]

    assert attempt["status"] == "incomplete"
    assert attempt["error"] == {"code": "model", "message": "review unit 1/1 failed for a.py: blocked"}
    assert _attempt_record(_attempt_dir(state)) == attempt


def test_repository_review_with_model_errors_marks_units_failed(tmp_path, monkeypatch):
    """A provider answering 'not json at all' fails every unit item and leaves the review stage incomplete."""
    _live_provider(monkeypatch, "not json at all")
    state = tmp_path / "state"

    run = _review(_repository(_flask_repository(tmp_path / "svc")), state)

    review = _stage(_records(run.out), "review")
    assert run.record.status == review["status"] == "incomplete"
    items = list((_review_dir(state) / "review" / "items").glob("*.json"))
    assert review["metrics"]["failed"] == review["metrics"]["items"] == len(items) > 0
    assert {json.loads(path.read_text())["status"] for path in items} == {"failed"}


def test_a_provider_that_rejects_access_fails_the_review_with_a_config_error(tmp_path, monkeypatch):
    """A provider raising ProviderAccessError fails the review stage and the attempt with a config error."""

    def reject(_system, _prompt):
        raise ProviderAccessError("provider rejected the request: invalid x-api-key")

    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(responder=reject))

    run = _review(_repository(_flask_repository(tmp_path / "svc")), tmp_path / "state")

    review = _stage(_records(run.out), "review")
    assert (review["status"], review["error"]["code"]) == ("failed", "config")
    assert (run.record.status, run.record.error.code) == ("failed", "config")


def test_a_session_busy_with_another_attempt_is_a_busy_error():
    """SessionBusyError classifies as busy, not as a config error that needs --fresh."""
    assert classify_error(SessionBusyError("another attempt is already running")).code == "busy"


def test_partially_parsed_sources_are_counted_as_fact_limitations(tmp_path):
    """A repository with a syntax error in app.py reports one limitation on the facts record and stays ok."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\ndef broken(:\n")

    run = _review(_repository(repository), tmp_path / "state")

    assert _stage(_records(run.out), "facts")["metrics"]["limitations"] == 1
    assert run.record.status == "ok"


def test_review_repository_skips_ignored_trees_of_a_git_work_tree(tmp_path):
    """A .gitignore'd .venv tree and its lib64 symlink are left out of the source snapshot and the unit plan."""
    repository = tmp_path / "svc"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / ".gitignore").write_text(".venv/\n")
    (repository / "app.py").write_text("x = 1\n")
    (repository / ".venv" / "lib").mkdir(parents=True)
    (repository / ".venv" / "lib" / "site.py").write_text("y = 2\n")
    (repository / ".venv" / "lib64").symlink_to("lib", target_is_directory=True)
    state = tmp_path / "state"

    assert _review(_repository(repository), state).record.status == "ok"

    review = _review_dir(state)
    files = [entry["path"] for entry in json.loads((review / "source" / "snapshot.json").read_text())["files"]]
    assert files == [".gitignore", "app.py"]
    plan = json.loads((review / "plan" / "plan.json").read_text())
    assert [path for unit in plan["units"] for path in unit["owned_paths"]] == [".gitignore", "app.py"]


def test_review_repository_grounds_units_with_syntax_facts(tmp_path):
    """Review extracts syntax facts before it grounds the planned units, delivering candidate callee source."""
    state = tmp_path / "state"

    assert _review(_repository(_graphable(tmp_path / "svc")), state).record.status == "ok"

    grounding = json.loads((_review_dir(state) / "grounding" / "grounding.json").read_text())
    assert grounding["schema"] == "cyberjury.grounding/v1"
    assert all(context["seed_chars"] > 0 for context in grounding["contexts"])
    assert [
        span["source_span"]["file"] for context in grounding["contexts"] for span in context["source_evidence"]
    ] == ["store.py"]


def test_a_review_whose_live_source_changes_keeps_its_result_and_says_so(tmp_path, monkeypatch):
    """Editing app.py after the review finishes marks the attempt source_changed but keeps it ok."""
    repository = _flask_repository(tmp_path / "svc")
    original = commandmod.run_review

    def review_then_edit(*args, **kwargs):
        result = original(*args, **kwargs)
        (repository / "app.py").write_text("changed = True\n", encoding="utf-8")
        return result

    monkeypatch.setattr(commandmod, "run_review", review_then_edit)

    attempt = _records(_review(_repository(repository), tmp_path / "state").out)[-1]

    assert attempt["status"] == "ok"
    assert attempt["attributes"] == {"source_changed": True}


@pytest.mark.parametrize(("concurrency", "expected"), [(None, 8), ("4", 4)])
def test_repository_review_concurrency_comes_from_the_environment(monkeypatch, tmp_path, concurrency, expected):
    """Repository concurrency is 8 when CYBERJURY_CONCURRENCY is unset and 4 when it is 4."""
    seen = {}
    monkeypatch.setattr(commandmod, "run_review", _stub_review(seen=seen))
    if concurrency is not None:
        monkeypatch.setenv("CYBERJURY_CONCURRENCY", concurrency)

    run = _review(_repository(_seed_source(tmp_path / "svc")), tmp_path / "state")

    assert run.record.status == "ok"
    assert seen["concurrency"] == expected


def test_diff_observable_request_matches_engine_options(monkeypatch, diff_target, tmp_path):
    """The request.json records the seat id and concurrency 5, model-calls.json is empty, and no key leaks."""
    seen = {}
    monkeypatch.setenv("CYBERJURY_API_KEY", "secret-canary")
    monkeypatch.setenv("CYBERJURY_CONCURRENCY", "5")
    monkeypatch.setattr(commandmod, "run_review", _stub_review(seen=seen))
    state = tmp_path / "state"

    assert _review(diff_target.target, state).record.status == "ok"

    attempt = _attempt_dir(state)
    request = json.loads((attempt / "request.json").read_text())
    model_calls = json.loads((attempt / "model-calls.json").read_text())
    assert request["providers"]["seat"]["seat_id"].startswith("seat-")
    assert request["concurrency"] == {"review": 5}
    assert seen["concurrency"] == 5
    assert model_calls["schema"] == "cyberjury.model-calls/v1"
    assert model_calls["calls"] == []
    assert "secret-canary" not in "".join(path.read_text() for path in _review_dir(state).rglob("*.json"))


def test_the_review_reads_its_seat_from_the_working_directory_env(monkeypatch, diff_target, tmp_path):
    """The provider, model, and key in ./.env select an anthropic seat running model-from-env."""
    monkeypatch.setattr(commandmod, "load_env_file", load_env_file)
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text(
        "CYBERJURY_PROVIDER=anthropic\nCYBERJURY_MODEL=model-from-env\nCYBERJURY_API_KEY=key-from-env\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(project)
    for name in ("CYBERJURY_PROVIDER", "CYBERJURY_MODEL", "CYBERJURY_API_KEY"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    seen = {}
    monkeypatch.setattr(commandmod, "run_review", _stub_review(seen=seen))

    run = _review(diff_target.target, tmp_path / "state")

    config = _stage(_records(run.out), "config")
    assert seen["seats"].finder_model == "model-from-env"
    assert (config["attributes"]["provider"], config["attributes"]["model"]) == ("anthropic", "model-from-env")


@pytest.mark.parametrize("scope", ["diff", "repository"])
def test_reviews_persist_calls_bound_to_planned_units(tmp_path, scope):
    """A review records model calls whose unit_id names a planned unit and whose trigger is a finder trigger."""
    change = _git_change(tmp_path / "repo", {}, {"app.py": "def run(name):\n    return name\n"})
    state = tmp_path / "state"

    assert _review(change.target if scope == "diff" else _repository(change.repository), state).record.status == "ok"

    unit_ids = {unit["id"] for unit in json.loads((_review_dir(state) / "plan" / "plan.json").read_text())["units"]}
    calls = json.loads((_attempt_dir(state) / "model-calls.json").read_text())["calls"]
    assert calls
    assert all(call["unit_id"] in unit_ids for call in calls)
    assert all(call["trigger"] in {"initial_judgment", "evidence_followup"} for call in calls)


def test_a_review_directory_holds_lowercase_kebab_case_files_named_after_their_schemas(tmp_path):
    """A review leaves lowercase kebab case files, each naming the schema its file name or record kind implies."""
    state = tmp_path / "state"

    assert _review(_repository(_flask_repository(tmp_path / "svc")), state).record.status == "ok"

    review = _review_dir(state)
    attempt = _attempt_dir(state).name
    units = [path.name for path in (review / "review" / "items").glob("*.json")]
    files = sorted(str(path.relative_to(review)) for path in review.rglob("*") if path.is_file())
    assert files == sorted(
        [
            "session.json",
            "session/intent.json",
            "session/judgment-configuration.json",
            "target/target.json",
            "source/snapshot.json",
            "source/contract.json",
            "facts/facts.json",
            "plan/plan.json",
            "plan/skipped-files.json",
            "grounding/grounding.json",
            *(f"review/items/{unit}" for unit in units),
            *(f"review/findings/{unit}" for unit in units),
            f"attempts/{attempt}/request.json",
            f"attempts/{attempt}/record.json",
            f"attempts/{attempt}/findings.json",
            f"attempts/{attempt}/model-calls.json",
            *(f"attempts/{attempt}/stages/{stage}.json" for stage in STAGES),
        ]
    )
    assert all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.json)?", part) for name in files for part in name.split("/"))

    def expected_schema(name: str) -> str:
        if name.startswith(("review/items/", f"attempts/{attempt}/stages/")) or name.endswith("/record.json"):
            return "cyberjury.record/v1"
        if name.startswith("review/findings/"):
            return "cyberjury.unit-findings/v1"
        return f"cyberjury.{Path(name).stem}/v1"

    assert {name: json.loads((review / name).read_text())["schema"] for name in files} == {
        name: expected_schema(name) for name in files
    }


def test_repository_reruns_share_review_with_distinct_attempts(tmp_path):
    """Two runs of one repository reuse one review directory, and the second restores every unit."""
    target = _repository(_flask_repository(tmp_path / "svc"))
    state = tmp_path / "state"

    assert _review(target, state).record.status == "ok"
    run = _review(target, state)

    review = _stage(_records(run.out), "review")
    attempts = sorted((_review_dir(state) / "attempts").iterdir())
    assert len(attempts) == 2
    assert [_attempt_record(attempt)["status"] for attempt in attempts] == ["ok", "ok"]
    assert review["metrics"]["restored"] == review["metrics"]["items"] > 0


@pytest.mark.parametrize("scope", ["diff", "repository"])
def test_every_stage_record_lists_the_artifacts_it_wrote(monkeypatch, tmp_path, scope):
    """Each stage artifact a record lists exists under the review directory and carries its schema."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review())
    change = _git_change(tmp_path / "repo", {}, {"app.py": "source\n"})
    state = tmp_path / "state"

    run = _review(change.target if scope == "diff" else _repository(change.repository), state)

    review = _review_dir(state)
    artifacts = {record["id"]: record["artifacts"] for record in _records(run.out)}
    schemas = {
        path: json.loads((review / path).read_text())["schema"]
        for paths in artifacts.values()
        for path in paths
        if not path.startswith("attempts/")
    }
    assert artifacts["target"] == ["target/target.json"]
    assert artifacts["source"] == ["source/snapshot.json", "source/contract.json"]
    assert artifacts["plan"] == ["plan/plan.json", "plan/skipped-files.json"]
    assert schemas == {
        "target/target.json": "cyberjury.target/v1",
        "source/snapshot.json": "cyberjury.snapshot/v1",
        "source/contract.json": "cyberjury.contract/v1",
        "facts/facts.json": "cyberjury.facts/v1",
        "plan/plan.json": "cyberjury.plan/v1",
        "plan/skipped-files.json": "cyberjury.skipped-files/v1",
        "grounding/grounding.json": "cyberjury.grounding/v1",
    }
    assert all((review / path).is_file() for paths in artifacts.values() for path in paths)


def test_repository_without_reviewable_source_fails_the_review_stage_before_model_calls(tmp_path):
    """A repository holding only README.md plans no units and fails the review stage with an input error."""
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("unknown target\n")
    state = tmp_path / "state"

    review = _stage(_records(_review(_repository(repository), state).out), "review")

    assert review["status"] == "failed"
    assert review["error"]["code"] == "input"
    assert json.loads((_review_dir(state) / "plan" / "plan.json").read_text())["units"] == []
    assert json.loads((_attempt_dir(state) / "model-calls.json").read_text())["calls"] == []


def test_a_repository_edited_before_resuming_fails_the_source_stage_with_a_fresh_hint(tmp_path):
    """Re-running after app.py changes fails the source stage with a config error naming --fresh."""
    repository = _seed_source(tmp_path / "svc")
    state = tmp_path / "state"
    assert _review(_repository(repository), state).record.status == "ok"
    (repository / "app.py").write_text("value = 2\n")

    source = _stage(_records(_review(_repository(repository), state).out), "source")

    assert source["error"]["code"] == "config"
    assert "--fresh" in source["error"]["message"]


def test_diff_runs_get_independent_review_sessions(monkeypatch, diff_target, tmp_path):
    """Two identical diff runs create two review directories with the same target and snapshot hashes."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review())

    assert _review(diff_target.target, tmp_path).record.status == "ok"
    assert _review(diff_target.target, tmp_path).record.status == "ok"

    reviews = list((tmp_path / "reviews").iterdir())
    assert len(reviews) == 2
    targets = [json.loads((review / "target" / "target.json").read_text()) for review in reviews]
    snapshots = [json.loads((review / "source" / "snapshot.json").read_text()) for review in reviews]
    assert len({target["target_sha256"] for target in targets}) == 1
    assert len({snapshot["snapshot_id"] for snapshot in snapshots}) == 1


def test_repository_configuration_change_requires_fresh(monkeypatch, tmp_path):
    """Changing CYBERJURY_MODEL between runs fails the session stage citing --fresh, which then starts a new review."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review())
    target = _repository(_seed_source(tmp_path / "repo"))
    state = tmp_path / "state"

    monkeypatch.setenv("CYBERJURY_MODEL", "model-a")
    assert _review(target, state).record.status == "ok"
    monkeypatch.setenv("CYBERJURY_MODEL", "model-b")
    session = _stage(_records(_review(target, state).out), "session")
    assert _review(target, state, fresh=True).record.status == "ok"

    assert session["error"]["code"] == "config"
    assert "--fresh" in session["error"]["message"]
    reviews = sorted((state / "reviews").iterdir(), key=lambda path: len(list(path.glob("attempts/*"))))
    assert [len(list(review.glob("attempts/*"))) for review in reviews] == [1, 1]


def _terminate(*_args, **_kwargs):
    assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    os.kill(os.getpid(), signal.SIGTERM)
    raise AssertionError("SIGTERM did not stop the review")


def test_a_terminated_review_keeps_its_model_calls_and_ends_interrupted(monkeypatch, diff_target, tmp_path):
    """A SIGTERM during the review keeps model-calls.json and records the attempt interrupted by SIGTERM."""
    monkeypatch.setattr(commandmod, "run_review", _terminate)
    state = tmp_path / "state"

    run = _review(diff_target.target, state)

    attempt = _attempt_dir(state)
    record = _attempt_record(attempt)
    assert run.record.status == record["status"] == "interrupted"
    assert record["attributes"]["reason"] == TERMINATED
    assert (attempt / "model-calls.json").is_file()


def test_a_review_terminated_during_source_capture_ends_the_source_stage_interrupted(
    monkeypatch, diff_target, tmp_path
):
    """A SIGTERM while the contract receipt is captured records the source stage and the attempt interrupted."""
    monkeypatch.setattr(commandmod.ContractReceipt, "capture", _terminate)

    records = _records(_review(diff_target.target, tmp_path / "state").out)

    assert [record["id"] for record in records[:-1]] == ["config", "target", "session", "source"]
    assert records[-2]["status"] == records[-1]["status"] == "interrupted"


def test_model_call_persistence_failure_marks_the_attempt_failed(monkeypatch, diff_target, tmp_path):
    """When writing model-calls.json raises, record.json carries a failed status and an internal error."""
    monkeypatch.setattr(commandmod, "run_review", _stub_review())

    def fail_write(_attempt, _document):
        raise RuntimeError("model call artifact failed")

    monkeypatch.setattr(commandmod.ReviewAttempt, "write_model_calls", fail_write)
    state = tmp_path / "state"

    _review(diff_target.target, state)

    record = _attempt_record(_attempt_dir(state))
    assert record["status"] == "failed"
    assert record["error"] == {"code": "internal", "message": "RuntimeError: model call artifact failed"}
