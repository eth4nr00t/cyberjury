"""CLI tests cover command parsing, provider configuration, and dispatch."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers import configuration as provider_configuration_module
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import GroundingCoverage
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.facts import Facts, FactsReceipt
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.request import ReviewIntent, TargetInput
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.run import ReviewRun
from cyberjury.review.unit_plans import UnitPlanReceipt
from tests.support import git


@pytest.fixture(autouse=True)
def _private_state_home(monkeypatch, tmp_path_factory):
    monkeypatch.setenv("CYBERJURY_HOME", str(tmp_path_factory.mktemp("state-home")))
    monkeypatch.setattr(climod, "load_env_file", lambda: [])


def test_install_slash_command_writes_the_file(tmp_path):
    rc = main(["install-slash-command", "--dir", str(tmp_path)])
    assert rc == 0
    f = tmp_path / "cyberjury-review.md"
    text = f.read_text()
    assert f.is_file()
    assert "cyberjury review repository" in text
    assert "cyberjury review diff" in text
    assert "--repository <path>" in text
    assert "--git-range <range>" in text


def test_install_slash_command_refuses_to_clobber_without_force(tmp_path, capsys):
    target = tmp_path / "cyberjury-review.md"
    target.write_text("my own prompt")
    assert main(["install-slash-command", "--dir", str(tmp_path)]) == 1
    assert target.read_text() == "my own prompt"
    assert "already exists" in capsys.readouterr().err
    assert main(["install-slash-command", "--dir", str(tmp_path), "--force"]) == 0
    assert "cyberjury review repository" in target.read_text()


def test_install_slash_command_writes_both_agent_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert main(["install-slash-command"]) == 0
    claude = tmp_path / ".claude" / "commands" / "cyberjury-review.md"
    codex = tmp_path / ".codex" / "prompts" / "cyberjury-review.md"
    assert claude.is_file()
    assert codex.is_file()
    assert claude.read_text() == codex.read_text()


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    from cyberjury.cli import _default_workspace

    monkeypatch.setenv("CYBERJURY_HOME", str(tmp_path / "state"))
    assert _default_workspace() == str(tmp_path / "state")

    monkeypatch.delenv("CYBERJURY_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".cyberjury")


def test_slash_command_does_not_pin_a_shared_workspace():
    assert "/var/tmp" not in climod.SLASH_COMMAND_FILE.read_text()


def _fake_run(prepared, kwargs, *, failures=(), grounding=None, errors=0, failure_reason=""):
    """Return one review result bound to the prepared snapshot without model work."""
    outcome = ReviewOutcome(
        findings=(),
        failures=tuple(failures),
        errors=errors,
        failure_reason=failure_reason or (grounding.failure_reason if grounding is not None else ""),
        grounding=grounding if grounding is not None else GroundingCoverage(),
    )
    findings = FindingsArtifact.create((), ())
    return ReviewRun(
        outcome=outcome,
        findings=findings,
        outcome_artifact=OutcomeArtifact.create(
            target=kwargs["target"].kind,
            source_revision=prepared.shared.snapshot.snapshot_id,
            findings=findings,
            outcome=outcome,
        ),
    )


def _repository_project(state_root: Path, repository: Path) -> Path:
    intent = ReviewIntent(target=TargetInput(kind="repository", repository=str(repository.resolve())))
    locator = json.loads((state_root / "locators" / "reviews" / f"{intent.intent_sha256}.json").read_text())
    return state_root / "reviews" / locator["session_id"] / "work" / repository.name


def _complete_stage_one_only(run) -> int:
    facts = FactsReceipt.create(backend_id="test", facts=Facts())
    run.attempt.bind_facts(facts)
    unit_plan = UnitPlanReceipt.create(facts=facts, units=())
    run.attempt.bind_unit_plan(unit_plan)
    grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=())
    run.attempt.bind_grounding(grounding)
    if run.attempt.request.providers is not None:
        findings = FindingsArtifact.create((), ())
        outcome = OutcomeArtifact.create(
            target=run.attempt.intent.target.kind,
            source_revision=run.snapshot.snapshot_id,
            findings=findings,
            outcome=ReviewOutcome(findings=()),
        )
        run.attempt.bind_result(findings, outcome)
    return 0


def _seed_source(repository: Path) -> None:
    repository.mkdir(parents=True, exist_ok=True)
    source = repository / "app.py"
    if not source.exists():
        source.write_text("value = 1\n")


def test_diff_without_key_errors_loud(monkeypatch, diff_target):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args])


def test_diff_openai_without_key_errors_loud(monkeypatch, diff_target):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args, "--provider", "openai"])


def test_review_diff_dry_run_uses_repository_grounding(capsys, diff_target):
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["findings"]["findings"] == []


def _git_change(repo: Path, base: dict[str, str], head: dict[str, str]) -> SimpleNamespace:
    """Commit the base files, then the head files over them, and return the two-dot range arguments."""
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
        args=("--repository", str(repo), "--git-range", f"{base_revision}..HEAD"),
        repository=repo,
        base=base_revision,
    )


@pytest.fixture
def diff_target(tmp_path):
    return _git_change(tmp_path / "repo", {}, {"a.py": "x = 1\n"})


def test_diff_source_root_uses_resolved_head_revision(tmp_path):
    change = _git_change(tmp_path / "repo", {"app.py": "old\n"}, {"app.py": "new\n"})
    ref = git(change.repository, "rev-parse", "HEAD")

    target = climod.resolve_diff_target(change.repository, f"{change.base}..{ref}")
    with climod.materialize_diff_target(target) as root:
        assert (root / "app.py").read_text() == "new\n"
        worktree = root

    assert not worktree.exists()


def test_diff_review_materializes_the_revision_once_and_closes_it(monkeypatch, diff_target):
    original = climod.materialize_diff_target
    roots = []

    @contextlib.contextmanager
    def counted(target):
        with original(target) as root:
            roots.append(root)
            yield root

    monkeypatch.setattr(climod, "materialize_diff_target", counted)

    assert main(["review", "diff", *diff_target.args, "--dry-run"]) == 0
    assert len(roots) == 1
    assert not roots[0].exists()


def test_review_diff_dry_run_uses_real_git_range_and_grounding(tmp_path, capsys):
    change = _git_change(
        tmp_path / "repo",
        {"app.py": "def run(name):\n    return name\n"},
        {"app.py": "def run(name):\n    return cursor.execute('SELECT ' + name)\n"},
    )

    rc = main(
        ["review", "diff", "--repository", str(change.repository), "--git-range", f"{change.base}...HEAD", "--dry-run"]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["findings"]["findings"] == []
    assert json.loads(captured.out)["findings"]["issues"] == []
    assert "prepare done in" in captured.err
    assert "0 findings in 0 issues: " in captured.err


def test_docs_only_diff_skips_model_calls(tmp_path, capsys):
    change = _git_change(
        tmp_path / "repo",
        {"app.py": "def run():\n    return True\n", "README.md": "Before\n"},
        {"README.md": "After\n"},
    )

    assert main(["review", "diff", *change.args, "--dry-run"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["findings"]["findings"] == []
    assert "skipped 1 file excluded by the noise rules: README.md" in captured.err
    assert json.loads(captured.out)["outcome"]["skipped_files"] == [{"path": "README.md", "reason": "noise"}]


def test_hunkless_diff_sections_are_listed_as_skipped_in_the_outcome(tmp_path, capsys):
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

    assert main(["review", "diff", "--repository", str(repo), "--git-range", f"{base}..HEAD", "--dry-run"]) == 0

    captured = capsys.readouterr()
    outcome = json.loads(captured.out)["outcome"]
    assert outcome["complete"] is True
    assert sorted(outcome["skipped_files"], key=lambda item: item["path"]) == [
        {"path": "empty.py", "reason": "empty_new_file"},
        {"path": "renamed.py", "reason": "rename_only"},
        {"path": "run.sh", "reason": "mode_only"},
    ]
    assert "skipped 3 files without reviewable content:" in captured.err
    assert "run.sh (mode change only)" in captured.err
    assert "noise rules" not in captured.err


def _capture_diff_review(monkeypatch):
    seen = {}

    def fake_review(prepared, **kwargs):
        seen.update(kwargs, units=list(prepared.units), root=prepared.shared.root)
        return _fake_run(prepared, kwargs)

    monkeypatch.setattr(climod, "run_review", fake_review)
    return seen


def test_review_diff_grounds_units_and_judges_issue_links_on_the_finder(monkeypatch, diff_target):
    seen = _capture_diff_review(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default="{}"))

    assert main(["review", "diff", *diff_target.args]) == 0
    [unit] = seen["units"]
    assert "+x = 1" in unit.diff
    assert "# file: a.py lines 1-1" in unit.grounding.prompt.source
    assert Path(seen["root"]).name == diff_target.repository.name
    assert not Path(seen["root"]).exists()
    assert seen["seats"].issue_judge is not None
    assert seen["seats"].finder_label.startswith("seat-")
    assert seen["concurrency"] == 8


def test_review_diff_plans_only_the_filtered_patch(monkeypatch, tmp_path):
    change = _git_change(
        tmp_path / "repo",
        {},
        dict.fromkeys(("app.py", "docs/readme.md", "tests/test_app.py"), "changed\n"),
    )
    seen = _capture_diff_review(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default="{}"))

    state = tmp_path / "state"
    assert main(["review", "diff", *change.args, "--workspace", str(state)]) == 0

    [unit] = seen["units"]
    assert unit.paths == ("app.py",)
    assert "docs/readme.md" not in unit.diff
    assert "tests/test_app.py" not in unit.diff
    review = next(state.glob("reviews/review-*"))
    plan = json.loads((review / "units.json").read_text())
    grounding = json.loads((review / "grounding.json").read_text())
    assert plan["expected_owned_paths"] == ["app.py"]
    assert grounding["unit_plan_receipt_sha256"] == plan["receipt_sha256"]
    assert [context["unit_id"] for context in grounding["contexts"]] == [unit["id"] for unit in plan["units"]]


def test_review_diff_empty_git_range_is_clean(monkeypatch, capsys, diff_target):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setattr(
        "cyberjury.providers.configuration.make_provider",
        lambda *a, **k: MockProvider(default='{"findings": []}'),
    )
    rc = main(
        [
            "review",
            "diff",
            "--repository",
            str(diff_target.repository),
            "--git-range",
            "HEAD..HEAD",
        ]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["findings"]["findings"] == []
    assert result["outcome"]["complete"] is True


def test_incomplete_diff_review_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys, diff_target, tmp_path):
    monkeypatch.setattr(climod, "run_review", lambda prepared, **k: _fake_run(prepared, k, errors=1))
    rc = main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"])
    assert rc == 1
    output = capsys.readouterr()
    assert "the review is incomplete" in output.err
    assert json.loads(output.out)["outcome"]["complete"] is False
    attempt = next(next((tmp_path / "reviews").iterdir()).joinpath("attempts").iterdir())
    assert json.loads((attempt / "attempt.json").read_text())["state"] == "incomplete"


def test_incomplete_diff_review_surfaces_grounding_limitations(monkeypatch, capsys, diff_target):
    grounding = GroundingCoverage(limitations=("facts:app.ts:3:8",))
    monkeypatch.setattr(
        climod,
        "run_review",
        lambda prepared, **k: _fake_run(prepared, k, grounding=grounding),
    )
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])

    assert rc == 1
    assert "structured facts unavailable: facts:app.ts:3:8" in capsys.readouterr().err


def test_incomplete_diff_review_surfaces_failed_batch_details(monkeypatch, capsys, diff_target):
    """Large diff failures include batch paths before the generic incomplete error."""

    def fake_review(prepared, **kwargs):
        return _fake_run(
            prepared,
            kwargs,
            failures=[
                ReviewUnitFailure(
                    index=2,
                    total=3,
                    paths=("app.py", "billing.py", "routes.py", "views.py"),
                    reason="RuntimeError: blocked",
                )
            ],
        )

    monkeypatch.setattr(climod, "run_review", fake_review)
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "review unit 2/3 failed for app.py, billing.py, routes.py, and 1 more: RuntimeError: blocked" in err
    assert "the review is incomplete" in err


def test_review_repository_scaffold_writes_the_unit_plan_without_markdown_workflow(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    review = _repository_project(ws, repository).parents[1]
    assert [unit["name"] for unit in json.loads((review / "units.json").read_text())["units"]] == ["app.py"]


def test_review_repository_scaffold_skips_ignored_trees_of_a_git_work_tree(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    git(repository, "init", "--quiet")
    (repository / ".gitignore").write_text(".venv/\n")
    (repository / "app.py").write_text("x = 1\n")
    (repository / ".venv" / "lib").mkdir(parents=True)
    (repository / ".venv" / "lib" / "site.py").write_text("y = 2\n")
    (repository / ".venv" / "lib64").symlink_to("lib", target_is_directory=True)
    ws = tmp_path / "ws"

    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"]) == 0

    review = _repository_project(ws, repository).parents[1]
    files = [entry["path"] for entry in json.loads((review / "snapshot.json").read_text())["files"]]
    assert files == [".gitignore", "app.py"]
    assert json.loads((review / "units.json").read_text())["expected_owned_paths"] == [".gitignore", "app.py"]


def _graphable(root):
    root.mkdir()
    (root / "app.py").write_text("def handle(req):\n    return lookup(req)\n")
    (root / "store.py").write_text("def lookup(key):\n    return key\n")
    return root


def test_review_repository_grounds_units_with_syntax_facts(tmp_path):
    """Scaffold extracts syntax facts before it grounds the planned units, delivering candidate callee source."""
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(_graphable(tmp_path / "svc")), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    review = _repository_project(ws, tmp_path / "svc").parents[1]
    grounding = json.loads((review / "grounding.json").read_text())
    assert grounding["schema"] == "cyberjury.grounding/v1"
    assert all(context["seed_chars"] > 0 for context in grounding["contexts"])
    assert [
        span["source_span"]["file"] for context in grounding["contexts"] for span in context["source_evidence"]
    ] == ["store.py"]


def _flask_repository(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n'
    )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_repository_run_keeps_its_result_when_the_live_source_changes(tmp_path, monkeypatch, capsys):
    repository = _flask_repository(tmp_path / "svc")
    original = climod.run_review

    def review_then_edit(*args, **kwargs):
        result = original(*args, **kwargs)
        (repository / "app.py").write_text("changed = True\n", encoding="utf-8")
        return result

    monkeypatch.setattr(climod, "run_review", review_then_edit)
    rc = main(["review", "repository", str(repository), "--workspace", str(tmp_path / "ws"), "--run", "--dry-run"])

    assert rc == 0
    err = capsys.readouterr().err
    assert "NOTE: review source changed while the review was running" in err
    assert "Findings written to" in err


def test_diff_review_keeps_its_result_when_the_source_check_fails(monkeypatch, capsys, diff_target, tmp_path):
    monkeypatch.setattr(climod.SourceSnapshot, "matches", lambda self: False)

    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]) == 0

    captured = capsys.readouterr()
    assert "NOTE: review source changed while the review was running" in captured.err
    assert json.loads(captured.out)["outcome"]["complete"] is True
    attempt = next(next((tmp_path / "reviews").iterdir()).joinpath("attempts").iterdir())
    assert (attempt / "outcome.json").is_file()


def test_repository_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    monkeypatch.setattr(
        "cyberjury.providers.configuration.make_provider",
        lambda *a, **k: MockProvider(default="not json at all"),
    )
    rc = main(
        [
            "review",
            "repository",
            str(repository),
            "--workspace",
            str(ws),
            "--run",
        ]
    )
    assert rc == 1


def test_run_builds_one_finder_provider(monkeypatch, tmp_path):
    providers = []

    def fake_make_provider(name, **kwargs):
        provider = MockProvider(default='{"findings": []}')
        providers.append(provider)
        return provider

    monkeypatch.setattr(provider_configuration_module, "make_provider", fake_make_provider)
    monkeypatch.setattr(climod, "run_review", lambda prepared, **kw: _fake_run(prepared, kw))
    _seed_source(tmp_path)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert main(["review", "repository", str(tmp_path), "--run"]) == 0
    assert len(providers) == 1


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ([], 8),
        (["--concurrency", "4"], 4),
    ],
)
def test_run_concurrency_uses_the_api_default(monkeypatch, tmp_path, args, expected):
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run", *args])
    assert captured["concurrency"] == expected


def _patch_run(monkeypatch, tmp_path, **result):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    _seed_source(tmp_path)
    monkeypatch.setattr(
        climod,
        "run_review",
        lambda prepared, **kw: _fake_run(prepared, kw, **result),
    )


def test_run_with_failed_calls_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    failure = ReviewUnitFailure(index=1, total=2, paths=("app.py",), reason="RuntimeError: provider rate limited")
    _patch_run(monkeypatch, tmp_path, failures=[failure], errors=1)
    rc = main(["review", "repository", str(tmp_path), "--run"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error: review unit 1/2 failed for app.py: RuntimeError: provider rate limited" in err


def test_run_failure_reason_exits_nonzero_and_asks_to_rerun(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, tmp_path, errors=1, failure_reason="structured facts unavailable: facts:app.py")
    rc = main(["review", "repository", str(tmp_path), "--run"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error: structured facts unavailable: facts:app.py" in err
    assert "Re-run to retry open work" in err


def test_abbreviated_live_flag_is_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--run", "--conc", "2"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "flag",
    [
        ("--concurrency", "0"),
        ("--retries", "-1"),
        ("--timeout", "0"),
        ("--timeout", "nan"),
        ("--model", ""),
    ],
)
def test_diff_rejects_invalid_cli_values(flag, capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "review",
                "diff",
                "--repository",
                "repo",
                "--git-range",
                "base..HEAD",
                "--dry-run",
                *flag,
            ]
        )
    assert exc.value.code == 2
    assert flag[0] in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["--scaffold", "--model", "unused-model"],
        ["--scaffold", "--provider", "openai"],
        ["--scaffold", "--concurrency", "2"],
        ["--scaffold", "--dry-run"],
    ],
)
def test_repository_rejects_flags_outside_the_selected_action(args, capsys, tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), *args])
    assert exc.value.code == 2
    assert "does not apply" in capsys.readouterr().err


def test_invalid_numeric_environment_uses_the_cli_error_boundary(monkeypatch, capsys, diff_target):
    monkeypatch.setenv("CYBERJURY_RETRIES", "not-an-int")
    assert main(["review", "diff", *diff_target.args, "--dry-run"]) == 1
    err = capsys.readouterr().err
    assert "CYBERJURY_RETRIES must be a nonnegative integer" in err
    assert "Traceback" not in err


def test_failure_text_reads_the_failures_the_cli_prints(monkeypatch, capsys, diff_target):
    monkeypatch.setenv("CYBERJURY_RETRIES", "not-an-int")
    main(["review", "diff", *diff_target.args, "--dry-run"])

    failures = [text for line in capsys.readouterr().err.splitlines() if (text := climod.failure_text(line))]

    assert failures == ["CYBERJURY_RETRIES must be a nonnegative integer"]
    assert climod.failure_text("error: the review is incomplete") == "the review is incomplete"
    assert climod.failure_text("NOTE: review source changed while the review was running") is None


def _capture_run(monkeypatch, repository):
    captured = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    _seed_source(repository)

    def fake_run(prepared, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(climod, "run_review", fake_run)
    return captured


def test_repository_run_uses_the_finder_seat(monkeypatch, tmp_path):
    """Repository run reviews with the finder seat and its seat provenance label."""
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["seats"].finder is not None
    assert captured["seats"].finder_label.startswith("seat-")


def test_diff_observable_request_matches_engine_options(monkeypatch, diff_target, tmp_path):
    captured = {}

    def fake_review(prepared, **kwargs):
        captured.update(kwargs)
        return _fake_run(prepared, kwargs)

    monkeypatch.setenv("CYBERJURY_API_KEY", "secret-canary")
    monkeypatch.setattr(climod, "run_review", fake_review)
    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--concurrency", "5"]) == 0
    review_dir = next((tmp_path / "reviews").iterdir())
    attempt_dir = next((review_dir / "attempts").iterdir())
    request = json.loads((attempt_dir / "request.json").read_text())
    model_calls = json.loads((attempt_dir / "model-calls.json").read_text())

    assert "schedule" not in request
    assert request["providers"]["roles"]["finder"] is not None
    assert request["concurrency"]["review"] == captured["concurrency"] == 5
    assert request["concurrency"] == {"review": 5}
    assert "verification" not in request
    assert not (attempt_dir / "verification.json").exists()
    assert model_calls["schema"] == "cyberjury.model-calls/v1"
    assert model_calls["calls"] == []
    assert "secret-canary" not in "".join(path.read_text() for path in review_dir.rglob("*.json*"))


def test_diff_dry_run_persists_calls_bound_to_planned_units(diff_target, tmp_path):
    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]) == 0
    review = next((tmp_path / "reviews").iterdir())
    attempt = next(review.joinpath("attempts").iterdir())
    unit_ids = {unit["id"] for unit in json.loads((review / "units.json").read_text())["units"]}
    model_calls = json.loads((attempt / "model-calls.json").read_text())

    assert unit_ids
    assert model_calls["calls"]
    assert all(call["unit_id"] in unit_ids for call in model_calls["calls"])
    assert all("round" not in call for call in model_calls["calls"])
    assert all(call["trigger"] in {"initial_judgment", "evidence_followup"} for call in model_calls["calls"])


def test_repository_dry_run_persists_calls_bound_to_planned_units(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    state = tmp_path / "state"

    assert (
        main(
            [
                "review",
                "repository",
                str(repository),
                "--run",
                "--workspace",
                str(state),
                "--dry-run",
            ]
        )
        == 0
    )
    review = next((state / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    unit_ids = {unit["id"] for unit in json.loads((review / "units.json").read_text())["units"]}
    model_calls = json.loads((attempt / "model-calls.json").read_text())

    assert model_calls["calls"]
    assert all(call["unit_id"] in unit_ids for call in model_calls["calls"])
    assert all("round" not in call for call in model_calls["calls"])


def test_repository_actions_share_review_with_distinct_attempts(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    state_root = tmp_path / "state"

    assert main(["review", "repository", str(repository), "--workspace", str(state_root), "--scaffold"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(state_root), "--run", "--dry-run"]) == 0

    reviews = list((state_root / "reviews").iterdir())
    assert len(reviews) == 1
    attempts = sorted((reviews[0] / "attempts").iterdir())
    actions = sorted(json.loads((attempt / "request.json").read_text())["action"] for attempt in attempts)
    assert actions == ["run", "scaffold"]
    assert all(json.loads((attempt / "attempt.json").read_text())["state"] == "complete" for attempt in attempts)


def test_provider_preflight_failure_is_terminal_and_redacted(monkeypatch, diff_target, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path)])

    review_dir = next((tmp_path / "reviews").iterdir())
    attempt_dir = next((review_dir / "attempts").iterdir())
    state = json.loads((attempt_dir / "attempt.json").read_text())
    assert state["state"] == "failed"
    assert "authorization=" not in json.dumps(state).lower()


def test_model_call_persistence_failure_marks_the_attempt_failed(monkeypatch, diff_target, tmp_path):
    monkeypatch.setattr(climod, "_execute_review", _complete_stage_one_only)

    def fail_record(_args):
        raise RuntimeError("model call artifact failed")

    monkeypatch.setattr(climod, "_record_model_calls", fail_record)

    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]) == 1

    review = next((tmp_path / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    assert json.loads((attempt / "attempt.json").read_text())["state"] == "failed"


@pytest.mark.parametrize("scope", ["diff", "repository"])
def test_stage_one_request_is_shared_across_targets(
    monkeypatch,
    tmp_path,
    scope,
):
    captured = {}

    def fake_dispatch(run):
        captured["request"] = run.attempt.request
        captured["intent"] = run.session.intent
        captured["workspace"] = run.session.workspace.path
        return _complete_stage_one_only(run)

    monkeypatch.setattr(climod, "_execute_review", fake_dispatch)
    change = _git_change(tmp_path / "repo", {}, {"app.py": "source\n"})
    target_args = (
        ["diff", *change.args, "--dry-run"]
        if scope == "diff"
        else ["repository", str(change.repository), "--run", "--dry-run"]
    )

    assert (
        main(
            [
                "review",
                *target_args,
                "--workspace",
                str(tmp_path / "state"),
            ]
        )
        == 0
    )
    request = captured["request"]
    assert captured["intent"].target.kind == scope
    assert request.providers.finder_seat_id is not None
    target_artifact = json.loads((captured["workspace"] / "target.json").read_text())
    snapshot_artifact = json.loads((captured["workspace"] / "snapshot.json").read_text())
    contract_artifact = json.loads((captured["workspace"] / "contract.json").read_text())
    facts_artifact = json.loads((captured["workspace"] / "facts.json").read_text())
    units_artifact = json.loads((captured["workspace"] / "units.json").read_text())
    assert target_artifact["schema"] == "cyberjury.resolved-target/v1"
    assert snapshot_artifact["schema"] == "cyberjury.source-snapshot/v1"
    assert contract_artifact["schema"] == "cyberjury.review-contract/v1"
    assert set(contract_artifact["files"]) == {
        "review/contract/security-kernel.md",
        "review/contract/severity-rubric.md",
        "review/contract/detection.yaml",
        "review/syntax/queries.yaml",
    }
    assert facts_artifact["schema"] == "cyberjury.facts/v1"
    assert units_artifact["schema"] == "cyberjury.unit-plan/v1"


def test_repository_without_reviewable_source_fails_before_model_calls(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("unknown target\n")
    state = tmp_path / "state"

    assert main(["review", "repository", str(repository), "--run", "--dry-run", "--workspace", str(state)]) == 1

    review = next((state / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    assert (review / "target.json").is_file()
    assert (review / "snapshot.json").is_file()
    assert json.loads((review / "units.json").read_text())["units"] == []
    assert json.loads((attempt / "model-calls.json").read_text())["calls"] == []
    assert json.loads((attempt / "attempt.json").read_text())["state"] == "failed"


def test_diff_runs_get_independent_review_sessions(monkeypatch, diff_target, tmp_path):
    monkeypatch.setattr(climod, "_execute_review", _complete_stage_one_only)
    command = ["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]

    assert main(command) == 0
    assert main(command) == 0

    reviews = list((tmp_path / "reviews").iterdir())
    assert len(reviews) == 2
    targets = [json.loads((review / "target.json").read_text()) for review in reviews]
    snapshots = [json.loads((review / "snapshot.json").read_text()) for review in reviews]
    assert len({target["target_sha256"] for target in targets}) == 1
    assert len({snapshot["snapshot_id"] for snapshot in snapshots}) == 1


def test_repository_configuration_change_requires_fresh(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(climod, "_execute_review", _complete_stage_one_only)
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n")
    base = ["review", "repository", str(repository), "--run", "--workspace", str(tmp_path / "state")]

    assert main([*base, "--model", "model-a"]) == 0
    assert main([*base, "--model", "model-b"]) == 1
    assert "--fresh" in capsys.readouterr().err
    assert main([*base, "--model", "model-b", "--fresh"]) == 0

    assert len(list((tmp_path / "state" / "reviews").iterdir())) == 2


def test_explicit_review_id_must_already_exist(tmp_path, capsys):
    repository = tmp_path / "repo"
    repository.mkdir()
    state = tmp_path / "state"

    assert (
        main(
            [
                "review",
                "repository",
                str(repository),
                "--scaffold",
                "--workspace",
                str(state),
                "--review-id",
                "review-" + "c" * 32,
            ]
        )
        == 1
    )
    assert "does not exist" in capsys.readouterr().err
    assert not (state / "reviews").exists()


def test_state_root_inside_repository_is_rejected_before_workspace_creation(tmp_path, capsys):
    repository = tmp_path / "repo"
    repository.mkdir()
    state = repository / ".state"

    assert (
        main(
            [
                "review",
                "repository",
                str(repository),
                "--scaffold",
                "--workspace",
                str(state),
            ]
        )
        == 1
    )

    assert "state root cannot be inside" in capsys.readouterr().err
    assert not state.exists()


def test_invalid_committed_git_range_records_failed_attempt_before_models(tmp_path, capsys):
    repository = tmp_path / "repo"
    repository.mkdir()
    git(repository, "init", "--quiet")
    git(repository, "commit", "--quiet", "--allow-empty", "-m", "base")
    state = tmp_path / "state"

    assert (
        main(
            [
                "review",
                "diff",
                "--repository",
                str(repository),
                "--git-range",
                "HEAD",
                "--workspace",
                str(state),
                "--dry-run",
            ]
        )
        == 1
    )

    assert "must use A..B or A...B" in capsys.readouterr().err
    review = next((state / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    assert json.loads((attempt / "attempt.json").read_text())["state"] == "failed"
    assert not (review / "target.json").exists()
