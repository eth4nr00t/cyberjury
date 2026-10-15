"""CLI tests cover command parsing, provider configuration, and dispatch."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers import configuration as provider_configuration_module
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import GroundingContext, GroundingCoverage
from cyberjury.review.diff import checkout as diff_checkout
from cyberjury.review.diff.engine import DiffReviewResult
from cyberjury.review.diff.model import DiffUnit
from cyberjury.review.engine import ReviewOutcome
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle
from cyberjury.review.request import ReviewIntent, TargetInput
from cyberjury.review.result import FindingsArtifact, OutcomeArtifact
from cyberjury.review.scheduling import SchedulingReceipt
from cyberjury.review.session import ReviewSession
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.review.verification import VerificationReceipt, VerifyResult
from cyberjury.sources.snapshot import SourceSnapshot
from tests.cyberjury.review.diff.support import diff_units


@pytest.fixture(autouse=True)
def _hermetic_seat_env(monkeypatch, tmp_path_factory):
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CYBERJURY_HOME", str(tmp_path_factory.mktemp("state-home")))
    monkeypatch.setattr(climod, "load_env_file", lambda: [])


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "cyberjury" in capsys.readouterr().out


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
    assert "--profile <name>" in claude.read_text()
    assert claude.read_text() == codex.read_text()


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    from cyberjury.cli import _default_workspace

    monkeypatch.setenv("CYBERJURY_HOME", str(tmp_path / "state"))
    assert _default_workspace() == str(tmp_path / "state")

    monkeypatch.delenv("CYBERJURY_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".cyberjury")


def test_slash_command_does_not_pin_a_shared_workspace():
    from cyberjury.resources import SLASH_COMMAND_FILE

    assert "/var/tmp" not in SLASH_COMMAND_FILE.read_text()


_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_DIFF = _FILE_A


def _fake_diff_result(options, **values):
    unit_ids = tuple(unit.id for unit in options.grounding.prepare_diff(""))
    degraded = bool(values.pop("degraded", False))
    failures = values.pop("failures", ())
    grounding = values.pop("grounding", None)
    assert not values
    errors = 1 if degraded and not failures and grounding is None else 0
    scheduling = (
        SchedulingReceipt.create(
            unit_ids=unit_ids,
            new_finding_ids=(),
            union_finding_ids=(),
            errors=1 if degraded else 0,
            failures=0,
            incomplete=0,
            clean=not degraded,
            duration_seconds=0,
        )
        if unit_ids
        else SchedulingReceipt.empty(stop_reason="no_reviewable_units")
    )
    outcome = ReviewOutcome(
        findings=(),
        failures=failures,
        errors=errors,
        grounding=grounding if grounding is not None else GroundingCoverage(),
        scheduling=scheduling,
    )
    return DiffReviewResult(outcome=outcome, dropped=[])


def _fake_repository_outcome(options, **values):
    complete = values.pop("complete", True)
    values.pop("degraded", None)
    failure_reason = values.pop("failure_reason", "")
    assert not values
    outcome = ReviewOutcome(
        findings=(),
        failure_reason=failure_reason,
        scheduling=SchedulingReceipt.empty(stop_reason="no_open_units"),
    )
    assert outcome.complete is complete
    return outcome


def _empty_repository_artifacts(target, outcome):
    findings = FindingsArtifact.create(())
    artifact = OutcomeArtifact.create(
        target="repository",
        source_revision=climod.capture_source_snapshot(target).snapshot_id,
        findings=findings,
        outcome=outcome,
    )
    return findings, artifact


def _repository_project(state_root: Path, repository: Path, profile: str = "auto") -> Path:
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(repository.resolve())),
        requested_profile=profile,
    )
    locator = json.loads((state_root / "locators" / "reviews" / f"{intent.intent_sha256}.json").read_text())
    return state_root / "reviews" / locator["session_id"] / "work" / repository.name


def _complete_stage_one_only(run) -> int:
    native_analysis = _native_analysis()
    run.attempt.bind_native_analysis(native_analysis)
    facts_resolution = _facts_resolution(native_analysis)
    run.attempt.bind_facts_resolution(facts_resolution)
    unit_plan = _unit_plan(facts_resolution)
    run.attempt.bind_unit_plan(unit_plan)
    grounding = GroundingReceipt.create(unit_plan=unit_plan, contexts=())
    run.attempt.bind_grounding(grounding, duration_seconds=0)
    if run.attempt.request.providers is not None:
        climod._record_provider_route(run)
        run.attempt.bind_scheduling(SchedulingReceipt.empty(stop_reason="no_reviewable_units"))
        verification = run.attempt.request.verification
        assert verification is not None
        run.attempt.bind_verification(
            VerificationReceipt.create(
                request_sha256=run.attempt.request.request_sha256,
                enabled=verification.enabled,
                candidate_ids=(),
            )
        )
        findings = FindingsArtifact.create(())
        outcome = OutcomeArtifact.create(
            target=run.attempt.intent_target.kind,
            source_revision=run.snapshot.snapshot_id,
            findings=findings,
            outcome=ReviewOutcome(findings=()),
        )
        run.attempt.bind_result(findings, outcome)
    return 0


def _native_analysis() -> NativeAnalysisReceipt:
    return NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )


def _facts_resolution(native_analysis: NativeAnalysisReceipt) -> FactsResolutionReceipt:
    return FactsResolutionReceipt.create(
        native_analysis=native_analysis,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


def _unit_plan(facts_resolution: FactsResolutionReceipt) -> UnitPlanReceipt:
    return UnitPlanReceipt.create(facts_resolution=facts_resolution, units=())


def _seed_web_profile(repository: Path) -> None:
    repository.mkdir(parents=True, exist_ok=True)
    source = repository / "app.py"
    if not source.exists():
        source.write_text("value = 1\n")


def _activate_repository_review(state_root: Path, repository: Path) -> None:
    _seed_web_profile(repository)
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(repository.resolve())),
        requested_profile="auto",
    )
    ReviewSession.select_active(state_root, intent, reuse=True)


def test_diff_without_key_errors_loud(monkeypatch, diff_target):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args])


def test_diff_openai_without_key_errors_loud(monkeypatch, diff_target):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args, "--provider", "openai"])


def _role_args(**over):
    from argparse import Namespace

    base = {
        "provider": "anthropic",
        "model": "claude-base",
        "api_key": "basekey",
        "api_base": None,
        "wire_api": "chat",
        "retries": 0,
        "timeout": 10,
    }
    for role in ("finder", "skeptic", "confirmer"):
        for field in ("provider", "model", "api_key", "api_base", "wire_api"):
            base[f"{role}_{field}"] = None
    base.update(over)
    return Namespace(**base)


def test_role_seat_inherits_base_when_unset():
    s = climod._provider_configuration(_role_args()).skeptic
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-base", "basekey")


def test_base_seat_wire_flows_and_role_inherits_it():
    configuration = climod._provider_configuration(_role_args(wire_api="responses"))
    assert configuration.base.wire_api == "responses"
    assert configuration.skeptic.wire_api == "responses"


def test_role_seat_cross_vendor_override_drops_base_provider_specific_fields():
    """A provider switch must not carry vendor-specific base settings into the role."""
    a = _role_args(
        api_base="https://anthropic.example.test",
        wire_api="chat",
        skeptic_provider="openai",
    )
    s = climod._provider_configuration(a).skeptic
    assert (s.provider, s.model) == ("openai", "gpt-5.6")
    assert s.api_key is None
    assert s.api_base is None
    assert s.wire_api is None


def test_role_seat_cross_vendor_keeps_explicit_role_fields():
    """Role fields stay authoritative when the role intentionally changes provider."""
    from cyberjury.providers.configuration import ProviderSeat

    a = _role_args(
        skeptic_provider="openai",
        skeptic_model="gpt-x",
        skeptic_api_key="role-key",
        skeptic_api_base="https://openai.example.test",
        skeptic_wire_api="responses",
    )
    assert climod._provider_configuration(a).skeptic == ProviderSeat(
        provider="openai",
        model="gpt-x",
        api_key="role-key",
        api_base="https://openai.example.test",
        wire_api="responses",
    )


def test_role_seat_same_vendor_override_keeps_base_key():
    s = climod._provider_configuration(_role_args(skeptic_model="claude-other")).skeptic
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-other", "basekey")


def test_role_provider_errors_loud_at_startup_on_a_missing_key(monkeypatch):
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    run = SimpleNamespace(providers=climod._provider_configuration(_role_args()), meter=UsageMeter())
    with pytest.raises(SystemExit, match="no reachable API key"):
        climod._role_provider(run, ProviderSeat(provider="openai", model="m"))
    climod._role_provider(run, ProviderSeat(provider="anthropic", model="m", api_key="k"))


def test_note_verify_route_states_the_active_route(capsys):
    from cyberjury.cli import _note_verify_route

    _note_verify_route(2)
    out = capsys.readouterr().err
    assert "skeptic plus 2 confirmers" in out
    _note_verify_route(1)
    assert "skeptic plus 1 confirmer," in capsys.readouterr().err
    _note_verify_route(0)
    assert "keep-all" in capsys.readouterr().err


_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_DIFF = _FILE_A


def test_review_diff_dry_run_uses_repository_grounding(capsys, diff_target):
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["findings"]["findings"] == []


def test_review_diff_help_exposes_the_profile_flag(capsys):
    """The canonical selector must be discoverable without advertising removed syntax."""
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--profile PROFILE" in output
    assert "--domain" not in output


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--repository", "repo"],
        ["--git-range", "base..HEAD"],
    ],
)
def test_review_diff_requires_repository_and_git_range(args, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", *args])
    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err


def test_review_diff_rejects_the_removed_domain_flag(capsys):
    """Removed syntax must fail instead of silently selecting the default profile."""
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "review",
                "diff",
                "--repository",
                "repo",
                "--git-range",
                "base..HEAD",
                "--domain",
                "web",
                "--dry-run",
            ]
        )
    assert exc.value.code == 2
    assert "unrecognized arguments: --domain web" in capsys.readouterr().err


def _git(cwd, *args):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


@pytest.fixture
def diff_target(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "commit", "--quiet", "--allow-empty", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "--quiet", "-m", "head")

    class Collector:
        review_paths = ("a.py",)
        navigator = None
        source_snapshot = SourceSnapshot.capture(repo, ("a.py",))
        native_analysis = _native_analysis()
        facts_resolution = _facts_resolution(native_analysis)

        @staticmethod
        def plan(diff):
            return diff_units(diff)

        @classmethod
        def ground(cls, units):
            context = GroundingContext(
                text="repository source",
                source="diff",
                source_snapshot=cls.source_snapshot,
                snapshot_files=("a.py",),
            )
            return [replace(unit, grounding=context) for unit in units]

    monkeypatch.setattr(diff_checkout, "build_diff_context_collector", lambda *args, **kwargs: Collector())
    return SimpleNamespace(
        args=("--repository", str(repo), "--git-range", f"{base}..HEAD"),
        repository=repo,
    )


def test_diff_source_root_uses_resolved_head_revision(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("old\n")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "--quiet", "-m", "old")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("new\n")
    _git(repo, "commit", "--quiet", "-am", "new")
    ref = _git(repo, "rev-parse", "HEAD")

    target = climod.resolve_diff_target(repo, f"{base}..{ref}")
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
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("def run(name):\n    return name\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "--quiet", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text(
        "def run(name):\n    return cursor.execute('SELECT ' + name)\n",
        encoding="utf-8",
    )
    _git(repo, "commit", "--quiet", "-am", "head")

    rc = main(
        [
            "review",
            "diff",
            "--repository",
            str(repo),
            "--git-range",
            f"{base}...HEAD",
            "--dry-run",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert json.loads(captured.out)["findings"]["findings"] == []
    assert "grounded diff context for 1 changed source file" in captured.err


def test_docs_only_diff_skips_facts_extraction_and_model_calls(tmp_path, monkeypatch, capsys):
    import cyberjury.review.diff.context as diff_context

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    (repo / "app.py").write_text("def run():\n    return True\n")
    (repo / "README.md").write_text("Before\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "README.md").write_text("After\n")
    _git(repo, "commit", "--quiet", "-am", "docs")

    def unexpected_facts(*args, **kwargs):
        raise AssertionError("facts extraction is unnecessary for an empty review worklist")

    monkeypatch.setattr(diff_context, "extract_facts", unexpected_facts)
    assert main(["review", "diff", "--repository", str(repo), "--git-range", f"{base}..HEAD", "--dry-run"]) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["findings"]["findings"] == []
    assert "skipped 1 non-reviewable file" in captured.err


def test_review_diff_collects_context_and_verifies(monkeypatch, diff_target):
    seen = {}

    class _Collector:
        review_paths = ("a.py",)
        navigator = None
        source_snapshot = None
        native_analysis = _native_analysis()
        facts_resolution = _facts_resolution(native_analysis)

        def plan(self, diff_text):
            seen["context_diff"] = diff_text
            return [
                DiffUnit(
                    index=1,
                    total=1,
                    diff=diff_text,
                    paths=("a.py",),
                )
            ]

        def ground(self, units):
            context = GroundingContext(
                text="source context",
                source="diff",
                source_snapshot=self.source_snapshot,
                snapshot_files=("a.py",),
            )
            return [replace(unit, grounding=context) for unit in units]

    def fake_audit(*args, **kwargs):
        options = kwargs["options"]
        seen["context"] = options.grounding.prepare_diff(_DIFF)[0].grounding.text
        seen["verification_root"] = options.verification.root
        seen["verifier"] = options.verification.verifier
        seen["verification_confirmers"] = options.verification.confirmers
        seen["verification_found_by"] = options.verification.found_by
        seen["verification_concurrency"] = options.verification.concurrency
        return _fake_diff_result(kwargs["options"])

    def fake_context_collector(root, profile, *, facts_root=None, review_diff="", source_snapshot=None):
        seen["review_diff"] = review_diff
        collector = _Collector()
        collector.source_snapshot = source_snapshot
        return collector

    monkeypatch.setattr(diff_checkout, "build_diff_context_collector", fake_context_collector)
    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default="{}"))
    monkeypatch.setattr(diff_checkout, "run_diff_review", fake_audit)

    assert main(["review", "diff", *diff_target.args, "--api-key", "k"]) == 0
    assert seen["context"] == "source context"
    assert "diff --git a/a.py b/a.py" in seen["review_diff"]
    assert "+x = 1" in seen["review_diff"]
    assert Path(seen["verification_root"]).name == diff_target.repository.name
    assert not Path(seen["verification_root"]).exists()
    assert seen["verifier"] is not None
    assert seen["verification_confirmers"] == ()
    assert len(seen["verification_found_by"]) == 1
    assert seen["verification_found_by"][0].startswith("seat-")
    assert seen["verification_concurrency"] == 8


def test_review_diff_plans_only_the_filtered_patch(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "commit", "--quiet", "--allow-empty", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    for relative in ("app.py", "docs/readme.md", "tests/test_app.py"):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("changed\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "head")
    seen = {}
    navigator = object()

    class Collector:
        review_paths = ("app.py",)
        native_analysis = _native_analysis()
        facts_resolution = _facts_resolution(native_analysis)

        def __init__(self, root, review_diff, source_snapshot):
            self.source_snapshot = source_snapshot
            self.navigator = navigator
            seen["context_diff"] = review_diff

        @staticmethod
        def plan(diff):
            seen["planned_diff"] = diff
            return diff_units(diff)

        def ground(self, units):
            context = GroundingContext(
                text="source context",
                source="diff",
                source_snapshot=self.source_snapshot,
                snapshot_files=("app.py",),
            )
            return [replace(unit, grounding=context) for unit in units]

    def fake_context_collector(root, profile, *, facts_root=None, review_diff="", source_snapshot=None):
        return Collector(root, review_diff, source_snapshot)

    def fake_review(*args, **kwargs):
        seen["unit_paths"] = kwargs["options"].grounding.prepare_diff("")[0].paths
        seen["navigator"] = kwargs["options"].grounding.navigator
        return _fake_diff_result(kwargs["options"])

    monkeypatch.setattr(diff_checkout, "build_diff_context_collector", fake_context_collector)
    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default="{}"))
    monkeypatch.setattr(diff_checkout, "run_diff_review", fake_review)

    state = tmp_path / "state"
    assert (
        main(
            [
                "review",
                "diff",
                "--repository",
                str(repo),
                "--git-range",
                f"{base}..HEAD",
                "--workspace",
                str(state),
                "--api-key",
                "k",
            ]
        )
        == 0
    )

    assert "app.py" in seen["context_diff"]
    assert "docs/readme.md" not in seen["context_diff"]
    assert "tests/test_app.py" not in seen["context_diff"]
    assert seen["planned_diff"] == seen["context_diff"]
    assert seen["unit_paths"] == ("app.py",)
    assert seen["navigator"] is navigator
    review = next(state.glob("reviews/review-*"))
    plan = json.loads((review / "units.json").read_text())
    grounding = json.loads((review / "grounding.json").read_text())
    assert plan["expected_owned_paths"] == ["app.py"]
    assert grounding["unit_plan_receipt_sha256"] == plan["receipt_sha256"]
    assert [context["unit_id"] for context in grounding["contexts"]] == [unit["id"] for unit in plan["units"]]
    events = [
        json.loads(line)["operation"]
        for line in next((review / "attempts").glob("attempt-*/events.jsonl")).read_text().splitlines()
    ]
    assert events.index("units.planned") < events.index("grounding.prepared") < events.index("provider.route.resolved")


def test_review_diff_uses_only_a_confirmer_distinct_from_the_finder(monkeypatch, diff_target):
    """A diff finder cannot also approve deleting its own finding."""
    seen = {}

    def fake_audit(*args, **kwargs):
        verification = kwargs["options"].verification
        seen["verification_confirmers"] = verification.confirmers
        seen["verification_found_by"] = verification.found_by
        seen["verification_concurrency"] = verification.concurrency
        return _fake_diff_result(kwargs["options"])

    monkeypatch.setattr(provider_configuration_module, "make_provider", lambda *a, **k: MockProvider(default="{}"))
    monkeypatch.setattr(diff_checkout, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                *diff_target.args,
                "--api-key",
                "k",
                "--finder-model",
                "finder",
                "--skeptic-model",
                "skeptic",
                "--confirmer-model",
                "confirmer",
                "--concurrency",
                "4",
            ]
        )
        == 0
    )
    labels = [label for label, _checker in seen["verification_confirmers"]]
    assert len(labels) == 1
    assert labels[0].startswith("seat-")
    assert len(seen["verification_found_by"]) == 1
    assert seen["verification_found_by"][0] not in labels
    assert seen["verification_concurrency"] == 4


def test_review_diff_rejects_removed_file_input(capsys, diff_target):
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", *diff_target.args, "--file", "/nonexistent/nope.diff"])
    assert exc.value.code == 2
    assert "unrecognized arguments: --file" in capsys.readouterr().err


@pytest.mark.parametrize("removed", [["--format", "text"], ["--debug"]])
def test_review_diff_rejects_removed_presentation_options(capsys, diff_target, removed):
    with pytest.raises(SystemExit) as exc:
        main(["review", "diff", *diff_target.args, "--dry-run", *removed])

    assert exc.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_review_diff_empty_git_range_is_clean(monkeypatch, capsys, diff_target):
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
            "--api-key",
            "x",
        ]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["findings"]["findings"] == []
    assert result["outcome"]["complete"] is True


def test_diff_degraded_audit_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys, diff_target, tmp_path):
    monkeypatch.setattr(
        diff_checkout,
        "run_diff_review",
        lambda *a, **k: _fake_diff_result(k["options"], degraded=True),
    )
    rc = main(
        [
            "review",
            "diff",
            *diff_target.args,
            "--workspace",
            str(tmp_path),
            "--api-key",
            "k",
        ]
    )
    assert rc == 1
    output = capsys.readouterr()
    assert "degraded" in output.err
    assert json.loads(output.out)["outcome"]["complete"] is False
    attempt = next(next((tmp_path / "reviews").iterdir()).joinpath("attempts").iterdir())
    assert json.loads((attempt / "status.json").read_text())["state"] == "incomplete"


def test_diff_degraded_audit_surfaces_grounding_limitations(monkeypatch, capsys, diff_target):
    grounding = GroundingCoverage(limitations=("facts:app.ts:3:8",))
    monkeypatch.setattr(
        diff_checkout,
        "run_diff_review",
        lambda *a, **k: _fake_diff_result(k["options"], degraded=True, grounding=grounding),
    )
    rc = main(["review", "diff", *diff_target.args, "--api-key", "k"])

    assert rc == 1
    assert "structured facts unavailable: facts:app.ts:3:8" in capsys.readouterr().err


def test_diff_degraded_audit_surfaces_failed_batch_details(monkeypatch, capsys, diff_target):
    """Large diff failures include batch paths before the generic degraded error."""

    def fake_audit(*args, **kwargs):
        return _fake_diff_result(
            kwargs["options"],
            degraded=True,
            failures=[
                ReviewUnitFailure(
                    index=2,
                    total=3,
                    paths=("app.py", "billing.py", "routes.py", "views.py"),
                    reason="AuditError: blocked",
                )
            ],
        )

    monkeypatch.setattr(diff_checkout, "run_diff_review", fake_audit)
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "diff batch 2/3 failed for app.py, billing.py, routes.py, and 1 more: AuditError: blocked" in err
    assert "the diff audit degraded" in err


def test_repository_help_says_run_scaffolds_automatically(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", "--help"])
    assert exc.value.code == 0
    output = " ".join(capsys.readouterr().out.split())
    assert "--run performs this setup automatically" in output
    assert "prerequisite for --run" not in output


def test_review_repository_scaffold_writes_the_unit_plan_without_markdown_workflow(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    project = _repository_project(ws, repository)
    assert (project / "_unit_plan.json").is_file()
    assert not (project / "methodology.md").exists()
    assert not (project / "units").exists()


def test_review_repository_requires_a_mode(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(repository), "--workspace", str(ws)])
    assert exc.value.code == 2


def test_review_repository_facts_writes_no_grounding_for_a_tree_with_no_definitions(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert not (_repository_project(ws, repository) / "_facts.md").exists()


def _graphable(root):
    root.mkdir()
    (root / "app.py").write_text("def handle(req):\n    return lookup(req)\n")
    (root / "store.py").write_text("def lookup(key):\n    return key\n")
    return root


def test_review_repository_grounds_the_web_profile(tmp_path):
    """Automatic web selection must bind tree-sitter before scaffold builds units."""
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(_graphable(tmp_path / "svc")), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    project = _repository_project(ws, tmp_path / "svc")
    assert (project / "_facts.md").is_file()
    assert (project / "_facts_graph.json").is_file()


def _flask_repository(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n'
    )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_repository_gate_exits_nonzero_until_a_run_completes(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 1
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 0


def test_repository_mode_flags_are_mutually_exclusive(tmp_path, capsys):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    for combo in (["--run", "--gate"], ["--run", "--scaffold"], ["--scaffold", "--gate"]):
        with pytest.raises(SystemExit) as exc:
            main(["review", "repository", str(repository), "--workspace", str(ws), *combo])
        assert exc.value.code == 2
        assert "not allowed with argument" in capsys.readouterr().err
    assert not ws.exists()


def test_repository_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
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
            "--api-key",
            "x",
        ]
    )
    assert rc == 1


def test_run_wires_skeptic_and_independent_confirmer(monkeypatch, tmp_path):
    from cyberjury.review.verification import ModelRefutationChecker, ModelVerifier

    captured = _capture_run(monkeypatch, tmp_path)
    main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--run",
            "--api-key",
            "basekey",
            "--skeptic-provider",
            "openai",
            "--skeptic-model",
            "gpt-x",
            "--skeptic-api-key",
            "k",
            "--confirmer-provider",
            "anthropic",
            "--confirmer-model",
            "claude-x",
            "--confirmer-api-key",
            "k2",
        ]
    )
    verification = captured["options"].verification
    assert isinstance(verification.verifier, ModelVerifier)
    assert verification.verifier._model == "gpt-x"
    ((label, checker),) = verification.confirmers
    assert isinstance(checker, ModelRefutationChecker)
    assert checker._model == "claude-x"
    assert checker.checkpoint_fingerprint().seat_id == label


def test_run_default_has_no_confirmer_and_notes_keep_all(monkeypatch, tmp_path, capsys):
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run"])
    options = captured["options"]
    assert options.verification.confirmers == ()
    assert options.output.poc_backend is None
    assert "keep-all" in capsys.readouterr().err


@pytest.mark.parametrize("action", ["scaffold", "gate"])
def test_repository_rejects_poc_for_non_model_actions(tmp_path, action, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), f"--{action}", "--poc"])
    assert exc.value.code == 2
    assert f"--poc does not apply to repository --{action}" in capsys.readouterr().err


def test_run_builds_finder_verifier_and_poc_providers(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng

    providers = []

    def fake_make_provider(name, **kwargs):
        provider = MockProvider(default='{"findings": []}')
        providers.append(provider)
        return provider

    def fake_run(target, workspace, *, options):
        assert options.execution.on_native_analysis is not None
        assert options.execution.on_facts_resolution is not None
        assert options.execution.on_unit_plan is not None
        assert options.execution.on_grounding is not None
        native_analysis = _native_analysis()
        options.execution.on_native_analysis(native_analysis)
        facts_resolution = _facts_resolution(native_analysis)
        options.execution.on_facts_resolution(facts_resolution)
        unit_plan = _unit_plan(facts_resolution)
        options.execution.on_unit_plan(unit_plan)
        options.execution.on_grounding(
            GroundingReceipt.create(unit_plan=unit_plan, contexts=()),
            0,
        )
        fake_run.poc_backend = options.output.poc_backend
        verify = VerifyResult()
        acc = SimpleNamespace(findings=[], errors=0)
        scaffold = SimpleNamespace(workspace=str(tmp_path))
        outcome = _fake_repository_outcome(options)
        findings_artifact, outcome_artifact = _empty_repository_artifacts(target, outcome)
        return SimpleNamespace(
            scaffold=scaffold,
            accumulator=acc,
            verify=verify,
            units=1,
            outcome=outcome,
            findings_artifact=findings_artifact,
            outcome_artifact=outcome_artifact,
            poc_failures=(),
        )

    monkeypatch.setattr(provider_configuration_module, "make_provider", fake_make_provider)
    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    _seed_web_profile(tmp_path)
    assert (
        main(
            [
                "review",
                "repository",
                str(tmp_path),
                "--run",
                "--poc",
                "--api-key",
                "k",
            ]
        )
        == 0
    )
    assert fake_run.poc_backend is not None
    assert len(providers) == 3


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
    assert captured["options"].execution.concurrency == expected
    assert captured["options"].verification.concurrency == expected


def _patch_run(monkeypatch, tmp_path, *, errors, failure_reason="", verify=None):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    _seed_web_profile(tmp_path)

    def fake_run(target, workspace, **kw):
        options = kw["options"]
        assert options.execution.on_native_analysis is not None
        assert options.execution.on_facts_resolution is not None
        assert options.execution.on_unit_plan is not None
        assert options.execution.on_grounding is not None
        native_analysis = _native_analysis()
        options.execution.on_native_analysis(native_analysis)
        facts_resolution = _facts_resolution(native_analysis)
        options.execution.on_facts_resolution(facts_resolution)
        unit_plan = _unit_plan(facts_resolution)
        options.execution.on_unit_plan(unit_plan)
        options.execution.on_grounding(
            GroundingReceipt.create(unit_plan=unit_plan, contexts=()),
            0,
        )
        scaffold = SimpleNamespace(workspace=str(tmp_path))
        acc = SimpleNamespace(findings=[], errors=errors)
        outcome = _fake_repository_outcome(
            options,
            complete=not errors,
            degraded=bool(errors),
            failure_reason=failure_reason,
        )
        findings_artifact, outcome_artifact = _empty_repository_artifacts(target, outcome)
        return SimpleNamespace(
            scaffold=scaffold,
            accumulator=acc,
            verify=verify,
            units=1,
            outcome=outcome,
            findings_artifact=findings_artifact,
            outcome_artifact=outcome_artifact,
            poc_failures=(),
        )

    monkeypatch.setattr(eng, "run_repository_review", fake_run)


def test_run_with_failed_calls_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    _patch_run(
        monkeypatch,
        tmp_path,
        errors=2,
        failure_reason="RuntimeError: provider rate limited",
    )
    rc = main(["review", "repository", str(tmp_path), "--run"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "review step(s) failed" in err
    assert "RuntimeError: provider rate limited" in err


def test_run_verify_errors_exit_nonzero_and_ask_to_rerun(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, tmp_path, errors=0, verify=VerifyResult(errors=1))
    rc = main(["review", "repository", str(tmp_path), "--run"])
    assert rc == 1
    assert "re-run to retry" in capsys.readouterr().err


def test_unlocatable_warning_uses_singular_finding(capsys):
    climod._warn_unlocatable(SimpleNamespace(unlocatable=[SimpleNamespace(title="ghost", file="ghost.py")]))
    err = capsys.readouterr().err
    assert "1 finding cites" in err
    assert "so it was kept" in err


def test_run_has_no_confirmer_when_the_confirmer_is_the_finder(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch, tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--run",
            "--api-key",
            "basekey",
            "--skeptic-provider",
            "openai",
            "--skeptic-model",
            "gpt-x",
            "--skeptic-api-key",
            "k",
        ]
    )
    assert not captured["options"].verification.confirmers


def test_executor_flag_is_removed(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--run", "--reviewer", "model"])
    assert exc.value.code == 2
    assert "--reviewer" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--run", "--executor", "api"])
    assert exc.value.code == 2
    assert "--executor" in capsys.readouterr().err


def test_abbreviated_live_flag_is_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--run", "--conc", "2"])
    assert exc.value.code == 2


def test_timeout_flag_is_accepted(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert (
        main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run", "--timeout", "5"])
        == 0
    )


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
        ["--gate", "--provider", "openai"],
        ["--gate", "--confirmer-model=unused-model"],
        ["--gate", "--fresh"],
        ["--scaffold", "--concurrency", "2"],
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


def _capture_run(monkeypatch, repository):
    import cyberjury.review.repository.engine as eng

    captured = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    _seed_web_profile(repository)

    def fake_run(target, workspace, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    return captured


def test_repository_run_uses_the_finder_seat(monkeypatch, tmp_path):
    """Repository run reviews with the finder seat and its seat provenance label."""
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run"])
    options = captured["options"]
    assert options.roles.provider is not None
    assert options.roles.finder_label.startswith("seat-")


def test_run_defaults_concurrency_to_eight(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["options"].execution.concurrency == 8
    assert captured["options"].verification.concurrency == 8


def test_explicit_concurrency_overrides_the_backend_default(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch, tmp_path)
    main(["review", "repository", str(tmp_path), "--run", "--concurrency", "9"])
    assert captured["options"].execution.concurrency == 9
    assert captured["options"].verification.concurrency == 9


def test_repository_stages_record_a_whole_pipeline_timeline(tmp_path):
    from cyberjury.telemetry import TIMELINE_FILE

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    project = _repository_project(ws, repo)
    timeline = project / TIMELINE_FILE
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]
    review = project.parents[1]
    unit_plan = json.loads((review / "units.json").read_text())
    grounding = json.loads((review / "grounding.json").read_text())
    assert grounding["unit_plan_receipt_sha256"] == unit_plan["receipt_sha256"]
    events = [
        json.loads(line)["operation"]
        for line in next((review / "attempts").glob("attempt-*/events.jsonl")).read_text().splitlines()
    ]
    assert events.index("units.planned") < events.index("grounding.prepared")
    assert "provider.route.resolved" not in events

    main(["review", "repository", str(repo), "--workspace", str(ws), "--gate"])
    stages = json.loads(timeline.read_text())
    assert [r["stage"] for r in stages] == ["scaffold", "gate"]
    assert all(r["ok"] and isinstance(r["seconds"], (int, float)) for r in stages)

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]


def test_diff_observable_request_matches_engine_options(monkeypatch, diff_target, tmp_path):
    captured = {}

    def fake_review(_diff, *, options, **_kwargs):
        captured["options"] = options
        return _fake_diff_result(options)

    monkeypatch.setattr(diff_checkout, "run_diff_review", fake_review)
    assert (
        main(
            [
                "review",
                "diff",
                *diff_target.args,
                "--workspace",
                str(tmp_path),
                "--concurrency",
                "5",
                "--api-key",
                "secret-canary",
            ]
        )
        == 0
    )
    review_dir = next((tmp_path / "reviews").iterdir())
    attempt_dir = next((review_dir / "attempts").iterdir())
    request = json.loads((attempt_dir / "request.json").read_text())
    model_calls = json.loads((attempt_dir / "model-calls.json").read_text())
    scheduling = json.loads((attempt_dir / "scheduling.json").read_text())
    verification = json.loads((attempt_dir / "verification.json").read_text())
    options = captured["options"]

    assert "schedule" not in request
    assert request["providers"]["roles"]["finder"] is not None
    assert request["concurrency"]["review"] == options.execution.concurrency == 5
    assert request["concurrency"]["verification"] == options.verification.concurrency == 5
    assert model_calls["schema"] == "cyberjury.model-calls/v7"
    assert verification["enabled"] is True
    assert verification["candidate_ids"] == []
    assert verification["decisions"] == []
    assert model_calls["calls"] == []
    assert scheduling["schema"] == "cyberjury.scheduling/v3"
    assert scheduling["stop_reason"] == "complete"
    assert "secret-canary" not in "".join(path.read_text() for path in review_dir.rglob("*.json*"))


def test_diff_dry_run_persists_matching_schedule_and_call_units(diff_target, tmp_path):
    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]) == 0
    attempt = next(next((tmp_path / "reviews").iterdir()).joinpath("attempts").iterdir())
    scheduling = json.loads((attempt / "scheduling.json").read_text())
    model_calls = json.loads((attempt / "model-calls.json").read_text())

    assert scheduling["stop_reason"] == "complete"
    assert scheduling["unit_ids"]
    assert model_calls["calls"]
    assert all(call["unit_id"] in scheduling["unit_ids"] for call in model_calls["calls"])
    assert all("round" not in call for call in model_calls["calls"])
    assert all(call["trigger"] in {"initial_judgment", "evidence_followup"} for call in model_calls["calls"])
    assert all(call["navigation_status"] == "not_requested" for call in model_calls["calls"])
    assert all(call["navigation_delta_chars"] == 0 for call in model_calls["calls"])


def test_repository_dry_run_persists_matching_schedule_and_call_units(tmp_path):
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
    scheduling = json.loads((attempt / "scheduling.json").read_text())
    model_calls = json.loads((attempt / "model-calls.json").read_text())

    assert scheduling["stop_reason"] == "complete"
    assert model_calls["calls"]
    assert all(call["unit_id"] in scheduling["unit_ids"] for call in model_calls["calls"])
    assert all("round" not in call for call in model_calls["calls"])
    assert all(call["navigation_status"] == "not_requested" for call in model_calls["calls"])


def test_repository_actions_share_review_with_distinct_attempts(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    state_root = tmp_path / "state"

    assert main(["review", "repository", str(repository), "--workspace", str(state_root), "--scaffold"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(state_root), "--gate"]) == 1

    reviews = list((state_root / "reviews").iterdir())
    assert len(reviews) == 1
    attempts = sorted((reviews[0] / "attempts").iterdir())
    assert len(attempts) == 2
    actions = [json.loads((attempt / "request.json").read_text())["action"] for attempt in attempts]
    assert sorted(actions) == ["gate", "scaffold"]
    gate = next(
        attempt for attempt in attempts if json.loads((attempt / "request.json").read_text())["action"] == "gate"
    )
    assert json.loads((gate / "status.json").read_text())["state"] == "complete"
    assert json.loads((gate / "events.jsonl").read_text().splitlines()[-1])["payload"]["data"]["exit_code"] == 1


def test_provider_preflight_failure_is_terminal_and_redacted(monkeypatch, diff_target, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path)])

    review_dir = next((tmp_path / "reviews").iterdir())
    attempt_dir = next((review_dir / "attempts").iterdir())
    status = json.loads((attempt_dir / "status.json").read_text())
    event = json.loads((attempt_dir / "events.jsonl").read_text().splitlines()[-1])
    assert status["state"] == "failed"
    assert event["operation"] == "attempt.failed"
    assert "authorization=" not in json.dumps(event).lower()


def test_model_call_persistence_failure_marks_the_attempt_failed(monkeypatch, diff_target, tmp_path):
    monkeypatch.setattr(climod, "_dispatch_review_action", _complete_stage_one_only)

    def fail_record(_args):
        raise RuntimeError("model call artifact failed")

    monkeypatch.setattr(climod, "_record_model_calls", fail_record)

    assert main(["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]) == 1

    review = next((tmp_path / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    status = json.loads((attempt / "status.json").read_text())
    event = json.loads((attempt / "events.jsonl").read_text().splitlines()[-1])
    assert status["state"] == "failed"
    assert event["operation"] == "attempt.failed"


@pytest.mark.parametrize("scope", ["diff", "repository"])
def test_stage_one_request_is_shared_across_target_and_profile(
    monkeypatch,
    tmp_path,
    scope,
):
    captured = {}

    def fake_dispatch(run):
        captured["request"] = run.request
        captured["intent"] = run.session.intent
        captured["workspace"] = run.session.workspace.path
        return _complete_stage_one_only(run)

    monkeypatch.setattr(climod, "_dispatch_review_action", fake_dispatch)
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "commit", "--quiet", "--allow-empty", "-m", "base")
    base_revision = _git(repository, "rev-parse", "HEAD")
    (repository / "app.py").write_text("source\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "head")
    target_args = (
        ["diff", "--repository", str(repository), "--git-range", f"{base_revision}..HEAD", "--dry-run"]
        if scope == "diff"
        else ["repository", str(repository), "--run", "--dry-run"]
    )

    assert (
        main(
            [
                "review",
                *target_args,
                "--profile",
                "web",
                "--workspace",
                str(tmp_path / "state"),
            ]
        )
        == 0
    )
    request = captured["request"]
    assert captured["intent"].target.kind == scope
    assert captured["intent"].requested_profile == "web"
    assert request.providers.finder_seat_id is not None
    target_artifact = json.loads((captured["workspace"] / "target.json").read_text())
    snapshot_artifact = json.loads((captured["workspace"] / "snapshot.json").read_text())
    profile_artifact = json.loads((captured["workspace"] / "profile.json").read_text())
    analysis_artifact = json.loads((captured["workspace"] / "analysis.json").read_text())
    facts_artifact = json.loads((captured["workspace"] / "facts.json").read_text())
    units_artifact = json.loads((captured["workspace"] / "units.json").read_text())
    assert target_artifact["schema"] == "cyberjury.resolved-target/v1"
    assert snapshot_artifact["schema"] == "cyberjury.source-snapshot/v1"
    assert profile_artifact["schema"] == "cyberjury.profile-binding/v4"
    assert profile_artifact["name"] == "web"
    assert analysis_artifact["schema"] == "cyberjury.native-analysis/v1"
    assert facts_artifact["schema"] == "cyberjury.facts-resolution/v1"
    assert units_artifact["schema"] == "cyberjury.unit-plan/v2"


@pytest.mark.parametrize("scope", ["diff", "repository"])
def test_auto_profile_uses_the_complete_snapshot_for_web_repositories(monkeypatch, tmp_path, scope):
    captured = {}

    def fake_dispatch(run):
        captured["profile"] = run.profile.name
        return _complete_stage_one_only(run)

    monkeypatch.setattr(climod, "_dispatch_review_action", fake_dispatch)
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    (repository / "app.py").write_text("def run():\n    return True\n")
    (repository / "pyproject.toml").write_text("[project]\nname = 'sample'\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "base")
    base_revision = _git(repository, "rev-parse", "HEAD")
    (repository / "views.py").write_text("from app import run\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "deployment script")
    target_args = (
        ["diff", "--repository", str(repository), "--git-range", f"{base_revision}..HEAD", "--dry-run"]
        if scope == "diff"
        else ["repository", str(repository), "--run", "--dry-run"]
    )

    assert main(["review", *target_args, "--workspace", str(tmp_path / "state")]) == 0
    assert captured["profile"] == "web"


def test_unknown_auto_profile_fails_before_provider_routing(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("unknown target\n")
    state = tmp_path / "state"

    assert main(["review", "repository", str(repository), "--run", "--dry-run", "--workspace", str(state)]) == 1

    review = next((state / "reviews").iterdir())
    attempt = next((review / "attempts").iterdir())
    operations = [json.loads(line)["operation"] for line in (attempt / "events.jsonl").read_text().splitlines()]
    assert (review / "target.json").is_file()
    assert (review / "snapshot.json").is_file()
    assert not (review / "profile.json").exists()
    assert "provider.route.resolved" not in operations
    assert operations[-1] == "attempt.failed"


def test_diff_runs_get_independent_review_sessions(monkeypatch, diff_target, tmp_path):
    monkeypatch.setattr(climod, "_dispatch_review_action", _complete_stage_one_only)
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
    monkeypatch.setattr(climod, "_dispatch_review_action", _complete_stage_one_only)
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n")
    base = ["review", "repository", str(repository), "--run", "--workspace", str(tmp_path / "state")]

    assert main([*base, "--api-key", "key", "--model", "model-a"]) == 0
    assert main([*base, "--api-key", "key", "--model", "model-b"]) == 1
    assert "--fresh" in capsys.readouterr().err
    assert main([*base, "--api-key", "key", "--model", "model-b", "--fresh"]) == 0

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
                "--gate",
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


def test_gate_without_active_review_does_not_create_a_session(tmp_path, capsys):
    repository = tmp_path / "repo"
    repository.mkdir()
    state = tmp_path / "state"

    assert main(["review", "repository", str(repository), "--gate", "--workspace", str(state)]) == 1

    assert "no active session" in capsys.readouterr().err
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
    _git(repository, "init", "--quiet")
    _git(repository, "commit", "--quiet", "--allow-empty", "-m", "base")
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
    assert json.loads((attempt / "status.json").read_text())["state"] == "failed"
    assert not (review / "target.json").exists()
