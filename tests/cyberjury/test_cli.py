"""CLI tests cover command parsing, provider configuration, and dispatch."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers.mock import MockProvider
from cyberjury.review.context import GroundingContext, GroundingCoverage
from cyberjury.review.diff.model import diff_units
from cyberjury.review.failures import ReviewUnitFailure
from cyberjury.review.request import ReviewIntent, TargetInput
from cyberjury.review.session import ReviewSession
from cyberjury.review.target import GitTarget, PatchArtifact, ResolvedTarget
from cyberjury.sources.snapshot import SourceSnapshot


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


def test_old_audit_command_is_gone(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--dry-run"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


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
    assert "--profile auto|web|evm" in claude.read_text()
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


def _repository_project(state_root: Path, repository: Path, profile: str = "auto") -> Path:
    intent = ReviewIntent(
        target=TargetInput(kind="repository", repository=str(repository.resolve())),
        requested_profile=profile,
    )
    locator = json.loads((state_root / "locators" / "reviews" / f"{intent.intent_sha256}.json").read_text())
    return state_root / "reviews" / locator["session_id"] / "work" / repository.name


def _complete_stage_one_only(args) -> int:
    if args._review_attempt.request.providers is not None:
        climod._record_provider_route(args)
    return 0


def _activate_repository_review(state_root: Path, repository: Path) -> None:
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


def test_diff_adversarial_resolves_each_seat_independently(monkeypatch, diff_target):
    captured = {}

    def fake_audit(diff, *, options, **kw):
        captured.update(
            finder=options.roles.finder_provider,
            challenger=options.roles.challenger_provider,
            judge=options.roles.judge_provider,
        )
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    rc = main(
        [
            "review",
            "diff",
            *diff_target.args,
            "--mode",
            "adversarial",
            "--api-key",
            "k",
            "--challenger-provider",
            "openai",
            "--challenger-api-key",
            "k2",
        ]
    )
    assert rc == 0
    assert captured["finder"] is not captured["challenger"]
    assert captured["judge"] is not captured["challenger"]


def test_diff_standard_uses_the_finder_seat_when_it_is_overridden(monkeypatch):
    """The single pass must honor finder-specific backend overrides."""
    from argparse import Namespace

    captured = {}

    def fake_create(configuration, mode, *, meter=None):
        captured["configuration"] = configuration
        captured["mode"] = mode
        return climod.DiffProviders(
            base_provider=object(),
            base_model=configuration.finder.model,
            finder_provider=object(),
            finder_model=configuration.finder.model,
        )

    monkeypatch.setattr(climod, "create_diff_providers", fake_create)
    args = Namespace(
        provider="anthropic",
        model="base",
        api_key="k",
        api_base=None,
        wire_api="chat",
        finder_provider=None,
        finder_model="finder",
        finder_api_key=None,
        finder_api_base=None,
        finder_wire_api=None,
        challenger_provider=None,
        challenger_model=None,
        challenger_api_key=None,
        challenger_api_base=None,
        challenger_wire_api=None,
        judge_provider=None,
        judge_model=None,
        judge_api_key=None,
        judge_api_base=None,
        judge_wire_api=None,
        mode="standard",
        retries=0,
        timeout=10,
    )

    providers = climod._build_diff_providers(args)

    assert providers.base_model == "finder"
    assert providers.finder_model == "finder"
    assert providers.challenger_provider is None
    assert providers.judge_provider is None
    assert captured["configuration"].finder.model == "finder"
    assert captured["mode"] == "standard"


def _role_args(**over):
    from argparse import Namespace

    base = {"provider": "anthropic", "model": "claude-base", "api_key": "basekey", "api_base": None, "wire_api": "chat"}
    for role in ("finder", "challenger", "judge"):
        for field in ("provider", "model", "api_key", "api_base", "wire_api"):
            base[f"{role}_{field}"] = None
    base.update(over)
    return Namespace(**base)


def test_role_spec_inherits_base_when_unset():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args()
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-base", "basekey")


def test_base_seat_wire_flows_and_role_inherits_it():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(wire_api="responses")
    base = _base_spec(a)
    assert base.wire_api == "responses"
    assert _role_spec(a, "challenger", base).wire_api == "responses"


def test_role_spec_cross_vendor_override_drops_base_provider_specific_fields():
    """A provider switch must not carry vendor-specific base settings into the role."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(
        api_base="https://anthropic.example.test",
        wire_api="chat",
        challenger_provider="openai",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model) == ("openai", "gpt-5.6")
    assert s.api_key is None
    assert s.api_base is None
    assert s.wire_api is None


def test_role_spec_cross_vendor_keeps_explicit_role_fields():
    """Role fields stay authoritative when the role intentionally changes provider."""
    from cyberjury.cli import _base_spec, _role_spec
    from cyberjury.providers.configuration import ProviderSeat

    a = _role_args(
        challenger_provider="openai",
        challenger_model="gpt-x",
        challenger_api_key="role-key",
        challenger_api_base="https://openai.example.test",
        challenger_wire_api="responses",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert s == ProviderSeat(
        provider="openai",
        model="gpt-x",
        api_key="role-key",
        api_base="https://openai.example.test",
        wire_api="responses",
    )


def test_role_spec_same_vendor_override_keeps_base_key():
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(challenger_model="claude-other")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s.provider, s.model, s.api_key) == ("anthropic", "claude-other", "basekey")


def test_confirmers_exclude_the_skeptic_and_dedupe(monkeypatch):
    from argparse import Namespace

    from cyberjury.cli import _confirmers
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    a = Namespace(retries=0, timeout=10)
    chal = ProviderSeat(provider="anthropic", model="skep", api_key="k", wire_api="chat")
    jud = ProviderSeat(provider="anthropic", model="judge", api_key="k", wire_api="chat")
    fnd = ProviderSeat(provider="anthropic", model="judge", api_key="k", wire_api="chat")
    confirmers = _confirmers(a, challenger=chal, judge=jud, finder=fnd)
    assert [label for label, _ in confirmers] == ["judge"]
    same = ProviderSeat(provider="anthropic", model="skep", api_key="k", wire_api="chat")
    assert _confirmers(a, challenger=chal, judge=same, finder=same) == []


def test_key_reachable_by_explicit_key_or_vendor_env(monkeypatch):
    from cyberjury.cli import _key_reachable
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _key_reachable(ProviderSeat(provider="anthropic", model="m", api_key="k"))
    assert not _key_reachable(ProviderSeat(provider="anthropic", model="m"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    assert _key_reachable(ProviderSeat(provider="anthropic", model="m"))
    assert not _key_reachable(ProviderSeat(provider="openai", model="m"))


def test_require_key_errors_loud_at_startup_on_a_missing_key(monkeypatch):
    from cyberjury.cli import _require_key
    from cyberjury.providers.configuration import ProviderSeat

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        _require_key(ProviderSeat(provider="openai", model="m"))
    _require_key(ProviderSeat(provider="anthropic", model="m", api_key="k"))


def test_note_verify_route_states_the_active_route(capsys):
    from argparse import Namespace

    from cyberjury.cli import _note_verify_route

    args = Namespace(verify=True, dry_run=False)
    _note_verify_route(args, [("m1", object()), ("m2", object())])
    out = capsys.readouterr().err
    assert "skeptic plus 2 confirmers" in out
    _note_verify_route(args, [("m1", object())])
    assert "skeptic plus 1 confirmer," in capsys.readouterr().err
    _note_verify_route(args, [])
    assert "keep-all" in capsys.readouterr().err
    _note_verify_route(Namespace(verify=True, dry_run=True), [])
    assert "Verify route" not in capsys.readouterr().err


_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_DIFF = _FILE_A


def test_review_diff_dry_run_uses_repository_grounding(capsys, diff_target):
    rc = main(["review", "diff", *diff_target.args, "--dry-run"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


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


def test_review_diff_auto_profile_parses_quoted_solidity_path(tmp_path):
    patch = (
        'diff --git "a/Token Contract.sol" "b/Token Contract.sol"\n'
        '--- "a/Token Contract.sol"\n'
        '+++ "b/Token Contract.sol"\n'
        "@@ -1 +1 @@\n-old\n+new\n"
    )
    revision = "a" * 40
    state = climod._prepare_diff_command(
        SimpleNamespace(
            dry_run=True,
            repository="repo",
            git_range="base..HEAD",
            profile="auto",
            _resolved_target=ResolvedTarget(
                kind="diff",
                repository_root=str(tmp_path.resolve()),
                git=GitTarget(
                    object_format="sha1",
                    requested_range="base..HEAD",
                    range_kind="two-dot",
                    left_revision=revision,
                    right_revision=revision,
                    patch_base_revision=revision,
                ),
                patch=PatchArtifact.from_text(patch),
            ),
        )
    )

    assert state.profile.name == "evm"


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
        source_snapshot = SourceSnapshot.capture(repo, ("a.py",))

        @staticmethod
        def prepare(diff):
            context = GroundingContext(text="repository source", source="repository")
            return [replace(unit, grounding=context) for unit in diff_units(diff)]

    monkeypatch.setattr(climod, "build_diff_context_collector", lambda *args, **kwargs: Collector())
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
    assert json.loads(captured.out)["findings"] == []
    assert "grounded diff context for 1 changed source file" in captured.err


def test_review_diff_closes_its_backends(monkeypatch, diff_target):
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=spy, base_model="mock"),
    )
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False)),
    )
    assert main(["review", "diff", *diff_target.args, "--api-key", "k"]) == 0
    assert closed == [True]


def test_close_backends_dedupes_same_object_by_identity():
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    climod._close_backends(spy, spy, None)
    assert closed == [True]


def test_review_diff_collects_context_and_verifies(monkeypatch, diff_target):
    seen = {}

    class _Collector:
        review_paths = ("app.py",)
        source_snapshot = None

        def prepare(self, diff_text):
            seen["context_diff"] = diff_text
            return [SimpleNamespace(grounding=SimpleNamespace(text="source context"))]

    def fake_audit(*args, **kwargs):
        options = kwargs["options"]
        seen["context"] = options.grounding.prepare_diff(_DIFF)[0].grounding.text
        seen["verification_root"] = options.verification.root
        seen["verifier"] = options.verification.verifier
        seen["verification_confirmers"] = options.verification.confirmers
        seen["verification_found_by"] = options.verification.found_by
        seen["verification_concurrency"] = options.verification.concurrency
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    def fake_context_collector(root, profile, *, review_diff=""):
        seen["review_diff"] = review_diff
        collector = _Collector()
        collector.source_snapshot = climod.capture_source_snapshot(root)
        return collector

    monkeypatch.setattr(climod, "build_diff_context_collector", fake_context_collector)
    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=MockProvider(default="{}"), base_model="mock"),
    )
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert main(["review", "diff", *diff_target.args, "--api-key", "k"]) == 0
    assert seen["context"] == "source context"
    assert "diff --git a/a.py b/a.py" in seen["review_diff"]
    assert "+x = 1" in seen["review_diff"]
    assert Path(seen["verification_root"]).name == diff_target.repository.name
    assert not Path(seen["verification_root"]).exists()
    assert seen["verifier"] is not None
    assert seen["verification_confirmers"] == ()
    assert seen["verification_found_by"] == ("claude-opus-5",)
    assert seen["verification_concurrency"] == 8


def test_review_diff_standard_uses_distinct_judge_and_finder_confirmers(monkeypatch, diff_target):
    """A standard diff finder cannot also approve deleting its own finding."""
    seen = {}

    def fake_audit(*args, **kwargs):
        verification = kwargs["options"].verification
        seen["verification_confirmers"] = verification.confirmers
        seen["verification_found_by"] = verification.found_by
        seen["verification_concurrency"] = verification.concurrency
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(base_provider=MockProvider(default="{}"), base_model="finder"),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

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
                "--challenger-model",
                "skeptic",
                "--judge-model",
                "judge",
                "--concurrency",
                "4",
            ]
        )
        == 0
    )
    assert [label for label, _checker in seen["verification_confirmers"]] == ["judge", "finder"]
    assert seen["verification_found_by"] == ("finder",)
    assert seen["verification_concurrency"] == 4


def test_review_diff_adversarial_uses_finder_as_a_provenance_aware_confirmer(monkeypatch, diff_target):
    """Adversarial provenance lets the finder confirm only findings it did not surface."""
    seen = {}

    def fake_audit(*args, **kwargs):
        verification = kwargs["options"].verification
        seen["verification_confirmers"] = verification.confirmers
        seen["verification_found_by"] = verification.found_by
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "_build_diff_providers",
        lambda args: climod.DiffProviders(
            base_provider=MockProvider(default="{}"),
            base_model="finder",
            finder_provider=MockProvider(default="{}"),
            finder_model="finder",
            challenger_provider=MockProvider(default="{}"),
            challenger_model="skeptic",
            judge_provider=MockProvider(default="{}"),
            judge_model="judge",
        ),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                *diff_target.args,
                "--mode",
                "adversarial",
                "--api-key",
                "k",
                "--finder-model",
                "finder",
                "--challenger-model",
                "skeptic",
                "--judge-model",
                "judge",
            ]
        )
        == 0
    )
    assert [label for label, _checker in seen["verification_confirmers"]] == ["judge", "finder"]
    assert seen["verification_found_by"] == ()


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
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_diff_adversarial_rounds_flow_into_audit(monkeypatch, diff_target):
    captured = {}

    def fake_audit(diff, *, options, **kw):
        captured["mode"] = options.roles.mode
        captured["max_rounds"] = options.roles.max_rounds
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    assert main(["review", "diff", *diff_target.args, "--mode", "adversarial", "--rounds", "5", "--api-key", "k"]) == 0
    assert captured == {"mode": "adversarial", "max_rounds": 5}


def test_diff_degraded_audit_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys, diff_target, tmp_path):
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=True)),
    )
    rc = main(
        [
            "review",
            "diff",
            *diff_target.args,
            "--workspace",
            str(tmp_path),
            "--mode",
            "adversarial",
            "--api-key",
            "k",
        ]
    )
    assert rc == 1
    assert "degraded" in capsys.readouterr().err
    attempt = next(next((tmp_path / "reviews").iterdir()).joinpath("attempts").iterdir())
    assert json.loads((attempt / "status.json").read_text())["state"] == "incomplete"


def test_diff_degraded_audit_surfaces_grounding_limitations(monkeypatch, capsys, diff_target):
    grounding = GroundingCoverage(limitations=("facts:app.ts:3:8",))
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(
            outcome=SimpleNamespace(findings=[], failures=[], degraded=True, grounding=grounding)
        ),
    )
    rc = main(["review", "diff", *diff_target.args, "--mode", "standard", "--api-key", "k"])

    assert rc == 1
    assert "structured facts unavailable: facts:app.ts:3:8" in capsys.readouterr().err


def test_diff_degraded_audit_surfaces_failed_batch_details(monkeypatch, capsys, diff_target):
    """Large diff failures include batch paths before the generic degraded error."""

    def fake_audit(*args, **kwargs):
        return SimpleNamespace(
            outcome=SimpleNamespace(
                findings=[],
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
        )

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
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


def test_review_repository_writes_methodology_to_workspace(tmp_path):
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (_repository_project(ws, repository) / "methodology.md").is_file()


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
    for combo in (["--run", "--gate"], ["--run", "--finalize"], ["--finalize", "--gate"]):
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


def test_finalize_wires_challenger_skeptic_and_judge_confirmer(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.verification import ModelRefutationChecker, ModelVerifier

    captured = {}

    def fake_finalize(target, workspace, *, options):
        captured["verifier"] = options.verification.verifier
        captured["confirmers"] = options.verification.confirmers
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    rc = main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--finalize",
            "--workspace",
            str(state),
            "--api-key",
            "basekey",
            "--challenger-provider",
            "openai",
            "--challenger-model",
            "gpt-x",
            "--challenger-api-key",
            "k",
            "--judge-provider",
            "anthropic",
            "--judge-model",
            "claude-x",
            "--judge-api-key",
            "k2",
        ]
    )
    assert rc == 0
    assert isinstance(captured["verifier"], ModelVerifier)
    assert captured["verifier"]._model == "gpt-x"
    ((label, checker),) = captured["confirmers"]
    assert label == "claude-x"
    assert isinstance(checker, ModelRefutationChecker)
    assert checker._model == "claude-x"


def test_finalize_default_has_no_confirmer_and_notes_keep_all(monkeypatch, tmp_path, capsys):
    import cyberjury.review.repository.engine as eng

    def fake_finalize(target, workspace, *, options):
        fake_finalize.confirmers = options.verification.confirmers
        fake_finalize.poc_backend = options.output.poc_backend
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    rc = main(["review", "repository", str(tmp_path), "--finalize", "--workspace", str(state)])
    assert rc == 0
    assert fake_finalize.confirmers == ()
    assert fake_finalize.poc_backend is not None
    out = capsys.readouterr()
    assert "keep-all" in out.err
    assert "PoC reconciliation" not in out.out


def test_finalize_closes_api_verifier_and_poc_providers(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng

    class ProviderWithClose(MockProvider):
        def __init__(self):
            super().__init__(default='{"real": true, "reason": ""}')
            self.closed = 0

        def close(self):
            self.closed += 1

    providers = []

    def fake_role_provider(args, spec):
        provider = ProviderWithClose()
        providers.append(provider)
        return provider

    monkeypatch.setattr(climod, "_role_provider", fake_role_provider)
    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    assert main(["review", "repository", str(tmp_path), "--finalize", "--workspace", str(state)]) == 0
    assert [p.closed for p in providers] == [1, 1]


def test_run_closes_api_role_verifier_and_poc_providers(monkeypatch, tmp_path):
    import cyberjury.review.repository.engine as eng

    class ProviderWithClose(MockProvider):
        def __init__(self):
            super().__init__(default='{"findings": []}')
            self.closed = 0

        def close(self):
            self.closed += 1

    providers = []

    def fake_role_provider(args, spec):
        provider = ProviderWithClose()
        providers.append(provider)
        return provider

    def fake_run(target, workspace, *, options):
        fake_run.poc_backend = options.output.poc_backend
        verify = SimpleNamespace(retained=[], verified=[], refuted=[], errors=0, unlocatable=[])
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=True, errors=0)
        scaffold = SimpleNamespace(fallback_note="", workspace=str(tmp_path))
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=verify, units=1)

    monkeypatch.setattr(climod, "_role_provider", fake_role_provider)
    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    assert main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial", "--api-key", "k"]) == 0
    assert fake_run.poc_backend is not None
    assert len(providers) == 5
    assert [p.closed for p in providers] == [1, 1, 1, 1, 1]


def test_repository_run_preparation_closes_partial_resources(monkeypatch):
    class CloseSpy:
        def __init__(self):
            self.closed = 0

        def close(self):
            self.closed += 1

    seat = climod.ProviderSeat(provider="anthropic", model="m", api_key="k")
    shared = CloseSpy()
    finder = CloseSpy()
    resources = climod._RepositoryResources(
        profile=climod.resolve_profile("web"),
        base=seat,
        finder=seat,
        challenger=seat,
        judge=seat,
        verifier=shared,
    )
    calls = 0

    def create(*_args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("challenger unavailable")
        return finder

    monkeypatch.setattr(climod, "_prepare_repository_resources", lambda *a, **k: resources)
    monkeypatch.setattr(climod, "_require_key", lambda _seat: None)
    monkeypatch.setattr(climod, "_role_provider", create)

    with pytest.raises(RuntimeError, match="challenger unavailable"):
        climod._prepare_repository_run_resources(SimpleNamespace(dry_run=False, mode="adversarial"))

    assert finder.closed == 1
    assert shared.closed == 1


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--api-key", "k"], 8),
        (["--api-key", "k", "--concurrency", "4"], 4),
    ],
)
def test_finalize_concurrency_uses_the_api_default(monkeypatch, tmp_path, args, expected):
    import cyberjury.review.repository.engine as eng

    captured = {}

    def fake_finalize(target, workspace, *, options):
        captured["concurrency"] = options.verification.concurrency
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    assert main(["review", "repository", str(tmp_path), "--finalize", "--workspace", str(state), *args]) == 0
    assert captured["concurrency"] == expected


def test_finalize_mentions_pocs_only_when_the_file_exists(monkeypatch, tmp_path, capsys):
    import cyberjury.review.repository.engine as eng

    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "_pocs.md").write_text("# PoC Reconciliation\n", encoding="utf-8")
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    main(["review", "repository", str(tmp_path), "--finalize", "--workspace", str(state)])
    assert f"PoC reconciliation in {tmp_path}/_pocs.md" in capsys.readouterr().out


def _patch_run(monkeypatch, tmp_path, *, converged, errors, failure_reason=""):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_run(target, workspace, **kw):
        scaffold = SimpleNamespace(fallback_note="", workspace=str(tmp_path))
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=converged, errors=errors)
        outcome = SimpleNamespace(findings=[], degraded=bool(errors) or not converged, failure_reason=failure_reason)
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=None, units=1, outcome=outcome)

    monkeypatch.setattr(eng, "run_repository_review", fake_run)


def test_run_with_failed_calls_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    _patch_run(
        monkeypatch,
        tmp_path,
        converged=True,
        errors=2,
        failure_reason="RuntimeError: provider rate limited",
    )
    rc = main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "review step(s) failed" in err
    assert "RuntimeError: provider rate limited" in err
    assert "did not converge" not in err


def test_run_that_did_not_converge_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    _patch_run(monkeypatch, tmp_path, converged=False, errors=0)
    rc = main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "did not converge" in err
    assert "model calls failed" not in err


def test_finalize_verify_errors_exit_nonzero_and_ask_to_resume(monkeypatch, tmp_path, capsys):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_finalize(target, workspace, **kw):
        verify = SimpleNamespace(retained=[], verified=[], refuted=[], errors=1)
        outcome = SimpleNamespace(complete=False)
        return SimpleNamespace(parsed=0, deduped=0, workspace=str(tmp_path), verify=verify, outcome=outcome)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    state = tmp_path.parent / f"{tmp_path.name}-state"
    _activate_repository_review(state, tmp_path)
    rc = main(["review", "repository", str(tmp_path), "--finalize", "--workspace", str(state)])
    assert rc == 1
    assert "Re-run to resume" in capsys.readouterr().err


def test_unlocatable_warning_uses_singular_finding(capsys):
    climod._warn_unlocatable(SimpleNamespace(unlocatable=[SimpleNamespace(title="ghost", file="ghost.py")]))
    err = capsys.readouterr().err
    assert "1 finding cites" in err
    assert "so it was kept" in err


def test_run_passes_confirmers_and_no_extra_finders(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--run",
            "--api-key",
            "basekey",
            "--challenger-provider",
            "openai",
            "--challenger-model",
            "gpt-x",
            "--challenger-api-key",
            "k",
        ]
    )
    assert captured["options"].roles.extra_finder_backends == ()
    labels = [label for label, _ in captured["options"].verification.confirmers]
    assert len(labels) == 1
    assert labels[0] != "gpt-x"


def test_executor_flag_is_removed(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--finalize", "--reviewer", "model"])
    assert exc.value.code == 2
    assert "--reviewer" in capsys.readouterr().err
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(tmp_path), "--finalize", "--executor", "api"])
    assert exc.value.code == 2
    assert "--executor" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["review", "diff", "--exclude", "vendor/"],
        ["review", "diff", "--source-meta", "target/cyberjury-source.json"],
        ["review", "diff", "--no-filter"],
        ["review", "diff", "--fail-on", "high"],
        ["review", "diff", "--executor", "api"],
        ["review", "repository", ".", "--run", "--effort", "high"],
        ["review", "repository", ".", "--run", "--min-lens-shots", "2"],
        ["review", "repository", ".", "--run", "--max-passes", "2"],
        ["review", "repository", ".", "--run", "--converge-after", "2"],
        ["review", "repository", ".", "--run", "--votes", "2"],
        ["review", "repository", ".", "--run", "--max-units", "10"],
        ["review", "repository", ".", "--scaffold", "--invariants", "rules.md"],
        ["review", "repository", ".", "--run", "--no-verify"],
        ["review", "repository", ".", "--gate", "--strict-coverage"],
        ["review", "repository", ".", "--finalize", "--poc"],
    ],
)
def test_removed_cli_flags_are_rejected(args, capsys):
    if args[:2] == ["review", "diff"]:
        args = [*args[:2], "--repository", "repo", "--git-range", "base..HEAD", *args[2:]]
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 2
    active_modes = {"--run", "--scaffold", "--gate", "--finalize"}
    rejected = next(arg for arg in reversed(args) if arg.startswith("--") and arg not in active_modes)
    assert rejected in capsys.readouterr().err


def test_timeout_flag_is_accepted(tmp_path):
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert (
        main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run", "--timeout", "5"])
        == 0
    )


def test_auto_concurrency_defaults_to_eight():
    assert climod._auto_concurrency(None) == 8
    assert climod._auto_concurrency(4) == 4


@pytest.mark.parametrize(
    "flag",
    [
        ("--rounds", "0"),
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


def test_standard_rejects_explicit_rounds(capsys):
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
                "--mode",
                "standard",
                "--rounds",
                "3",
            ]
        )
    assert exc.value.code == 2
    assert "applies only with --mode adversarial" in capsys.readouterr().err


@pytest.mark.parametrize(
    "args",
    [
        ["--scaffold", "--mode", "adversarial"],
        ["--scaffold", "--model", "unused-model"],
        ["--gate", "--rounds", "3"],
        ["--gate", "--provider", "openai"],
        ["--gate", "--judge-model=unused-model"],
        ["--gate", "--fresh"],
        ["--finalize", "--fresh"],
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


def _finalize_result(tmp_path):
    from types import SimpleNamespace

    return SimpleNamespace(
        parsed=0,
        deduped=0,
        workspace=str(tmp_path),
        verify=None,
        outcome=SimpleNamespace(complete=True),
    )


def _capture_run(monkeypatch):
    import cyberjury.review.repository.engine as eng

    captured = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_run(target, workspace, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    return captured


def test_repository_adversarial_rounds_flow_into_the_run(monkeypatch, tmp_path):
    """Repository adversarial rounds use the shared depth flag."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial", "--rounds", "5"])
    options = captured["options"]
    assert options.roles.mode == "adversarial"
    assert options.execution.max_passes == 5
    assert options.verification.votes == 1
    assert options.roles.challenger_provider is not None
    assert options.roles.judge_provider is not None


def test_repository_standard_mode_runs_one_round(monkeypatch, tmp_path):
    """Repository standard mode matches the single finder default."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    options = captured["options"]
    assert options.roles.mode == "standard"
    assert options.execution.max_passes == 1
    assert options.roles.challenger_provider is None
    assert options.roles.judge_provider is None


def test_run_defaults_concurrency_to_eight(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["options"].execution.concurrency == 8
    assert captured["options"].verification.concurrency == 8


def test_explicit_concurrency_overrides_the_backend_default(monkeypatch, tmp_path):
    captured = _capture_run(monkeypatch)
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
    timeline = _repository_project(ws, repo) / TIMELINE_FILE
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]

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
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_review)
    assert (
        main(
            [
                "review",
                "diff",
                *diff_target.args,
                "--workspace",
                str(tmp_path),
                "--mode",
                "adversarial",
                "--rounds",
                "3",
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
    options = captured["options"]

    assert request["schedule"]["mode"] == options.roles.mode == "adversarial"
    assert request["schedule"]["max_rounds"] == options.roles.max_rounds == 3
    assert request["concurrency"]["review"] == options.execution.concurrency == 5
    assert request["concurrency"]["verification"] == options.verification.concurrency == 5
    assert "secret-canary" not in "".join(path.read_text() for path in review_dir.rglob("*.json*"))


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


@pytest.mark.parametrize("scope", ["diff", "repository"])
@pytest.mark.parametrize("profile", ["web", "evm"])
@pytest.mark.parametrize("mode", ["standard", "adversarial"])
def test_stage_one_request_is_shared_across_target_profile_and_mode(
    monkeypatch,
    tmp_path,
    scope,
    profile,
    mode,
):
    captured = {}

    def fake_dispatch(args):
        captured["request"] = args._review_attempt.request
        captured["intent"] = args._review_session.intent
        captured["workspace"] = args._review_session.workspace.path
        return _complete_stage_one_only(args)

    monkeypatch.setattr(climod, "_dispatch_review_action", fake_dispatch)
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "commit", "--quiet", "--allow-empty", "-m", "base")
    base_revision = _git(repository, "rev-parse", "HEAD")
    (repository / ("Token.sol" if profile == "evm" else "app.py")).write_text("source\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "head")
    mode_args = [] if mode == "standard" else ["--mode", "adversarial"]
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
                profile,
                "--workspace",
                str(tmp_path / "state"),
                *mode_args,
            ]
        )
        == 0
    )
    request = captured["request"]
    assert captured["intent"].target.kind == scope
    assert captured["intent"].requested_profile == profile
    assert request.schedule is not None
    assert request.schedule.mode == mode
    assert request.schedule.max_rounds == (1 if mode == "standard" else 3)
    assert request.providers.finder_seat_id is not None
    assert (request.providers.challenger_seat_id is not None) == (mode == "adversarial")
    assert (request.providers.judge_seat_id is not None) == (mode == "adversarial")
    target_artifact = json.loads((captured["workspace"] / "target.json").read_text())
    snapshot_artifact = json.loads((captured["workspace"] / "snapshot.json").read_text())
    assert target_artifact["schema"] == "cyberjury.resolved-target/v1"
    assert snapshot_artifact["schema"] == "cyberjury.source-snapshot/v1"


def test_diff_runs_get_independent_review_sessions(monkeypatch, diff_target, tmp_path):
    monkeypatch.setattr(climod, "_dispatch_review_action", _complete_stage_one_only)
    command = ["review", "diff", *diff_target.args, "--workspace", str(tmp_path), "--dry-run"]

    assert main(command) == 0
    assert main([*command, "--mode", "adversarial"]) == 0

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


_ADDR = "0x" + "ab" * 20

_PLAIN = "pragma solidity ^0.8.20;\ncontract Token {}\n"


def _payload(source_code: str = _PLAIN, **overrides: object) -> dict:
    entry = {
        "SourceCode": source_code,
        "ContractName": "Token",
        "CompilerVersion": "v0.8.20+commit.a1b79de6",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "",
        "EVMVersion": "Default",
        "LicenseType": "MIT",
        "Proxy": "0",
        "Implementation": "",
    }
    entry.update(overrides)
    return {"status": "1", "message": "OK", "result": [entry]}


class _FakeResponse:
    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


def test_cli_fetch_source_writes_tree(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload())))
    out = tmp_path / "target"
    rc = main(["fetch", "source", "--chain", "bsc", "--address", _ADDR, "--out", str(out), "--api-key", "KEY"])
    assert rc == 0
    assert (out / "Token.sol").exists()
    assert (out / "cyberjury-source.json").exists()
    assert "Fetched 1 source file" in capsys.readouterr().out


def test_cli_fetch_source_fails_loud_on_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload(""))))
    rc = main(["fetch", "source", "--address", _ADDR, "--out", str(tmp_path / "target"), "--api-key", "KEY"])
    assert rc == 1


def test_cli_fetch_without_subcommand_shows_usage(capsys):
    rc = main(["fetch"])
    assert rc == 1
    assert "fetch source" in capsys.readouterr().err
