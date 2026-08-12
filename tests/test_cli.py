"""The CLI surface covers command parsing, seat resolution, dispatch, and diff helpers."""

import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import audit_diff
from cyberjury.review.diff.model import pack_diff_chunks, split_diff_by_file
from cyberjury.review.failures import ReviewUnitFailure

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"
_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"
_DIFF = _FILE_A


@pytest.fixture(autouse=True)
def _hermetic_seat_env(monkeypatch, tmp_path_factory):
    """Seat resolution starts from a clean provider environment for every CLI test."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("xdg-state")))
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(climod, "load_env_file", lambda: [])


def test_split_diff_by_file():
    """Split diff by file."""
    chunks = split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    """Split diff empty and unbounded."""
    assert split_diff_by_file("") == []
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_pack_diff_chunks_empty_is_no_batches():
    """Pack diff chunks empty is no batches."""
    assert pack_diff_chunks("") == []


def test_pack_diff_chunks_greedily_combines_files():
    """Pack diff chunks greedily combines files."""
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A) + len(_FILE_B))
    assert batches == [_FILE_A + _FILE_B]
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A))
    assert batches == [_FILE_A, _FILE_B]


def test_pack_diff_chunks_isolates_an_oversized_file():
    """Pack diff chunks isolates an oversized file."""
    big = "diff --git a/big.py b/big.py\n@@ -0,0 +1 @@\n+" + "z" * 200 + "\n"
    batches = pack_diff_chunks(_FILE_A + big, max_chars=len(_FILE_A) + 5)
    assert batches == [_FILE_A, big]


def test_large_diff_is_audited_per_file(monkeypatch):
    """Large diff is audited per file."""
    monkeypatch.setattr("cyberjury.review.diff.model.MAX_DIFF_CHARS", 1)
    resp = (
        '{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
        '"category": "sql_injection", "description": "x", "confidence": 0.9}]}'
    )
    provider = MockProvider(default=resp)
    kept, _, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    assert len(provider.calls) == 2
    assert all(f.category == "sql-injection" for f in kept)


def test_large_diff_uses_batch_specific_context(monkeypatch):
    """Large diff uses batch specific context."""
    monkeypatch.setattr("cyberjury.review.diff.model.MAX_DIFF_CHARS", 1)
    provider = MockProvider(default='{"findings": []}')

    audit_diff(
        _FILE_A + _FILE_B,
        provider=provider,
        model="mock",
        context_for_diff=lambda d: "context for a.py" if "a.py" in d else "context for b.py",
    )

    prompts = [call["messages"][0].content for call in provider.calls]
    assert len(prompts) == 2
    assert "context for a.py" in prompts[0]
    assert "context for b.py" not in prompts[0]
    assert "context for b.py" in prompts[1]


def test_version_flag_exits_zero(capsys):
    """Version flag exits zero."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "cyberjury" in capsys.readouterr().out


def test_review_diff_dry_run_is_zero_config(capsys):
    """Review diff dry run is zero config."""
    rc = main(["review", "diff", "--dry-run"])
    assert rc == 0
    assert "sql-injection" in capsys.readouterr().out


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


def test_diff_source_root_uses_git_range_ref(tmp_path):
    """Diff source root uses git range ref."""
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

    args = SimpleNamespace(repository=str(repo), git_range=f"{base}..{ref}")
    with climod._diff_source_root(args) as root:
        assert (root / "app.py").read_text() == "new\n"
        worktree = root

    assert not worktree.exists()


def test_old_audit_command_is_gone(capsys):
    """Old audit command is gone."""
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--dry-run"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_review_repository_writes_methodology_to_workspace(tmp_path):
    """Review repository writes methodology to workspace."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "METHODOLOGY.md").is_file()


def test_review_repository_requires_a_mode(tmp_path):
    """Review repository requires a mode."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(repository), "--workspace", str(ws)])
    assert exc.value.code == 2


def test_review_repository_facts_writes_no_grounding_for_a_tree_with_no_definitions(tmp_path):
    """Review repository facts writes no grounding for a tree with no definitions."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert not (ws / "svc" / "_facts.md").exists()


def _graphable(root):
    root.mkdir()
    (root / "app.py").write_text("def handle(req):\n    return lookup(req)\n")
    (root / "store.py").write_text("def lookup(key):\n    return key\n")
    return root


def test_review_repository_grounds_the_web_domain(tmp_path):
    """Review repository grounds the web domain."""
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(_graphable(tmp_path / "svc")), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "_facts.md").is_file()
    assert (ws / "svc" / "_facts_graph.json").is_file()


def test_python_dash_m_cyberjury_runs():
    """Python dash m cyberjury runs."""
    import subprocess
    import sys

    r = subprocess.run([sys.executable, "-m", "cyberjury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "cyberjury" in r.stdout.lower()


def test_install_slash_command_writes_the_file(tmp_path):
    """Install slash command writes the file."""
    rc = main(["install-slash-command", "--dir", str(tmp_path)])
    assert rc == 0
    f = tmp_path / "cyberjury-review.md"
    text = f.read_text()
    assert f.is_file()
    assert "cyberjury review repository" in text
    assert "cyberjury review diff" in text


def test_install_slash_command_refuses_to_clobber_without_force(tmp_path, capsys):
    """Install slash command refuses to clobber without force."""
    target = tmp_path / "cyberjury-review.md"
    target.write_text("my own prompt")
    assert main(["install-slash-command", "--dir", str(tmp_path)]) == 1
    assert target.read_text() == "my own prompt"
    assert "already exists" in capsys.readouterr().err
    assert main(["install-slash-command", "--dir", str(tmp_path), "--force"]) == 0
    assert "cyberjury review repository" in target.read_text()


def test_install_slash_command_writes_both_agent_dirs(monkeypatch, tmp_path):
    """Install slash command writes both agent dirs."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert main(["install-slash-command"]) == 0
    claude = tmp_path / ".claude" / "commands" / "cyberjury-review.md"
    codex = tmp_path / ".codex" / "prompts" / "cyberjury-review.md"
    assert claude.is_file()
    assert codex.is_file()
    assert "--domain auto|web|evm" in claude.read_text()
    assert claude.read_text() == codex.read_text()


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    """Default workspace is user private."""
    from cyberjury.cli import _default_workspace

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert _default_workspace() == str(tmp_path / "state" / "cyberjury" / "reviews")

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".local" / "state" / "cyberjury" / "reviews")


def test_slash_command_does_not_pin_a_shared_workspace():
    """Slash command does not pin a shared workspace."""
    from cyberjury.resources import SLASH_COMMAND_FILE

    assert "/var/tmp" not in SLASH_COMMAND_FILE.read_text()


def _flask_repository(root):
    root.mkdir()
    (root / "app.py").write_text(
        "from flask import Flask, request\napp = Flask(__name__)\n"
        '@app.route("/x/<i>")\ndef h(i):\n    return request.args.get("y", "")\n'
    )
    (root / "requirements.txt").write_text("Flask==3.0\n")
    return root


def test_review_diff_closes_its_backends(monkeypatch, tmp_path):
    """Review diff closes its backends."""
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    monkeypatch.setattr(climod, "build_diff_providers", lambda args: (spy, "mock", None, None, None, None, None, None))
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False)),
    )
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+x = 1\n")
    assert main(["review", "diff", "--file", str(diff)]) == 0
    assert closed == [True]


def test_close_backends_dedupes_same_object_by_identity():
    """Close backends dedupes same object by identity."""
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    climod._close_backends(spy, spy, None)
    assert closed == [True]


def test_review_diff_repository_backed_file_collects_context_and_verifies(monkeypatch, tmp_path):
    """Review diff repository backed file collects context and verifies."""
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    class _Collector:
        def collect(self, diff_text):
            seen["context_diff"] = diff_text
            return SimpleNamespace(text="source context", files=("app.py",))

        def text_for_diff(self, diff_text):
            return "batch context"

    def fake_audit(*args, **kwargs):
        seen["context"] = kwargs["context"]
        seen["verification_root"] = kwargs["verification_root"]
        seen["verifier"] = kwargs["verifier"]
        seen["verification_confirmers"] = kwargs["verification_confirmers"]
        seen["verification_found_by"] = kwargs["verification_found_by"]
        seen["verification_concurrency"] = kwargs["verification_concurrency"]
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    def fake_context_collector(root, domain, *, review_diff=""):
        seen["review_diff"] = review_diff
        return _Collector()

    monkeypatch.setattr(climod, "build_diff_context_collector", fake_context_collector)
    monkeypatch.setattr(
        climod,
        "build_diff_providers",
        lambda args: (MockProvider(default="{}"), "mock", None, None, None, None, None, None),
    )
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert main(["review", "diff", "--file", str(diff), "--repository", str(repo), "--api-key", "k"]) == 0
    assert seen["context"] == "source context"
    assert seen["review_diff"] == diff.read_text()
    assert seen["verification_root"] == str(repo)
    assert seen["verifier"] is not None
    assert seen["verification_confirmers"] == []
    assert seen["verification_found_by"] == ("claude-opus-5",)
    assert seen["verification_concurrency"] == 8


def test_review_diff_standard_uses_distinct_judge_and_finder_confirmers(monkeypatch, tmp_path):
    """A standard diff finder cannot also approve deleting its own finding."""
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    def fake_audit(*args, **kwargs):
        seen["verification_confirmers"] = kwargs["verification_confirmers"]
        seen["verification_found_by"] = kwargs["verification_found_by"]
        seen["verification_concurrency"] = kwargs["verification_concurrency"]
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "build_diff_providers",
        lambda args: (MockProvider(default="{}"), "finder", None, None, None, None, None, None),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                "--file",
                str(diff),
                "--repository",
                str(repo),
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


def test_review_diff_adversarial_uses_finder_as_a_provenance_aware_confirmer(monkeypatch, tmp_path):
    """Adversarial provenance lets the finder confirm only findings it did not surface."""
    repo = tmp_path / "repo"
    repo.mkdir()
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+x = 1\n")
    seen = {}

    def fake_audit(*args, **kwargs):
        seen["verification_confirmers"] = kwargs["verification_confirmers"]
        seen["verification_found_by"] = kwargs["verification_found_by"]
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(
        climod,
        "build_diff_providers",
        lambda args: (
            MockProvider(default="{}"),
            "finder",
            MockProvider(default="{}"),
            "finder",
            MockProvider(default="{}"),
            "skeptic",
            MockProvider(default="{}"),
            "judge",
        ),
    )
    monkeypatch.setattr(climod, "_role_provider", lambda *args, **kwargs: MockProvider(default="{}"))
    monkeypatch.setattr(climod, "run_diff_review", fake_audit)

    assert (
        main(
            [
                "review",
                "diff",
                "--file",
                str(diff),
                "--repository",
                str(repo),
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


def test_repository_gate_exits_nonzero_until_a_run_completes(tmp_path):
    """Repository gate exits nonzero until a run completes."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 1
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 0


def test_review_diff_bad_file_exits_nonzero(capsys):
    """Review diff bad file exits nonzero."""
    rc = main(["review", "diff", "--file", "/nonexistent/nope.diff"])
    assert rc == 1
    assert "failed" in capsys.readouterr().err


def test_review_diff_empty_stdin_is_clean(monkeypatch, capsys):
    """Review diff empty stdin is clean."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setattr("cyberjury.cli.make_provider", lambda *a, **k: MockProvider(default='{"findings": []}'))
    rc = main(["review", "diff", "--api-key", "x"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out.lower()


def test_diff_without_key_errors_loud(monkeypatch):
    """Diff without key errors loud."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff"])


def test_diff_openai_without_key_errors_loud(monkeypatch):
    """Diff OpenAI without key errors loud."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", "--provider", "openai"])


def test_diff_adversarial_resolves_each_seat_independently(monkeypatch):
    """Diff adversarial resolves each seat independently."""
    captured = {}

    def fake_audit(diff, *, finder_provider, challenger_provider, judge_provider, **kw):
        captured.update(finder=finder_provider, challenger=challenger_provider, judge=judge_provider)
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(
        [
            "review",
            "diff",
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

    def fake_diff_provider(args, spec):
        captured["spec"] = spec
        return object()

    monkeypatch.setattr(climod, "_diff_provider", fake_diff_provider)
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

    _provider, model, *_roles = climod.build_diff_providers(args)

    assert model == "finder"
    assert captured["spec"]["model"] == "finder"


def test_diff_adversarial_rounds_flow_into_audit(monkeypatch):
    """Diff adversarial rounds flow into audit."""
    captured = {}

    def fake_audit(diff, *, mode, max_rounds, **kw):
        captured["mode"] = mode
        captured["max_rounds"] = max_rounds
        return SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=False))

    monkeypatch.setattr(climod, "run_diff_review", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    assert main(["review", "diff", "--mode", "adversarial", "--rounds", "5", "--api-key", "k"]) == 0
    assert captured == {"mode": "adversarial", "max_rounds": 5}


def test_diff_degraded_audit_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys):
    """Diff degraded audit exits nonzero and surfaces the error."""
    monkeypatch.setattr(
        climod,
        "run_diff_review",
        lambda *a, **k: SimpleNamespace(outcome=SimpleNamespace(findings=[], failures=[], degraded=True)),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(["review", "diff", "--mode", "adversarial", "--api-key", "k"])
    assert rc == 1
    assert "degraded" in capsys.readouterr().err


def test_diff_degraded_audit_surfaces_failed_batch_details(monkeypatch, capsys):
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
    rc = main(["review", "diff", "--dry-run"])

    err = capsys.readouterr().err
    assert rc == 1
    assert "diff batch 2/3 failed for app.py, billing.py, routes.py, and 1 more: AuditError: blocked" in err
    assert "the diff audit degraded" in err


def test_repository_mode_flags_are_mutually_exclusive(tmp_path, capsys):
    """Repository mode flags are mutually exclusive."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    for combo in (["--run", "--gate"], ["--run", "--finalize"], ["--finalize", "--gate"]):
        with pytest.raises(SystemExit) as exc:
            main(["review", "repository", str(repository), "--workspace", str(ws), *combo])
        assert exc.value.code == 2
        assert "not allowed with argument" in capsys.readouterr().err
    assert not (ws / "svc" / "findings.json").exists()


def test_repository_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    """Repository run with model errors exits nonzero."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    monkeypatch.setattr("cyberjury.cli.make_provider", lambda *a, **k: MockProvider(default="not json at all"))
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


def _role_args(**over):
    from argparse import Namespace

    base = {"provider": "anthropic", "model": "claude-base", "api_key": "basekey", "api_base": None, "wire_api": "chat"}
    for role in ("finder", "challenger", "judge"):
        for field in ("provider", "model", "api_key", "api_base", "wire_api"):
            base[f"{role}_{field}"] = None
    base.update(over)
    return Namespace(**base)


def test_role_spec_inherits_base_when_unset():
    """Role spec inherits base when unset."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args()
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-base", "basekey")


def test_base_seat_wire_flows_and_role_inherits_it():
    """Base seat wire flows and role inherits it."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(wire_api="responses")
    base = _base_spec(a)
    assert base["wire_api"] == "responses"
    assert _role_spec(a, "challenger", base)["wire_api"] == "responses"


def test_role_spec_cross_vendor_override_drops_base_provider_specific_fields():
    """A provider switch must not carry vendor-specific base settings into the role."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(
        api_base="https://anthropic.example.test",
        wire_api="chat",
        challenger_provider="openai",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"]) == ("openai", "gpt-5.6")
    assert s["api_key"] is None
    assert s["api_base"] is None
    assert s["wire_api"] is None


def test_role_spec_cross_vendor_keeps_explicit_role_fields():
    """Role fields stay authoritative when the role intentionally changes provider."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(
        challenger_provider="openai",
        challenger_model="gpt-x",
        challenger_api_key="role-key",
        challenger_api_base="https://openai.example.test",
        challenger_wire_api="responses",
    )
    s = _role_spec(a, "challenger", _base_spec(a))
    assert s == {
        "provider": "openai",
        "model": "gpt-x",
        "api_key": "role-key",
        "api_base": "https://openai.example.test",
        "wire_api": "responses",
    }


def test_role_spec_same_vendor_override_keeps_base_key():
    """Role spec same vendor override keeps base key."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(challenger_model="claude-other")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-other", "basekey")


def test_confirmers_exclude_the_skeptic_and_dedupe(monkeypatch):
    """Confirmers exclude the skeptic and dedupe."""
    from argparse import Namespace

    from cyberjury.cli import _confirmers

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    a = Namespace(retries=0, timeout=10)
    chal = {"provider": "anthropic", "model": "skep", "api_key": "k", "api_base": None, "wire_api": "chat"}
    jud = {"provider": "anthropic", "model": "judge", "api_key": "k", "api_base": None, "wire_api": "chat"}
    fnd = {"provider": "anthropic", "model": "judge", "api_key": "k", "api_base": None, "wire_api": "chat"}
    confirmers = _confirmers(a, challenger=chal, judge=jud, finder=fnd)
    assert [label for label, _ in confirmers] == ["judge"]
    same = {"provider": "anthropic", "model": "skep", "api_key": "k", "api_base": None, "wire_api": "chat"}
    assert _confirmers(a, challenger=chal, judge=same, finder=same) == []


def test_key_reachable_by_explicit_key_or_vendor_env(monkeypatch):
    """Key reachable by explicit key or vendor env."""
    from cyberjury.cli import _key_reachable

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _key_reachable({"provider": "anthropic", "api_key": "k"})
    assert not _key_reachable({"provider": "anthropic", "api_key": None})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    assert _key_reachable({"provider": "anthropic", "api_key": None})
    assert not _key_reachable({"provider": "openai", "api_key": None})


def test_require_key_errors_loud_at_startup_on_a_missing_key(monkeypatch):
    """Require key errors loud at startup on a missing key."""
    from cyberjury.cli import _require_key

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        _require_key({"provider": "openai", "api_key": None})
    _require_key({"provider": "anthropic", "api_key": "k"})


def test_note_verify_route_states_the_active_route(capsys):
    """Note verify route states the active route."""
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


def test_finalize_wires_challenger_skeptic_and_judge_confirmer(monkeypatch, tmp_path):
    """Finalize wires challenger skeptic and judge confirmer."""
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.verification import ModelRefutationChecker, ModelVerifier

    captured = {}

    def fake_finalize(target, workspace, *, verifier, confirmers, **kw):
        captured["verifier"], captured["confirmers"] = verifier, confirmers
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--finalize",
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
    """Finalize default has no confirmer and notes keep all."""
    import cyberjury.review.repository.engine as eng

    def fake_finalize(target, workspace, *, verifier, confirmers, **kw):
        fake_finalize.confirmers = confirmers
        fake_finalize.poc_backend = kw.get("poc_backend")
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 0
    assert fake_finalize.confirmers == []
    assert fake_finalize.poc_backend is not None
    out = capsys.readouterr()
    assert "keep-all" in out.err
    assert "PoC reconciliation" not in out.out


def test_finalize_closes_api_verifier_and_poc_providers(monkeypatch, tmp_path):
    """Finalize closes API verifier and PoC providers."""
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
    assert main(["review", "repository", str(tmp_path), "--finalize"]) == 0
    assert [p.closed for p in providers] == [1, 1]


def test_run_closes_api_role_verifier_and_poc_providers(monkeypatch, tmp_path):
    """Run closes API role verifier and PoC providers."""
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

    def fake_run(target, workspace, **kw):
        fake_run.poc_backend = kw.get("poc_backend")
        verify = SimpleNamespace(confirmed=[], refuted=[], errors=0, unlocatable=[])
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=True, errors=0)
        scaffold = SimpleNamespace(fallback_note="", workspace=str(tmp_path))
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=verify, units=1)

    monkeypatch.setattr(climod, "_role_provider", fake_role_provider)
    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    assert main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial", "--api-key", "k"]) == 0
    assert fake_run.poc_backend is not None
    assert len(providers) == 5
    assert [p.closed for p in providers] == [1, 1, 1, 1, 1]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["--api-key", "k"], 8),
        (["--api-key", "k", "--concurrency", "4"], 4),
    ],
)
def test_finalize_concurrency_uses_the_api_default(monkeypatch, tmp_path, args, expected):
    """Finalize concurrency uses the API default."""
    import cyberjury.review.repository.engine as eng

    captured = {}

    def fake_finalize(target, workspace, *, concurrency, **kw):
        captured["concurrency"] = concurrency
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    assert main(["review", "repository", str(tmp_path), "--finalize", *args]) == 0
    assert captured["concurrency"] == expected


def test_finalize_mentions_pocs_only_when_the_file_exists(monkeypatch, tmp_path, capsys):
    """Finalize mentions PoCs only when the file exists."""
    import cyberjury.review.repository.engine as eng

    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "_pocs.md").write_text("# PoC Reconciliation\n", encoding="utf-8")
    main(["review", "repository", str(tmp_path), "--finalize"])
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
    """Run with failed calls exits nonzero and warns."""
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
    assert "model calls failed" in err
    assert "RuntimeError: provider rate limited" in err
    assert "did not converge" not in err


def test_run_that_did_not_converge_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    """Run that did not converge exits nonzero and warns."""
    _patch_run(monkeypatch, tmp_path, converged=False, errors=0)
    rc = main(["review", "repository", str(tmp_path), "--run", "--mode", "adversarial"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "did not converge" in err
    assert "model calls failed" not in err


def test_finalize_verify_errors_exit_nonzero_and_ask_to_resume(monkeypatch, tmp_path, capsys):
    """Finalize verify errors exit nonzero and ask to resume."""
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_finalize(target, workspace, **kw):
        verify = SimpleNamespace(confirmed=[], refuted=[], errors=1)
        outcome = SimpleNamespace(complete=False)
        return SimpleNamespace(parsed=0, deduped=0, workspace=str(tmp_path), verify=verify, outcome=outcome)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 1
    assert "Re-run to resume" in capsys.readouterr().err


def test_unlocatable_warning_uses_singular_finding(capsys):
    """Unlocatable warning uses singular finding."""
    climod._warn_unlocatable(SimpleNamespace(unlocatable=[SimpleNamespace(title="ghost", file="ghost.py")]))
    err = capsys.readouterr().err
    assert "1 finding cites" in err
    assert "so it was kept" in err


def test_run_passes_confirmers_and_no_extra_finders(monkeypatch, tmp_path):
    """Run passes confirmers and no extra finders."""
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
    assert "extra_finder_backends" not in captured
    labels = [label for label, _ in captured["confirmers"]]
    assert len(labels) == 1
    assert labels[0] != "gpt-x"


def test_executor_flag_is_removed(tmp_path, capsys):
    """Executor flag is removed."""
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
    """Removed CLI flags are rejected."""
    with pytest.raises(SystemExit) as exc:
        main(args)
    assert exc.value.code == 2
    active_modes = {"--run", "--scaffold", "--gate", "--finalize"}
    rejected = next(arg for arg in reversed(args) if arg.startswith("--") and arg not in active_modes)
    assert rejected in capsys.readouterr().err


def test_timeout_flag_is_accepted(tmp_path):
    """Timeout flag is accepted."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert (
        main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run", "--timeout", "5"])
        == 0
    )


def test_auto_concurrency_defaults_to_eight():
    """Auto concurrency defaults to eight."""
    assert climod._auto_concurrency(None) == 8
    assert climod._auto_concurrency(4) == 4


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
    assert captured["mode"] == "adversarial"
    assert captured["max_passes"] == 5
    assert captured["votes"] == 1
    assert captured["challenger_provider"] is not None
    assert captured["judge_provider"] is not None
    assert captured["challenger_reviewer"] is None
    assert captured["judge_reviewer"] is None


def test_repository_standard_mode_runs_one_round(monkeypatch, tmp_path):
    """Repository standard mode matches the single finder default."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["mode"] == "standard"
    assert captured["max_passes"] == 1
    assert captured["challenger_reviewer"] is None
    assert captured["judge_reviewer"] is None


def test_run_defaults_concurrency_to_eight(monkeypatch, tmp_path):
    """Run defaults concurrency to eight."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["concurrency"] == 8


def test_explicit_concurrency_overrides_the_backend_default(monkeypatch, tmp_path):
    """Explicit concurrency overrides the backend default."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--concurrency", "9"])
    assert captured["concurrency"] == 9


def test_repository_stages_record_a_whole_pipeline_timeline(tmp_path):
    """Repository stages record a whole pipeline timeline."""
    from cyberjury.telemetry import TIMELINE_FILE

    repo = tmp_path / "svc"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    timeline = ws / "svc" / TIMELINE_FILE

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]

    main(["review", "repository", str(repo), "--workspace", str(ws), "--gate"])
    stages = json.loads(timeline.read_text())
    assert [r["stage"] for r in stages] == ["scaffold", "gate"]
    assert all(r["ok"] and isinstance(r["seconds"], (int, float)) for r in stages)

    main(["review", "repository", str(repo), "--workspace", str(ws), "--scaffold"])
    assert [r["stage"] for r in json.loads(timeline.read_text())] == ["scaffold"]
