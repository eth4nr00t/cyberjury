"""The CLI surface.

diff and repository command parsing, backend seat resolution, and dispatch, plus the
shared diff-audit helpers. A diff over the size budget is packed into size-bounded
batches and audited batch by batch so a big PR does not overflow the model context and
silently truncate the reply. The findings are then de-duplicated.
"""

import io
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import cyberjury.cli as climod
from cyberjury.cli import main
from cyberjury.finding import Finding
from cyberjury.providers.mock import MockProvider
from cyberjury.review.diff.engine import audit_diff, dedup_findings, pack_diff_chunks, split_diff_by_file

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"
_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"
_DIFF = _FILE_A


@pytest.fixture(autouse=True)
def _hermetic_seat_env(monkeypatch, tmp_path_factory):
    """Seat resolution reads credentials from the environment.

    so a developer shell that sourced a .env would make a keyless seat look key-reachable
    and flip the executor tests. Every CLI test starts from the clean keyless baseline CI
    has, and a test that needs a key sets it after this fixture runs. The .env auto-load is
    stubbed so a developer's working-directory file cannot leak back in, and the default
    workspace is pinned under a tmp dir so a command that omits --workspace never writes to
    the real user state dir.
    """
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("xdg-state")))
    for name in list(os.environ):
        if name.startswith(("CYBERJURY_", "ANTHROPIC_", "OPENAI_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(climod, "load_env_file", lambda: [])


def test_split_diff_by_file():
    """Exercise the split diff by file case."""
    chunks = split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    """Exercise the split diff empty and unbounded case."""
    assert split_diff_by_file("") == []
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_pack_diff_chunks_empty_is_no_batches():
    """Exercise the pack diff chunks empty is no batches case."""
    assert pack_diff_chunks("") == []


def test_pack_diff_chunks_greedily_combines_files():
    """Exercise the pack diff chunks greedily combines files case."""
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A) + len(_FILE_B))
    assert batches == [_FILE_A + _FILE_B]
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A))
    assert batches == [_FILE_A, _FILE_B]


def test_pack_diff_chunks_isolates_an_oversized_file():
    """Exercise the pack diff chunks isolates an oversized file case."""
    big = "diff --git a/big.py b/big.py\n@@ -0,0 +1 @@\n+" + "z" * 200 + "\n"
    batches = pack_diff_chunks(_FILE_A + big, max_chars=len(_FILE_A) + 5)
    assert batches == [_FILE_A, big]


def test_dedup_findings_collapses_identical():
    """Exercise the dedup findings collapses identical case."""
    f = Finding(file="a.py", line=1, severity="HIGH", category="sql-injection", description="d", confidence=0.9)
    g = Finding(file="a.py", line=2, severity="HIGH", category="sql-injection", description="d", confidence=0.9)
    assert dedup_findings([f, f, g]) == [f, g]


def test_dedup_findings_keeps_the_first_when_only_severity_differs():
    """Exercise the dedup findings keeps the first when only severity differs case."""
    a = Finding(file="a.py", line=1, severity="HIGH", category="sql-injection", description="d", confidence=0.9)
    b = Finding(file="a.py", line=1, severity="CRITICAL", category="sql-injection", description="d", confidence=0.9)
    assert dedup_findings([a, b]) == [a]


def test_large_diff_is_audited_per_file(monkeypatch):
    """Exercise the large diff is audited per file case."""
    monkeypatch.setattr("cyberjury.review.diff.engine._MAX_DIFF_CHARS", 1)
    resp = (
        '{"findings": [{"file": "a.py", "line": 1, "severity": "HIGH", '
        '"category": "sql_injection", "description": "x", "confidence": 0.9}]}'
    )
    provider = MockProvider(default=resp)
    kept, _, _ = audit_diff(_FILE_A + _FILE_B, provider=provider, model="mock")
    assert len(provider.calls) == 2
    assert all(f.category == "sql-injection" for f in kept)


def test_large_diff_uses_batch_specific_context(monkeypatch):
    """Exercise the large diff uses batch specific context case."""
    monkeypatch.setattr("cyberjury.review.diff.engine._MAX_DIFF_CHARS", 1)
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


def test_audit_diff_honors_exclude_paths():
    """Exercise the audit diff honors exclude paths case."""
    resp = (
        '{"findings": [{"file": "vendor/lib.py", "line": 1, "severity": "HIGH", '
        '"category": "sql_injection", "description": "x", "confidence": 0.9}]}'
    )
    kept, dropped, _ = audit_diff(
        _FILE_A, provider=MockProvider(default=resp), model="mock", exclude_paths=("vendor/",)
    )
    assert kept == []
    assert dropped
    assert "excluded path" in dropped[0][1]


def test_version_flag_exits_zero(capsys):
    """Exercise the version flag exits zero case."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "cyberjury" in capsys.readouterr().out


def test_review_diff_dry_run_is_zero_config(capsys):
    """Exercise the review diff dry run is zero config case."""
    rc = main(["review", "diff", "--dry-run"])
    assert rc == 0
    assert "sql-injection" in capsys.readouterr().out


def test_review_diff_dry_run_respects_exclude(capsys):
    """Exercise the review diff dry run respects exclude case."""
    rc = main(["review", "diff", "--dry-run", "--exclude", "app.py"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out


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
    """Exercise the diff source root uses git range ref case."""
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


def test_old_audit_command_is_gone():
    """Exercise the old audit command is gone case."""
    with pytest.raises(SystemExit):
        main(["audit", "--dry-run"])


def test_review_repository_writes_methodology_to_workspace(tmp_path):
    """Exercise the review repository writes methodology to workspace case."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(repository), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "METHODOLOGY.md").is_file()


def test_review_repository_requires_a_mode(tmp_path):
    """Exercise the review repository requires a mode case."""
    repository = tmp_path / "svc"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n")
    ws = tmp_path / "ws"
    with pytest.raises(SystemExit) as exc:
        main(["review", "repository", str(repository), "--workspace", str(ws)])
    assert exc.value.code == 2


def test_review_repository_facts_writes_no_grounding_for_a_tree_with_no_definitions(tmp_path):
    """Exercise the review repository facts writes no grounding for a tree with no definitions case."""
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
    """Exercise the review repository grounds the web domain case."""
    ws = tmp_path / "ws"
    rc = main(["review", "repository", str(_graphable(tmp_path / "svc")), "--workspace", str(ws), "--scaffold"])
    assert rc == 0
    assert (ws / "svc" / "_facts.md").is_file()
    assert (ws / "svc" / "_facts_graph.json").is_file()


def test_python_dash_m_cyberjury_runs():
    """Exercise the python dash m cyberjury runs case."""
    import subprocess
    import sys

    r = subprocess.run([sys.executable, "-m", "cyberjury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "cyberjury" in r.stdout.lower()


def test_install_slash_command_writes_the_file(tmp_path):
    """Exercise the install slash command writes the file case."""
    rc = main(["install-slash-command", "--dir", str(tmp_path)])
    assert rc == 0
    f = tmp_path / "cyberjury-review.md"
    text = f.read_text()
    assert f.is_file()
    assert "cyberjury review repository" in text
    assert "cyberjury review diff" in text


def test_install_slash_command_refuses_to_clobber_without_force(tmp_path, capsys):
    """Exercise the install slash command refuses to clobber without force case."""
    target = tmp_path / "cyberjury-review.md"
    target.write_text("my own prompt")
    assert main(["install-slash-command", "--dir", str(tmp_path)]) == 1
    assert target.read_text() == "my own prompt"
    assert "already exists" in capsys.readouterr().err
    assert main(["install-slash-command", "--dir", str(tmp_path), "--force"]) == 0
    assert "cyberjury review repository" in target.read_text()


def test_install_slash_command_writes_both_agent_dirs(monkeypatch, tmp_path):
    """Exercise the install slash command writes both agent dirs case."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert main(["install-slash-command"]) == 0
    claude = tmp_path / ".claude" / "commands" / "cyberjury-review.md"
    codex = tmp_path / ".codex" / "prompts" / "cyberjury-review.md"
    assert claude.is_file()
    assert codex.is_file()
    assert "--domain auto|web|evm" in claude.read_text()
    assert claude.read_text() == codex.read_text()


def test_default_workspace_is_user_private(monkeypatch, tmp_path):
    """Exercise the default workspace is user private case."""
    from cyberjury.cli import _default_workspace

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert _default_workspace() == str(tmp_path / "state" / "cyberjury" / "reviews")

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert _default_workspace() == str(tmp_path / "home" / ".local" / "state" / "cyberjury" / "reviews")


def test_slash_command_does_not_pin_a_shared_workspace():
    """Exercise the slash command does not pin a shared workspace case."""
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


def test_diff_fail_on_high_exits_nonzero():
    """Exercise the diff fail on high exits nonzero case."""
    assert main(["review", "diff", "--dry-run", "--fail-on", "high"]) == 1
    assert main(["review", "diff", "--dry-run"]) == 0


def test_review_diff_closes_its_backends(monkeypatch, tmp_path):
    """Exercise the review diff closes its backends case."""
    closed = []

    class _Spy:
        def close(self):
            closed.append(True)

    spy = _Spy()
    monkeypatch.setattr(climod, "build_diff_providers", lambda args: (spy, "mock", None, None, None, None, None, None))
    monkeypatch.setattr(climod, "audit_diff", lambda *a, **k: ([], None, False))
    diff = tmp_path / "c.diff"
    diff.write_text("--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+x = 1\n")
    assert main(["review", "diff", "--file", str(diff)]) == 0
    assert closed == [True]


def test_review_diff_repository_backed_file_collects_context_and_verifies(monkeypatch, tmp_path):
    """Exercise the review diff repository backed file collects context and verifies case."""
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
        return ([], None, False)

    monkeypatch.setattr(climod, "build_diff_context_collector", lambda root, domain: _Collector())
    monkeypatch.setattr(
        climod,
        "build_diff_providers",
        lambda args: (MockProvider(default="{}"), "mock", None, None, None, None, None, None),
    )
    monkeypatch.setattr(climod, "audit_diff", fake_audit)

    assert main(["review", "diff", "--file", str(diff), "--repository", str(repo)]) == 0
    assert seen["context"] == "source context"
    assert seen["verification_root"] == str(repo)
    assert seen["verifier"] is not None
    assert seen["verification_confirmers"]


def test_repository_gate_exits_nonzero_until_a_run_completes(tmp_path):
    """Exercise the repository gate exits nonzero until a run completes case."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 1
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run"]) == 0
    assert main(["review", "repository", str(repository), "--workspace", str(ws), "--gate"]) == 0


def test_review_diff_bad_file_exits_nonzero(capsys):
    """Exercise the review diff bad file exits nonzero case."""
    rc = main(["review", "diff", "--file", "/nonexistent/nope.diff"])
    assert rc == 1
    assert "failed" in capsys.readouterr().err


def test_review_diff_empty_stdin_is_clean(monkeypatch, capsys):
    """Exercise the review diff empty stdin is clean case."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    monkeypatch.setattr("cyberjury.cli.make_provider", lambda *a, **k: MockProvider(default='{"findings": []}'))
    rc = main(["review", "diff", "--executor", "api", "--api-key", "x"])
    assert rc == 0
    assert "no findings" in capsys.readouterr().out.lower()


def test_diff_executor_subscription_uses_the_agent_provider(monkeypatch):
    """Exercise the diff executor subscription uses the agent provider case."""
    from cyberjury.providers.claude_agent import ClaudeAgentProvider

    captured = {}

    def fake_audit(diff, *, provider, **kw):
        captured["provider"] = provider
        return [], [], False

    monkeypatch.setattr(climod, "audit_diff", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(["review", "diff", "--executor", "subscription"])
    assert rc == 0
    assert isinstance(captured["provider"], ClaudeAgentProvider)


def test_diff_executor_api_without_key_errors_loud(monkeypatch):
    """Exercise the diff executor api without key errors loud case."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="--executor api requires one"):
        main(["review", "diff", "--executor", "api"])


def test_diff_executor_auto_keyless_anthropic_falls_back_to_agent(monkeypatch, capsys):
    """Exercise the diff executor auto keyless anthropic falls back to agent case."""
    from cyberjury.providers.claude_agent import ClaudeAgentProvider

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CYBERJURY_API_KEY", raising=False)
    captured = {}

    def fake_audit(diff, *, provider, **kw):
        captured["provider"] = provider
        return [], [], False

    monkeypatch.setattr(climod, "audit_diff", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(["review", "diff"])
    assert rc == 0
    assert isinstance(captured["provider"], ClaudeAgentProvider)
    assert "subscription" in capsys.readouterr().err


def test_diff_executor_auto_keyless_non_anthropic_errors_loud(monkeypatch):
    """Exercise the diff executor auto keyless non anthropic errors loud case."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    with pytest.raises(SystemExit, match="no reachable API key"):
        main(["review", "diff", "--provider", "openai"])


def test_diff_adversarial_resolves_each_seat_independently(monkeypatch):
    """Exercise the diff adversarial resolves each seat independently case."""
    from cyberjury.providers.claude_agent import ClaudeAgentProvider

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CYBERJURY_API_KEY", raising=False)
    captured = {}

    def fake_audit(diff, *, finder_provider, challenger_provider, judge_provider, **kw):
        captured.update(finder=finder_provider, challenger=challenger_provider, judge=judge_provider)
        return [], [], False

    monkeypatch.setattr(climod, "audit_diff", fake_audit)
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(
        ["review", "diff", "--mode", "adversarial", "--challenger-provider", "openai", "--challenger-api-key", "k"]
    )
    assert rc == 0
    assert isinstance(captured["finder"], ClaudeAgentProvider)
    assert isinstance(captured["judge"], ClaudeAgentProvider)
    assert not isinstance(captured["challenger"], ClaudeAgentProvider)


def test_diff_degraded_audit_exits_nonzero_and_surfaces_the_error(monkeypatch, capsys):
    """Exercise the diff degraded audit exits nonzero and surfaces the error case."""
    monkeypatch.setattr(climod, "audit_diff", lambda *a, **k: ([], [], True))
    monkeypatch.setattr("sys.stdin", io.StringIO(_DIFF))
    rc = main(["review", "diff", "--executor", "subscription", "--mode", "adversarial"])
    assert rc == 1
    assert "degraded" in capsys.readouterr().err


def test_repository_mode_flags_are_mutually_exclusive(tmp_path):
    """Exercise the repository mode flags are mutually exclusive case."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    for combo in (["--run", "--gate"], ["--run", "--finalize"], ["--finalize", "--gate"]):
        with pytest.raises(SystemExit) as exc:
            main(["review", "repository", str(repository), "--workspace", str(ws), *combo])
        assert exc.value.code == 2
    assert not (ws / "svc" / "findings.json").exists()


def test_repository_run_with_model_errors_exits_nonzero(tmp_path, monkeypatch):
    """Exercise the repository run with model errors exits nonzero case."""
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
            "--no-verify",
            "--executor",
            "api",
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
    """Exercise the role spec inherits base when unset case."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args()
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-base", "basekey")


def test_base_seat_wire_flows_and_role_inherits_it():
    """Exercise the base seat wire flows and role inherits it case."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(wire_api="responses")
    base = _base_spec(a)
    assert base["wire_api"] == "responses"
    assert _role_spec(a, "challenger", base)["wire_api"] == "responses"


def test_role_spec_cross_vendor_override_drops_base_key():
    """Exercise the role spec cross vendor override drops base key case."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(challenger_provider="openai", challenger_model="gpt-x")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"]) == ("openai", "gpt-x")
    assert s["api_key"] is None


def test_role_spec_same_vendor_override_keeps_base_key():
    """Exercise the role spec same vendor override keeps base key case."""
    from cyberjury.cli import _base_spec, _role_spec

    a = _role_args(challenger_model="claude-other")
    s = _role_spec(a, "challenger", _base_spec(a))
    assert (s["provider"], s["model"], s["api_key"]) == ("anthropic", "claude-other", "basekey")


def test_confirmers_exclude_the_skeptic_and_dedupe(monkeypatch):
    """Exercise the confirmers exclude the skeptic and dedupe case."""
    from argparse import Namespace

    from cyberjury.cli import _confirmers

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    a = Namespace(executor="api", retries=0, timeout=10)
    chal = {"provider": "anthropic", "model": "skep", "api_key": "k", "api_base": None, "wire_api": "chat"}
    jud = {"provider": "anthropic", "model": "judge", "api_key": "k", "api_base": None, "wire_api": "chat"}
    fnd = {"provider": "anthropic", "model": "judge", "api_key": "k", "api_base": None, "wire_api": "chat"}
    confirmers = _confirmers(a, challenger=chal, judge=jud, finder=fnd)
    assert [label for label, _ in confirmers] == ["judge"]
    same = {"provider": "anthropic", "model": "skep", "api_key": "k", "api_base": None, "wire_api": "chat"}
    assert _confirmers(a, challenger=chal, judge=same, finder=same) == []


def test_key_reachable_by_explicit_key_or_vendor_env(monkeypatch):
    """Exercise the key reachable by explicit key or vendor env case."""
    from cyberjury.cli import _key_reachable

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _key_reachable({"provider": "anthropic", "api_key": "k"})
    assert not _key_reachable({"provider": "anthropic", "api_key": None})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    assert _key_reachable({"provider": "anthropic", "api_key": None})
    assert not _key_reachable({"provider": "litellm", "api_key": None})


def test_seat_backend_auto_falls_back_for_a_keyless_anthropic_seat(monkeypatch):
    """Exercise the seat backend auto falls back for a keyless anthropic seat case."""
    from cyberjury.cli import _seat_backend

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _seat_backend({"provider": "anthropic", "api_key": None}, "auto") == "agent"
    assert _seat_backend({"provider": "anthropic", "api_key": "k"}, "auto") == "api"
    assert _seat_backend({"provider": "openai", "api_key": "k"}, "subscription") == "agent"
    assert _seat_backend({"provider": "anthropic", "api_key": "k"}, "api") == "api"


def test_seat_backend_errors_loud_at_startup_on_a_missing_key(monkeypatch):
    """Exercise the seat backend errors loud at startup on a missing key case."""
    from cyberjury.cli import _seat_backend

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="no reachable API key"):
        _seat_backend({"provider": "openai", "api_key": None}, "auto")
    with pytest.raises(SystemExit, match="--executor api requires one"):
        _seat_backend({"provider": "anthropic", "api_key": None}, "api")


def test_note_verify_route_states_the_active_route(capsys):
    """Exercise the note verify route states the active route case."""
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


def test_run_auto_falls_back_to_agent_finder_and_skeptic_without_a_key(monkeypatch, tmp_path):
    """Exercise the run auto falls back to agent finder and skeptic without a key case."""
    from cyberjury.review.repository.agent import AgentReviewer, AgentVerifier

    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CYBERJURY_API_KEY", raising=False)
    main(["review", "repository", str(tmp_path), "--run", "--no-verify"])
    assert isinstance(captured["reviewer"], AgentReviewer)
    assert isinstance(captured["verifier"], AgentVerifier)
    assert captured["provider"] is None


def test_finalize_wires_challenger_skeptic_and_judge_confirmer(monkeypatch, tmp_path):
    """Exercise the finalize wires challenger skeptic and judge confirmer case."""
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.repository.verifier import ModelRefutationChecker, ModelVerifier

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
    """Exercise the finalize default has no confirmer and notes keep all case."""
    import cyberjury.review.repository.engine as eng

    def fake_finalize(target, workspace, *, verifier, confirmers, **kw):
        fake_finalize.confirmers = confirmers
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 0
    assert fake_finalize.confirmers == []
    out = capsys.readouterr()
    assert "keep-all" in out.err
    assert "PoC reconciliation" not in out.out


def test_finalize_mentions_pocs_only_when_the_file_exists(monkeypatch, tmp_path, capsys):
    """Exercise the finalize mentions pocs only when the file exists case."""
    import cyberjury.review.repository.engine as eng

    monkeypatch.setattr(eng, "finalize_repository_review", lambda *a, **k: _finalize_result(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    (tmp_path / "_pocs.md").write_text("# PoC Reconciliation\n", encoding="utf-8")
    main(["review", "repository", str(tmp_path), "--finalize"])
    assert f"PoC reconciliation in {tmp_path}/_pocs.md" in capsys.readouterr().out


def _patch_run(monkeypatch, tmp_path, *, converged, errors):
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_run(target, workspace, **kw):
        scaffold = SimpleNamespace(fallback_note="", invariants_note="", workspace=str(tmp_path))
        acc = SimpleNamespace(findings=[], new_per_pass=[[]], converged=converged, errors=errors)
        return SimpleNamespace(scaffold=scaffold, accumulator=acc, verify=None, units=1)

    monkeypatch.setattr(eng, "run_repository_review", fake_run)


def test_run_with_failed_calls_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    """Exercise the run with failed calls exits nonzero and warns case."""
    _patch_run(monkeypatch, tmp_path, converged=True, errors=2)
    rc = main(["review", "repository", str(tmp_path), "--run", "--no-verify"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "model calls failed" in err
    assert "did not converge" not in err


def test_run_that_did_not_converge_exits_nonzero_and_warns(monkeypatch, tmp_path, capsys):
    """Exercise the run that did not converge exits nonzero and warns case."""
    _patch_run(monkeypatch, tmp_path, converged=False, errors=0)
    rc = main(["review", "repository", str(tmp_path), "--run", "--no-verify"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "did not converge" in err
    assert "model calls failed" not in err


def test_finalize_verify_errors_exit_nonzero_and_ask_to_resume(monkeypatch, tmp_path, capsys):
    """Exercise the finalize verify errors exit nonzero and ask to resume case."""
    from types import SimpleNamespace

    import cyberjury.review.repository.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    def fake_finalize(target, workspace, **kw):
        verify = SimpleNamespace(confirmed=[], refuted=[], errors=1)
        return SimpleNamespace(parsed=0, deduped=0, workspace=str(tmp_path), verify=verify)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    rc = main(["review", "repository", str(tmp_path), "--finalize"])
    assert rc == 1
    assert "Re-run to resume" in capsys.readouterr().err


def test_unlocatable_warning_uses_singular_finding(capsys):
    """The warning keeps count grammar readable."""
    climod._warn_unlocatable(SimpleNamespace(unlocatable=[SimpleNamespace(title="ghost", file="ghost.py")]))
    err = capsys.readouterr().err
    assert "1 finding cites" in err
    assert "so it was kept" in err


def test_run_passes_confirmers_and_no_extra_finders(monkeypatch, tmp_path):
    """Exercise the run passes confirmers and no extra finders case."""
    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(
        [
            "review",
            "repository",
            str(tmp_path),
            "--run",
            "--no-verify",
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


def test_finalize_auto_builds_an_agent_confirmer_for_a_keyless_claude_judge(monkeypatch, tmp_path):
    """Exercise the finalize auto builds an agent confirmer for a keyless claude judge case."""
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.repository.agent import AgentRefutationChecker
    from cyberjury.review.repository.verifier import ModelVerifier

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
        ]
    )
    assert rc == 0
    assert isinstance(captured["verifier"], ModelVerifier)
    assert captured["verifier"]._model == "gpt-x"
    ((_label, checker),) = captured["confirmers"]
    assert isinstance(checker, AgentRefutationChecker)


def test_executor_subscription_wires_the_agent_verifier(monkeypatch, tmp_path):
    """Exercise the executor subscription wires the agent verifier case."""
    import cyberjury.review.repository.engine as eng
    from cyberjury.review.repository.agent import AgentVerifier

    captured = {}

    def fake_finalize(target, workspace, *, verifier, confirmers, **kw):
        captured["verifier"] = verifier
        return _finalize_result(tmp_path)

    monkeypatch.setattr(eng, "finalize_repository_review", fake_finalize)
    rc = main(["review", "repository", str(tmp_path), "--finalize", "--executor", "subscription"])
    assert rc == 0
    assert isinstance(captured["verifier"], AgentVerifier)


def test_executor_rename_is_a_clean_break(tmp_path):
    """Exercise the executor rename is a clean break case."""
    with pytest.raises(SystemExit):
        main(["review", "repository", str(tmp_path), "--finalize", "--reviewer", "model"])
    with pytest.raises(SystemExit):
        main(["review", "repository", str(tmp_path), "--finalize", "--executor", "claude-cli"])


def test_timeout_flag_is_accepted(tmp_path):
    """Exercise the timeout flag is accepted case."""
    repository = _flask_repository(tmp_path / "svc")
    ws = tmp_path / "ws"
    assert (
        main(["review", "repository", str(repository), "--workspace", str(ws), "--run", "--dry-run", "--timeout", "5"])
        == 0
    )


def test_effort_levels_set_shots_and_votes():
    """Exercise the effort levels set shots and votes case."""
    assert climod._resolve_effort("low", None, None) == (1, 1)
    assert climod._resolve_effort("medium", None, None) == (2, 1)
    assert climod._resolve_effort("high", None, None) == (3, 2)


def test_explicit_shots_or_votes_overrides_effort():
    """Exercise the explicit shots or votes overrides effort case."""
    assert climod._resolve_effort("high", 5, None) == (5, 2)
    assert climod._resolve_effort("low", None, 4) == (1, 4)


def test_auto_concurrency_holds_the_subscription_agent_to_two():
    """Exercise the auto concurrency holds the subscription agent to two case."""
    assert climod._auto_concurrency(None, "agent") == 2
    assert climod._auto_concurrency(None, "anthropic") == 6
    assert climod._auto_concurrency(8, "agent") == 8


def _finalize_result(tmp_path):
    from types import SimpleNamespace

    return SimpleNamespace(parsed=0, deduped=0, workspace=str(tmp_path), verify=None)


def _capture_run(monkeypatch):
    import cyberjury.review.repository.engine as eng

    captured = {}

    def fake_run(target, workspace, **kw):
        captured.update(kw)
        raise RuntimeError("stop after capture")

    monkeypatch.setattr(eng, "run_repository_review", fake_run)
    return captured


def test_effort_high_flows_shots_and_votes_into_the_run(monkeypatch, tmp_path):
    """Exercise the effort high flows shots and votes into the run case."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--effort", "high"])
    assert captured["min_lens_shots"] == 3
    assert captured["votes"] == 2


def test_keyless_run_defaults_concurrency_to_two(monkeypatch, tmp_path):
    """Exercise the keyless run defaults concurrency to two case."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["concurrency"] == 2


def test_keyed_run_defaults_concurrency_to_six(monkeypatch, tmp_path):
    """Exercise the keyed run defaults concurrency to six case."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run"])
    assert captured["concurrency"] == 6


def test_explicit_concurrency_overrides_the_backend_default(monkeypatch, tmp_path):
    """Exercise the explicit concurrency overrides the backend default case."""
    captured = _capture_run(monkeypatch)
    main(["review", "repository", str(tmp_path), "--run", "--concurrency", "9"])
    assert captured["concurrency"] == 9


def test_retries_and_timeout_reach_the_subscription_agent_finder(monkeypatch, tmp_path):
    """Exercise the retries and timeout reach the subscription agent finder case."""
    from cyberjury.review.repository.agent import AgentReviewer

    captured = _capture_run(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CYBERJURY_API_KEY", raising=False)
    main(["review", "repository", str(tmp_path), "--run", "--no-verify", "--retries", "5", "--timeout", "42"])
    reviewer = captured["reviewer"]
    assert isinstance(reviewer, AgentReviewer)
    assert reviewer._retries == 5
    assert reviewer._timeout == 42


def test_every_effort_tier_grounds_and_no_flag_can_turn_it_off(tmp_path):
    """Exercise the every effort tier grounds and no flag can turn it off case."""
    for flag in ("--facts", "--no-facts"):
        with pytest.raises(SystemExit):
            main(["review", "repository", ".", "--scaffold", flag])
    for tier in ("low", "medium", "high"):
        ws = tmp_path / f"ws-{tier}"
        target = str(_graphable(tmp_path / tier))
        rc = main(["review", "repository", target, "--workspace", str(ws), "--scaffold", "--effort", tier])
        assert rc == 0
        assert (ws / tier / "_facts.md").is_file(), f"--effort {tier} left the review ungrounded"


def test_repository_stages_record_a_whole_pipeline_timeline(tmp_path):
    """Exercise the repository stages record a whole pipeline timeline case."""
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
