"""The agent backends.

per-unit review and per-candidate verification run as a headless `claude -p` agent.
Tested with a fake runner, so no real claude is needed, and the engine runs end to end
with no provider.
"""

import json

import pytest

from cyberjury.review.repository.agent import (
    AgentRefutationChecker,
    AgentReviewer,
    AgentVerifier,
    _compose_claude_args,
    _default_runner,
    _envelope_error,
    _result_text,
)
from cyberjury.review.repository.engine import run_repository_review
from cyberjury.review.repository.shapes import Unit
from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verifier import VerifyError


def _envelope(result_text: str) -> str:
    return json.dumps({"type": "result", "subtype": "success", "result": result_text})


def test_result_text_unwraps_json_envelope_and_passes_plain_through():
    """Exercise the result text unwraps json envelope and passes plain through case."""
    assert _result_text(_envelope("hello")) == "hello"
    assert _result_text("just text") == "just text"


def test_agent_reviewer_parses_findings_from_claude_output():
    """Exercise the agent reviewer parses findings from claude output case."""
    findings = (
        '{"findings": [{"title": "idor", "category": "idor", '
        '"endpoint": "GET /x/<id>", "file": "a.py", "severity": "high", "status": "confirmed"}]}'
    )
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["prompt"], captured["cwd"] = prompt, cwd
        return _envelope(findings)

    rev = AgentReviewer(runner=fake_runner)
    cands = rev.review(Unit(name="u", root="/repository", files=("a.py", "svc/b.py")), "authorization")
    assert len(cands) == 1
    assert cands[0].endpoint == "GET /x/<id>"
    assert cands[0].severity == "HIGH"
    assert captured["cwd"] == "/repository"
    assert "a.py" in captured["prompt"]
    assert "AUTHORIZATION LENS" in captured["prompt"]


def test_agent_verifier_parses_refutation_and_keeps_on_garbage():
    """Exercise the agent verifier parses refutation and keeps on garbage case."""
    refute = AgentVerifier(runner=lambda p, **k: _envelope('{"real": false, "reason": "lock holds on Postgres"}'))
    v = refute.verify(Candidate(title="race", endpoint="POST /t", file="x.py"), "/repository")
    assert v.real is False
    assert "lock holds" in v.reason

    garbage = AgentVerifier(runner=lambda p, **k: _envelope("no json"))
    with pytest.raises(VerifyError):
        garbage.verify(Candidate(title="x"), "/repository")


def test_envelope_error_is_detected_not_treated_as_empty():
    """Exercise the envelope error is detected not treated as empty case."""
    assert _envelope_error(_envelope("ok")) is None
    assert _envelope_error(json.dumps({"is_error": True, "subtype": "error_max_turns"})) is not None
    assert _envelope_error(json.dumps({"subtype": "success", "api_error_status": "rate_limited"})) is not None
    assert _envelope_error("plain text, no envelope") is None


def test_ask_retries_a_transient_failure_then_succeeds():
    """Exercise the ask retries a transient failure then succeeds case."""
    calls = {"n": 0}
    findings = _envelope('{"findings": [{"title": "x", "endpoint": "GET /a", "severity": "high"}]}')

    def flaky(prompt, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("rate limited")
        return findings

    rev = AgentReviewer(runner=flaky, retries=2, backoff=0)
    cands = rev.review(Unit(name="u", root=".", files=()), "")
    assert calls["n"] == 2
    assert len(cands) == 1


def test_read_only_allowlist_is_mandatory_and_extra_args_cannot_remove_it():
    """Exercise the read only allowlist is mandatory and extra args cannot remove it case."""
    args = _compose_claude_args(("--model", "claude-x"), unsafe=False)
    assert "Read,Grep,Glob,LS" in args
    assert "--model" in args
    assert "claude-x" in args
    widened = _compose_claude_args(("--allowedTools", "Bash,Write", "--model", "x"), unsafe=False)
    assert "Bash,Write" not in widened
    assert "Read,Grep,Glob,LS" in widened
    unsafe = _compose_claude_args(("--allowedTools", "Bash"), unsafe=True)
    assert "Bash" in unsafe
    assert "Read,Grep,Glob,LS" not in unsafe


def test_env_args_are_shlex_parsed_and_cannot_drop_the_read_only_guard(monkeypatch):
    """Exercise the env args are shlex parsed and cannot drop the read only guard case."""
    monkeypatch.setenv("CYBERJURY_CLAUDE_ARGS", '--allowedTools Bash --append-system-prompt "be terse"')
    captured = {}

    def fake_runner(prompt, *, cwd, claude_bin, args, timeout):
        captured["args"] = args
        return _envelope('{"findings": []}')

    AgentReviewer(runner=fake_runner).review(Unit(name="u", root=".", files=()), "")
    args = captured["args"]
    assert "Read,Grep,Glob,LS" in args
    assert "Bash" not in args
    assert "be terse" in args


def test_agent_refutation_checker_holds_and_keeps_the_finding_on_garbage():
    """Exercise the agent refutation checker holds and keeps the finding on garbage case."""
    holds = AgentRefutationChecker(runner=lambda p, **k: _envelope('{"holds": true, "reason": "guard fires"}'))
    assert holds.holds(Candidate(title="x", file="a.py"), "owner check present", ".") is True
    garbage = AgentRefutationChecker(runner=lambda p, **k: _envelope("no json"))
    assert garbage.holds(Candidate(title="x", file="a.py"), "some reason", ".") is False


def test_default_runner_scrubs_anthropic_auth_from_the_nested_claude_env(monkeypatch):
    """Exercise the default runner scrubs anthropic auth from the nested claude env case."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "stale-key")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.invalid")
    monkeypatch.setenv("PATH_KEEPME", "1")
    captured = {}

    def fake_run(cmd, **kw):
        captured["env"] = kw["env"]
        import subprocess

        return subprocess.CompletedProcess(cmd, 0, stdout=_envelope("ok"), stderr="")

    monkeypatch.setattr("cyberjury.providers.claude_agent.subprocess.run", fake_run)
    _default_runner("prompt", cwd="", claude_bin="claude", args=(), timeout=10)
    assert "ANTHROPIC_API_KEY" not in captured["env"]
    assert "ANTHROPIC_BASE_URL" not in captured["env"]
    assert captured["env"]["PATH_KEEPME"] == "1"


def test_run_with_agent_backends_needs_no_provider(custody_repository, tmp_path):
    """Exercise the run with agent backends needs no provider case."""
    finding = _envelope(
        '{"findings": [{"title": "wallet idor", "category": "idor", '
        '"endpoint": "GET /wallets/<id>", "file": "app/services/wallet.py", '
        '"severity": "HIGH", "status": "confirmed"}]}'
    )
    reviewer = AgentReviewer(runner=lambda p, **k: finding)
    verifier = AgentVerifier(runner=lambda p, **k: _envelope('{"real": true, "reason": "real"}'))

    res = run_repository_review(
        custody_repository,
        tmp_path / "ws",
        reviewer=reviewer,
        verifier=verifier,
        converge_after=2,
        max_passes=8,
        concurrency=2,
    )

    assert res.verify is not None
    assert res.verify.confirmed
    data = json.loads((res.scaffold.workspace / "findings.json").read_text())
    assert any(f["entry"] == "GET /wallets/<id>" for f in data["findings"])
