"""The persistent Claude Agent SDK transport.

A fake async client stands in for the SDK, so no test spawns a real Claude Code, and the
pool, the session restart rules, and the fail-loud parsing are all exercised without a key.
The tool policy and the auth scrub are asserted against the real options builder.
"""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace

import pytest

from cyberjury.providers import claude_agent
from cyberjury.providers.claude_agent import (
    SdkClaudeTransport,
    _allowed_tools_from_args,
    _compose_claude_args,
    _int_env,
    _resolve_transport,
    _result_from_messages,
)


def _ok_messages(text: str = "ok") -> list[SimpleNamespace]:
    return [
        SimpleNamespace(content=[SimpleNamespace(text=text)], model="m"),
        SimpleNamespace(subtype="success", is_error=False, result=text),
    ]


class _FakeClient:
    def __init__(self, cwd, tools, events, messages, *, on_query=None):
        self.cwd = cwd
        self.tools = tools
        self._events = events
        self._messages = messages
        self._on_query = on_query

    async def connect(self):
        self._events.append(("connect", id(self)))

    async def disconnect(self):
        self._events.append(("disconnect", id(self)))

    async def query(self, prompt):
        if self._on_query is not None:
            self._on_query(self)
        self._events.append(("query", id(self)))

    async def receive_response(self):
        for m in self._messages:
            yield m


def _factory(events, *, messages=None, on_query=None):
    creations = []

    async def make(*, cwd, allowed_tools):
        creations.append((cwd, allowed_tools))
        client = _FakeClient(cwd, allowed_tools, events, messages or _ok_messages(), on_query=on_query)
        await client.connect()
        return client

    return make, creations


def _ask(transport, cwd="/repository", tools=("Read",), timeout=10):
    args = ("--allowedTools", ",".join(tools)) if tools else ()
    return transport.ask("prompt", cwd=cwd, claude_bin="claude", args=args, timeout=timeout)


def test_allowed_tools_read_from_the_guarded_args():
    assert _allowed_tools_from_args(_compose_claude_args((), unsafe=False, allowed_tools=())) == ()
    repository = _compose_claude_args(("--model", "x"), unsafe=False)
    assert _allowed_tools_from_args(repository) == ("Read", "Grep", "Glob", "LS")


def test_env_args_cannot_widen_sdk_tools_unless_unsafe():
    guarded = _compose_claude_args(("--allowedTools", "Bash,Write"), unsafe=False)
    assert _allowed_tools_from_args(guarded) == ("Read", "Grep", "Glob", "LS")
    unsafe = _compose_claude_args(("--allowedTools", "Bash"), unsafe=True)
    assert _allowed_tools_from_args(unsafe) == ("Bash",)


def test_result_from_messages_extracts_assistant_text():
    assert _result_from_messages(_ok_messages("hello")) == "hello"


def test_result_from_messages_falls_back_to_the_result_field():
    msgs = [SimpleNamespace(subtype="success", is_error=False, result="from-result")]
    assert _result_from_messages(msgs) == "from-result"


def test_result_from_messages_raises_on_an_error_result():
    msgs = [SimpleNamespace(subtype="error_max_turns", is_error=True, result="")]
    with pytest.raises(RuntimeError):
        _result_from_messages(msgs)


def test_result_from_messages_raises_on_an_error_status():
    msgs = [SimpleNamespace(subtype="success", is_error=False, api_error_status=429, result="")]
    with pytest.raises(RuntimeError):
        _result_from_messages(msgs)


def test_result_from_messages_raises_when_no_result_message():
    # a stream that ended before the result is a broken call, not a clean empty answer
    msgs = [SimpleNamespace(content=[SimpleNamespace(text="partial")], model="m")]
    with pytest.raises(RuntimeError, match="without a result"):
        _result_from_messages(msgs)


def test_result_from_messages_raises_on_empty_reply():
    msgs = [SimpleNamespace(subtype="success", is_error=False, result="")]
    with pytest.raises(RuntimeError, match="empty"):
        _result_from_messages(msgs)


def test_transport_returns_text_and_reuses_one_session_serially():
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=2, max_turns=8)
    assert _ask(t) == "ok"
    assert _ask(t) == "ok"
    t.close()
    # serial asks free the session back to idle, so one session serves both, one client made
    assert len(creations) == 1


def test_session_restarts_after_max_turns():
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=2)
    for _ in range(4):
        assert _ask(t) == "ok"
    t.close()
    # two prompts per client, so four asks span two clients
    assert len(creations) == 2


def test_session_restarts_when_cwd_changes():
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    _ask(t, cwd="/a")
    _ask(t, cwd="/a")
    _ask(t, cwd="/b")
    t.close()
    assert [c[0] for c in creations] == ["/a", "/b"]


def test_session_restarts_when_tools_change():
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    _ask(t, tools=("Read",))
    _ask(t, tools=("Read", "Grep"))
    t.close()
    assert [c[1] for c in creations] == [("Read",), ("Read", "Grep")]


def test_a_failed_call_closes_the_session_and_the_next_call_restarts():
    events = []
    bad = [SimpleNamespace(subtype="error_during_execution", is_error=True, result="")]
    make, _creations = _factory(events, messages=bad)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    with pytest.raises(RuntimeError):
        _ask(t)
    # the failed call disconnects its client, so the poisoned session cannot serve the next unit
    assert any(e[0] == "disconnect" for e in events)
    t.close()


def test_concurrent_asks_do_not_share_a_client():
    events = []
    barrier = threading.Barrier(2)
    seen_ids: list[int] = []
    lock = threading.Lock()

    def on_query(client):
        with lock:
            seen_ids.append(id(client))
        # hold both asks in flight at once, so a shared client would be driven by two threads
        barrier.wait(timeout=10)

    make, creations = _factory(events, on_query=on_query)
    t = SdkClaudeTransport(make_client=make, pool_size=2, max_turns=8)
    results: dict[int, str] = {}

    def call(i):
        results[i] = _ask(t)

    threads = [threading.Thread(target=call, args=(i,)) for i in (1, 2)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=10)
    t.close()
    assert results == {1: "ok", 2: "ok"}
    assert len(creations) == 2
    assert len(set(seen_ids)) == 2


def test_resolve_transport_selects_sdk_and_reports_both_on_unknown():
    assert isinstance(_resolve_transport("sdk"), SdkClaudeTransport)
    with pytest.raises(RuntimeError, match="process' or 'sdk'"):
        _resolve_transport("bogus")


def test_sdk_is_the_default_transport(monkeypatch):
    monkeypatch.delenv("CYBERJURY_CLAUDE_TRANSPORT", raising=False)
    assert isinstance(_resolve_transport(), SdkClaudeTransport)


def test_int_env_fails_loud_on_a_non_integer(monkeypatch):
    monkeypatch.setenv("CYBERJURY_CLAUDE_SDK_POOL_SIZE", "lots")
    with pytest.raises(RuntimeError, match="must be an integer"):
        _int_env("CYBERJURY_CLAUDE_SDK_POOL_SIZE", 6)


def test_missing_sdk_package_fails_loud(monkeypatch):
    monkeypatch.setattr(claude_agent, "_SDK", None)
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
    with pytest.raises(RuntimeError, match="claude-agent-sdk"):
        claude_agent._import_sdk()


def test_sdk_options_carry_the_allowlist_and_scrub_auth(monkeypatch):
    import claude_agent_sdk as sdk

    monkeypatch.setenv("ANTHROPIC_API_KEY", "stale")
    monkeypatch.setenv("PATH_KEEPME", "1")
    env = claude_agent._subscription_env()
    diff = claude_agent._sdk_options(sdk, cwd="", allowed_tools=(), cli_path="claude", env=env)
    assert diff.allowed_tools == []
    repository = claude_agent._sdk_options(
        sdk, cwd="/r", allowed_tools=("Read", "Grep", "Glob", "LS"), cli_path="claude", env=env
    )
    assert repository.allowed_tools == ["Read", "Grep", "Glob", "LS"]
    assert "ANTHROPIC_API_KEY" not in repository.env
    assert repository.env["PATH_KEEPME"] == "1"
