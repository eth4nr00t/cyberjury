"""The persistent Claude Agent SDK transport is exercised with a fake async client."""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace

import pytest

from cyberjury.providers import claude_agent
from cyberjury.providers.base import Usage
from cyberjury.providers.claude_agent import (
    ProcessClaudeTransport,
    SdkClaudeTransport,
    _allowed_tools_from_args,
    _compose_claude_args,
    _int_env,
    _resolve_transport,
    _result_from_messages,
    _result_text,
    _result_usage,
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


def _ask_text(transport, **kw):
    """The assistant text is unwrapped from the ask envelope."""
    return _result_text(_ask(transport, **kw))


def test_allowed_tools_read_from_the_guarded_args():
    """Allowed tools read from the guarded args."""
    assert _allowed_tools_from_args(_compose_claude_args((), unsafe=False, allowed_tools=())) == ()
    repository = _compose_claude_args(("--model", "x"), unsafe=False)
    assert _allowed_tools_from_args(repository) == ("Read", "Grep", "Glob", "LS")


def test_env_args_cannot_widen_sdk_tools_unless_unsafe():
    """Env args cannot widen SDK tools unless unsafe."""
    guarded = _compose_claude_args(("--allowedTools", "Bash,Write"), unsafe=False)
    assert _allowed_tools_from_args(guarded) == ("Read", "Grep", "Glob", "LS")
    unsafe = _compose_claude_args(("--allowedTools", "Bash"), unsafe=True)
    assert _allowed_tools_from_args(unsafe) == ("Bash",)


def test_result_from_messages_extracts_assistant_text():
    """Result from messages extracts assistant text."""
    assert _result_from_messages(_ok_messages("hello")) == "hello"


def test_the_sdk_transport_carries_the_token_counts_through():
    """SDK transport carries the token counts through."""
    events = []
    counts = {"input_tokens": 7, "output_tokens": 9, "cache_read_input_tokens": 11, "cache_creation_input_tokens": 13}
    messages = [
        SimpleNamespace(content=[SimpleNamespace(text="ok")], model="m"),
        SimpleNamespace(subtype="success", is_error=False, result="ok", usage=counts),
    ]
    make, _creations = _factory(events, messages=messages)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    usage = _result_usage(_ask(t))
    t.close()
    assert usage.input_tokens == 7
    assert usage.output_tokens == 9
    assert usage.cache_read_tokens == 11
    assert usage.cache_write_tokens == 13


def test_the_sdk_transport_reports_zero_counts_when_the_sdk_gives_none():
    """SDK transport reports zero counts when the SDK gives none."""
    events = []
    make, _creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    usage = _result_usage(_ask(t))
    t.close()
    assert usage == Usage()


def test_result_from_messages_falls_back_to_the_result_field():
    """Result from messages falls back to the result field."""
    msgs = [SimpleNamespace(subtype="success", is_error=False, result="from-result")]
    assert _result_from_messages(msgs) == "from-result"


def test_result_from_messages_raises_on_an_error_result():
    """Result from messages raises on an error result."""
    msgs = [SimpleNamespace(subtype="error_max_turns", is_error=True, result="")]
    with pytest.raises(RuntimeError):
        _result_from_messages(msgs)


def test_result_from_messages_raises_on_an_error_status():
    """Result from messages raises on an error status."""
    msgs = [SimpleNamespace(subtype="success", is_error=False, api_error_status=429, result="")]
    with pytest.raises(RuntimeError):
        _result_from_messages(msgs)


def test_result_from_messages_raises_when_no_result_message():
    """Result from messages raises when no result message."""
    msgs = [SimpleNamespace(content=[SimpleNamespace(text="partial")], model="m")]
    with pytest.raises(RuntimeError, match="without a result"):
        _result_from_messages(msgs)


def test_result_from_messages_raises_on_empty_reply():
    """Result from messages raises on empty reply."""
    msgs = [SimpleNamespace(subtype="success", is_error=False, result="")]
    with pytest.raises(RuntimeError, match="empty"):
        _result_from_messages(msgs)


def test_transport_reuses_one_session_across_serial_asks():
    """Transport reuses one session across serial asks."""
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=2, max_turns=8)
    assert _ask_text(t) == "ok"
    assert _ask_text(t) == "ok"
    t.close()
    assert len(creations) == 1


def test_session_restarts_after_max_turns():
    """Session restarts after max turns."""
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=2)
    for _ in range(4):
        assert _ask_text(t) == "ok"
    t.close()
    assert len(creations) == 2


def test_session_restarts_when_cwd_changes():
    """Session restarts when cwd changes."""
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    _ask(t, cwd="/a")
    _ask(t, cwd="/a")
    _ask(t, cwd="/b")
    t.close()
    assert [c[0] for c in creations] == ["/a", "/b"]


def test_session_restarts_when_tools_change():
    """Session restarts when tools change."""
    events = []
    make, creations = _factory(events)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    _ask(t, tools=("Read",))
    _ask(t, tools=("Read", "Grep"))
    t.close()
    assert [c[1] for c in creations] == [("Read",), ("Read", "Grep")]


def test_a_failed_call_closes_the_session_and_the_next_call_restarts():
    """Failed call closes the session and the next call restarts."""
    events = []
    bad = [SimpleNamespace(subtype="error_during_execution", is_error=True, result="")]
    make, _creations = _factory(events, messages=bad)
    t = SdkClaudeTransport(make_client=make, pool_size=1, max_turns=8)
    with pytest.raises(RuntimeError):
        _ask(t)
    assert any(e[0] == "disconnect" for e in events)
    t.close()


def test_concurrent_asks_do_not_share_a_client():
    """Concurrent asks do not share a client."""
    events = []
    barrier = threading.Barrier(2)
    seen_ids: list[int] = []
    lock = threading.Lock()

    def on_query(client):
        with lock:
            seen_ids.append(id(client))
        barrier.wait(timeout=10)

    make, creations = _factory(events, on_query=on_query)
    t = SdkClaudeTransport(make_client=make, pool_size=2, max_turns=8)
    results: dict[int, str] = {}

    def call(i):
        results[i] = _ask_text(t)

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
    """Resolve transport selects SDK and reports both on unknown."""
    assert isinstance(_resolve_transport("sdk"), SdkClaudeTransport)
    with pytest.raises(RuntimeError, match="process' or 'sdk'"):
        _resolve_transport("bogus")


def test_process_is_the_default_transport(monkeypatch):
    """Process is the default transport."""
    monkeypatch.delenv("CYBERJURY_CLAUDE_TRANSPORT", raising=False)
    assert isinstance(_resolve_transport(), ProcessClaudeTransport)


def test_int_env_fails_loud_on_a_non_integer(monkeypatch):
    """Int env fails loud on a non integer."""
    monkeypatch.setenv("CYBERJURY_CLAUDE_SDK_POOL_SIZE", "lots")
    with pytest.raises(RuntimeError, match="must be an integer"):
        _int_env("CYBERJURY_CLAUDE_SDK_POOL_SIZE", 6)


def test_missing_sdk_package_fails_loud(monkeypatch):
    """Missing SDK package fails loud."""
    monkeypatch.setattr(claude_agent, "_SDK", None)
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
    with pytest.raises(RuntimeError, match="claude-agent-sdk"):
        claude_agent._import_sdk()


def test_sdk_options_carry_the_allowlist_and_scrub_auth(monkeypatch):
    """SDK options carry the allowlist and scrub auth."""
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
