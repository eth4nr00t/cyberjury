"""The headless `claude -p` transport, shared by every subscription backend.

A subscription seat runs a headless Claude Code agent via `claude -p` instead of calling
a vendor API, so it uses the operator's Claude Code access with no provider key or proxy
limit. The same transport serves both review paths: the repository backends in
`review/repository/agent.py` subclass `_ClaudeBackend` to read files themselves, and
`ClaudeAgentProvider` here is a drop-in `Provider` for the diff path, where the diff is
already in the prompt and no file tools are needed.

The exact `claude` invocation varies by version, so the binary and its args are
configurable, via the constructor or `CYBERJURY_CLAUDE_BIN` / `CYBERJURY_CLAUDE_ARGS`. The
prompt is fed on stdin so a large mandate does not hit the argv limit. The subprocess call
goes through an injected runner, so the backends are testable with no real `claude`.

The call runs through a `ClaudeTransport`, selected by `CYBERJURY_CLAUDE_TRANSPORT`, so the
persistent transport can amortize the Claude Code startup cost that a fresh process pays on
every call, without touching the retry or fail-loud path. The default is `sdk`, a persistent
Claude Agent SDK session. Set `CYBERJURY_CLAUDE_TRANSPORT=process` for one `claude -p` per
call. An injected runner still wins, so the tests keep their seam.

This module is a leaf: it imports only the standard library and `providers.base`, never
`review/` or `domains/`, so the transport sits at the provider layer and both paths depend
on it downward.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future

from cyberjury.providers.base import CompletionResult, Message, Provider, Usage

_OUTPUT_ARGS = ("--output-format", "json")
READ_ONLY_TOOLS = ("--allowedTools", "Read,Grep,Glob,LS")
DEFAULT_CLAUDE_ARGS = (*_OUTPUT_ARGS, *READ_ONLY_TOOLS)
_UNSAFE_TOOLS_ENV = "CYBERJURY_CLAUDE_UNSAFE_TOOLS"
# The nested `claude -p` must authenticate with the operator's Claude Code subscription, not an
# API key this process carries for its own provider call. An inherited ANTHROPIC_API_KEY or base URL,
# stale or pointed at a proxy, makes the nested agent 401 instead of riding the subscription, so
# they are scrubbed from its environment.
_SCRUBBED_AUTH_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")

Runner = Callable[..., str]


def _subscription_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _SCRUBBED_AUTH_ENV}


def _drop_flag(args: tuple[str, ...], flag: str) -> tuple[str, ...]:
    out: list[str] = []
    it = iter(args)
    for a in it:
        if a == flag:
            next(it, None)
            continue
        out.append(a)
    return tuple(out)


def _compose_claude_args(
    extra: tuple[str, ...], *, unsafe: bool, allowed_tools: tuple[str, ...] = READ_ONLY_TOOLS
) -> tuple[str, ...]:
    """The effective `claude -p` args. `allowed_tools` is mandatory and substituted by the caller,
    the repository backends read files so they pass the read-only set, the diff provider answers from the
    prompt so it passes none. Extra args from `CYBERJURY_CLAUDE_ARGS` or the constructor are appended,
    but any `--allowedTools` they carry is dropped, so a misconfigured environment cannot silently
    widen the tools. `CYBERJURY_CLAUDE_UNSAFE_TOOLS=1` is the one explicit way to hand tool selection
    to the extra args."""
    if unsafe:
        return (*_OUTPUT_ARGS, *extra)
    return (*_OUTPUT_ARGS, *allowed_tools, *_drop_flag(extra, "--allowedTools"))


def _envelope(stdout: str) -> dict[str, object] | None:
    """The parsed `--output-format json` envelope, or None when the reply is plain text."""
    try:
        env = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    return env if isinstance(env, dict) else None


def _envelope_error(stdout: str) -> str | None:
    """An error reported inside a `--output-format json` envelope, or None.

    A rate-limited or failed `claude -p` can still exit 0 while the envelope carries
    `is_error` or a non-success subtype. Treating that as success silently turns a
    failed call into an empty clean result, the exact thing the fail-loud rule
    forbids, so the runner must detect it and raise."""
    env = _envelope(stdout)
    if env is None:
        return None
    if env.get("is_error") or env.get("api_error_status") or env.get("subtype", "success") != "success":
        return str(env.get("api_error_status") or env.get("subtype") or "is_error")
    return None


def _default_runner(prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
    """Run `claude -p` headless with the prompt on stdin, return stdout, raise on error."""
    proc = subprocess.run(
        [claude_bin, "-p", *args],
        input=prompt,
        cwd=cwd or None,
        env=_subscription_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    err = _envelope_error(proc.stdout)
    if err:
        raise RuntimeError(f"claude reported an error ({err}): {proc.stdout.strip()[:200]}")
    return proc.stdout


def _result_text(stdout: str) -> str:
    """Pull the assistant text out of `--output-format json`, or pass plain text through."""
    env = _envelope(stdout)
    if env is not None and "result" in env:
        return str(env["result"])
    return stdout.strip()


def _int_field(usage: dict[str, object], key: str) -> int:
    value = usage.get(key)
    return int(value) if isinstance(value, (int, float)) else 0


def _result_usage(stdout: str) -> Usage:
    """The token counts inside a `--output-format json` envelope, so a subscription run can be
    costed and its cache behavior measured instead of reporting zeros.

    The envelope carries the Anthropic wire names, where `cache_creation_input_tokens` is the write
    and `cache_read_input_tokens` the read. It counts the model that answered, so a helper model
    Claude Code invoked on its own appears under `modelUsage` and not here. A reply that carries no
    counts stays zero, which reads as unreported rather than as free."""
    env = _envelope(stdout)
    usage = env.get("usage") if env is not None else None
    if not isinstance(usage, dict):
        return Usage()
    return Usage(
        input_tokens=_int_field(usage, "input_tokens"),
        output_tokens=_int_field(usage, "output_tokens"),
        cache_read_tokens=_int_field(usage, "cache_read_input_tokens"),
        cache_write_tokens=_int_field(usage, "cache_creation_input_tokens"),
    )


_TRANSPORT_ENV = "CYBERJURY_CLAUDE_TRANSPORT"


class ClaudeTransport:
    """One call equivalent to `claude -p`, behind the seam where a runner is injected.

    `ask` mirrors the `Runner` signature, so a transport drops into `_ClaudeBackend._ask`
    with no change to its retry or fail-loud path, and a test can still inject a plain runner
    instead. `close` releases any persistent session a transport holds, and does nothing for
    the stateless process transport. The tool policy travels inside `args`, already composed
    and guarded by `_compose_claude_args`, so a transport reads it rather than deriving it again.

    `ask` returns the `--output-format json` envelope, so `_result_text` and `_result_usage` read
    text and token counts the same way whichever transport ran. Bare text still parses as text, but
    a transport that returns it reports no usage, so a new one carries the envelope.
    """

    def ask(self, prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
        raise NotImplementedError

    def close(self) -> None:
        pass


class ProcessClaudeTransport(ClaudeTransport):
    """One `claude -p` process per call, opt-in via `CYBERJURY_CLAUDE_TRANSPORT=process`."""

    def ask(self, prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
        return _default_runner(prompt, cwd=cwd, claude_bin=claude_bin, args=args, timeout=timeout)


_SDK_TURNS_ENV = "CYBERJURY_CLAUDE_SDK_MAX_TURNS"
_SDK_POOL_ENV = "CYBERJURY_CLAUDE_SDK_POOL_SIZE"
_SDK = None


def _import_sdk():
    """The Claude Agent SDK module, imported lazily so this leaf stays importable without the
    optional extra. A missing package fails loud with an install hint rather than at some later
    call, so the transport never silently degrades, invariant 4."""
    global _SDK
    if _SDK is None:
        try:
            import claude_agent_sdk as sdk
        except ImportError as exc:
            raise RuntimeError(
                "claude-agent-sdk not installed, it is a base dependency, run: pip install cyberjury"
            ) from exc
        _SDK = sdk
    return _SDK


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc


def _allowed_tools_from_args(args: tuple[str, ...]) -> tuple[str, ...]:
    """The tool allowlist the SDK options need, read from the already composed and guarded
    `args`. The `--allowedTools` value there has passed `_compose_claude_args`, so the unsafe
    gate and the widening drop already apply, and the SDK path inherits the same policy rather
    than deriving it again. The diff path passes no `--allowedTools`, so it maps to no tools."""
    it = iter(args)
    for a in it:
        if a == "--allowedTools":
            return tuple(t for t in next(it, "").split(",") if t)
    return ()


def _result_from_messages(messages: list) -> str:
    """The assistant text from one SDK response, fail-loud on anything that is not a clean
    success. An error result, an error status, a non-success subtype, a stream that ended with
    no result message, or an empty reply each raise, so a failed call is never read as clean,
    invariant 4. The `ResultMessage.result` text is the fallback when no text block was seen."""
    texts: list[str] = []
    result_text = ""
    error = None
    saw_result = False
    for msg in messages:
        content = getattr(msg, "content", None)
        if isinstance(content, (list, tuple)):
            texts.extend(b.text for b in content if isinstance(getattr(b, "text", None), str))
        if hasattr(msg, "subtype") and hasattr(msg, "is_error"):
            saw_result = True
            status = getattr(msg, "api_error_status", None)
            if getattr(msg, "is_error", False) or status or getattr(msg, "subtype", "success") != "success":
                error = str(status or getattr(msg, "subtype", None) or "error")
            if isinstance(getattr(msg, "result", None), str):
                result_text = msg.result
    if error is not None:
        raise RuntimeError(f"claude SDK error: {error}")
    if not saw_result:
        raise RuntimeError("claude SDK stream ended without a result message")
    text = "".join(texts).strip() or result_text.strip()
    if not text:
        raise RuntimeError("claude SDK returned an empty result")
    return text


def _usage_from_messages(messages: list) -> dict[str, object]:
    """The result message's token counts, or empty when the SDK reports none. Identified the same
    way `_result_from_messages` finds the result message, by the subtype and error fields."""
    for msg in messages:
        if hasattr(msg, "subtype") and hasattr(msg, "is_error"):
            usage = getattr(msg, "usage", None)
            if isinstance(usage, dict):
                return usage
    return {}


async def _collect(client, prompt: str, timeout: int) -> str:
    """Send one prompt on a connected client and gather the response, bounded by `timeout`.

    Returns the envelope `claude -p --output-format json` returns rather than bare text, so both
    transports hand the same shape downstream and the token counts survive the default SDK path.
    `_result_from_messages` still raises first on anything that is not a clean success."""

    async def go() -> list:
        await client.query(prompt)
        return [m async for m in client.receive_response()]

    messages = await asyncio.wait_for(go(), timeout)
    return json.dumps({"result": _result_from_messages(messages), "usage": _usage_from_messages(messages)})


def _sdk_options(sdk, *, cwd: str, allowed_tools: tuple[str, ...], cli_path: str, env: dict[str, str]):
    """The SDK options for one session. `allowed_tools` is the guarded allowlist, so the SDK
    session grants exactly the tools the process path would, no more. `env` is the scrubbed
    environment, so the nested Claude Code authenticates the subscription, not a stale key."""
    return sdk.ClaudeAgentOptions(
        allowed_tools=list(allowed_tools),
        cwd=cwd or None,
        cli_path=cli_path,
        env=env,
    )


class _SdkSession:
    """One thread, kept alive for the run, owning its own event loop and one `ClaudeSDKClient`.

    The client is bound to the loop that created it, so the session drives it only from its own
    thread and never shares it across threads, the isolation a concurrent run needs. The client
    is restarted when the working directory or the tool allowlist changes, or after `max_turns`
    prompts, so context does not accumulate unbounded across independent unit reviews. A failed
    call closes the client, so a broken session does not poison the next unit."""

    def __init__(self, *, make_client, max_turns: int) -> None:
        self._make_client = make_client
        self._max_turns = max_turns
        self._jobs: queue.Queue = queue.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client = None
        self._turns = 0
        self._cwd: str | None = None
        self._tools: tuple[str, ...] | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def submit(self, prompt: str, cwd: str, tools: tuple[str, ...], timeout: int) -> Future:
        fut: Future = Future()
        self._jobs.put(("ask", prompt, cwd, tools, timeout, fut))
        return fut

    def shutdown(self) -> None:
        fut: Future = Future()
        self._jobs.put(("stop", "", "", (), 0, fut))
        with contextlib.suppress(Exception):
            fut.result(timeout=30)
        self._thread.join(timeout=5)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            while True:
                kind, prompt, cwd, tools, timeout, fut = self._jobs.get()
                if kind == "stop":
                    self._loop.run_until_complete(self._close())
                    fut.set_result(None)
                    return
                try:
                    if self._needs_restart(cwd, tools):
                        self._loop.run_until_complete(self._restart(cwd, tools))
                    self._turns += 1
                    fut.set_result(self._loop.run_until_complete(_collect(self._client, prompt, timeout)))
                except Exception as exc:
                    self._loop.run_until_complete(self._close())
                    fut.set_exception(exc)
        finally:
            self._loop.close()

    def _needs_restart(self, cwd: str, tools: tuple[str, ...]) -> bool:
        return self._client is None or cwd != self._cwd or tools != self._tools or self._turns >= self._max_turns

    async def _restart(self, cwd: str, tools: tuple[str, ...]) -> None:
        await self._close()
        self._client = await self._make_client(cwd=cwd, allowed_tools=tools)
        self._cwd, self._tools, self._turns = cwd, tools, 0

    async def _close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.disconnect()
            self._client = None


class SdkClaudeTransport(ClaudeTransport):
    """A persistent Claude Agent SDK transport for the subscription seat.

    It keeps a bounded pool of `_SdkSession` workers alive across passes, so the Claude Code
    startup cost is paid once per session rather than once per prompt. A caller thread borrows
    an idle session, runs one prompt, and returns it, so concurrency is capped at the pool size
    and no session is driven by two threads at once. The tool policy and the scrubbed auth match
    the process transport. `close` shuts every session down, releasing the managed processes."""

    def __init__(
        self,
        *,
        pool_size: int | None = None,
        max_turns: int | None = None,
        cli_path: str | None = None,
        env: dict[str, str] | None = None,
        make_client=None,
    ) -> None:
        self._cli_path = cli_path or os.environ.get("CYBERJURY_CLAUDE_BIN") or shutil.which("claude") or "claude"
        self._env = env if env is not None else _subscription_env()
        self._pool_size = pool_size if pool_size is not None else _int_env(_SDK_POOL_ENV, 6)
        self._max_turns = max_turns if max_turns is not None else _int_env(_SDK_TURNS_ENV, 8)
        # an injected factory is the test seam, otherwise the real SDK, imported now so a missing
        # package fails loud at construction rather than mid-run
        if make_client is None:
            _import_sdk()
        self._make_client = make_client or self._make
        self._idle: queue.Queue = queue.Queue()
        self._sessions: list[_SdkSession] = []
        self._created = 0
        self._lock = threading.Lock()

    async def _make(self, *, cwd: str, allowed_tools: tuple[str, ...]):
        sdk = _import_sdk()
        client = sdk.ClaudeSDKClient(
            options=_sdk_options(sdk, cwd=cwd, allowed_tools=allowed_tools, cli_path=self._cli_path, env=self._env)
        )
        await client.connect()
        return client

    def ask(self, prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
        tools = _allowed_tools_from_args(args)
        session = self._acquire()
        try:
            return session.submit(prompt, cwd, tools, timeout).result()
        finally:
            self._idle.put(session)

    def _acquire(self) -> _SdkSession:
        try:
            return self._idle.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            if self._created < self._pool_size:
                session = _SdkSession(make_client=self._make_client, max_turns=self._max_turns)
                self._sessions.append(session)
                self._created += 1
                return session
        return self._idle.get()

    def close(self) -> None:
        with self._lock:
            sessions = list(self._sessions)
            self._sessions.clear()
            self._created = 0
        for session in sessions:
            session.shutdown()


def _resolve_transport(name: str | None = None) -> ClaudeTransport:
    """The transport named by `CYBERJURY_CLAUDE_TRANSPORT`, `sdk` by default. An unknown
    value fails loud at construction rather than silently falling back to a working default,
    so a misconfigured transport cannot pass as a clean run, invariant 4."""
    name = name if name is not None else os.environ.get(_TRANSPORT_ENV, "sdk")
    if name == "process":
        return ProcessClaudeTransport()
    if name == "sdk":
        return SdkClaudeTransport()
    raise RuntimeError(f"unknown {_TRANSPORT_ENV} {name!r}, expected 'process' or 'sdk'")


class _ClaudeBackend:
    def __init__(
        self,
        *,
        claude_bin: str | None = None,
        args: tuple[str, ...] | None = None,
        timeout: int = 900,
        retries: int = 2,
        backoff: float = 10.0,
        runner: Runner | None = None,
        transport: ClaudeTransport | None = None,
        allowed_tools: tuple[str, ...] = READ_ONLY_TOOLS,
    ) -> None:
        self._bin = claude_bin or os.environ.get("CYBERJURY_CLAUDE_BIN", "claude")
        env_args = os.environ.get("CYBERJURY_CLAUDE_ARGS")
        extra = tuple(shlex.split(env_args)) if env_args else (tuple(args) if args else ())
        unsafe = os.environ.get(_UNSAFE_TOOLS_ENV) == "1"
        self._args = _compose_claude_args(extra, unsafe=unsafe, allowed_tools=allowed_tools)
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        # An injected runner wins, the test seam. Otherwise a transport runs the call: the one
        # passed in, or the one CYBERJURY_CLAUDE_TRANSPORT selects, sdk by default. The
        # transport is held so a persistent one can be closed at the end of a run.
        self._transport = None if runner is not None else (transport or _resolve_transport())
        self._runner = runner if runner is not None else self._transport.ask

    def _ask(self, prompt: str, cwd: str) -> str:
        """Run the agent, retrying with backoff, since a rate limit is usually transient.
        Raises the last error if every attempt fails, so the orchestrator counts it."""
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                return self._runner(prompt, cwd=cwd, claude_bin=self._bin, args=self._args, timeout=self._timeout)
            except Exception as exc:
                last = exc
                if attempt < self._retries and self._backoff:
                    time.sleep(self._backoff * (attempt + 1))
        assert last is not None
        raise last

    def close(self) -> None:
        """Release the transport's persistent session, if any. It does nothing when a runner
        was injected or the transport is stateless, and is safe to call more than once."""
        if self._transport is not None:
            self._transport.close()


def _fold_prompt(system: str, messages: list[Message]) -> str:
    """Fold the system text and messages into one stdin prompt, since `claude -p` has no separate
    system channel. The system text leads so a 'respond with a single JSON object' instruction still
    governs the reply. A role label is added only when more than one message would be ambiguous, so
    the single-message diff calls stay verbatim."""
    parts: list[str] = []
    if system:
        parts.append(system)
    multi = len(messages) > 1
    for m in messages:
        parts.append(f"[{m.role}] {m.content}" if multi else m.content)
    return "\n\n".join(parts)


class ClaudeAgentProvider(_ClaudeBackend, Provider):
    """A Provider that answers through a headless `claude -p` agent on the operator's Claude Code
    subscription instead of a vendor API, so a path runs with no provider key. The diff is already
    in the prompt, so the agent takes no file tools. `model` is advisory, the subscription picks the
    model and no `--model` is passed. `cache` does not apply to a subprocess call. A blank or
    error-enveloped reply raises through `_ask`, never returns as an empty clean result."""

    def __init__(self, *, cwd: str = "", **kw) -> None:
        super().__init__(allowed_tools=(), **kw)
        self._cwd = cwd

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
        cache_prefix: str = "",
    ) -> CompletionResult:
        stdout = self._ask(_fold_prompt(system, messages), self._cwd)
        return CompletionResult(text=_result_text(stdout), usage=_result_usage(stdout))
