"""Web PoC writing for the web domain. For a candidate it writes a standalone Python script
that reproduces the exploit, so a web finding carries a concrete runnable recipe, not only a
prose scenario. It grounds the script on the finding's endpoint and the handler source, so the
request shape is read from the code rather than guessed.

It writes, it does not run, invariant 6. A web exploit needs a live server, credentials, and
state, so running is human-in-the-loop against a sandbox or dev host, never automatic and never
production. `execute` therefore reports the PoC as unrun, it never sends a request itself.

It only adds evidence, it never refutes, invariant 2. A finding is kept whether or not a human
later runs the script, so a written but unrun PoC lowers nothing and drops nothing.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from cyberjury.domains.base import PoCArtifact, PoCExecResult
from cyberjury.providers.base import Message, Provider

_SYSTEM = (
    "You write a single self-contained Python script that reproduces one web application "
    "vulnerability. Use only the requests library and the standard library. Read the target base "
    "url from the BASE_URL environment variable and read any test credential from a named "
    "environment variable, so the script needs no other input. Use the endpoint and the request "
    "shape you can read from the handler source you are given, do not invent a route or a field. "
    "Perform the minimal steps, such as authenticating and then sending the exploit request, and "
    "assert that the exploit succeeded, for example that it read another user's resource or "
    "performed an action it must not. Never perform a destructive action and never target a "
    "production host. Respond with only the Python source of the script, no prose and no fences."
)

_RUN_HINT = "python the script, set BASE_URL to a sandbox or dev host, never production"

# a cap on the handler source folded into the prompt, so a large file cannot crowd out the
# instruction. Truncation is marked, never silent, invariant 4.
_SOURCE_CAP = 12000


def _extract_python(text: str) -> str:
    """The Python body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


def _parse_note(source: str) -> str:
    """A warning when the written script is not valid Python, empty when it parses. It flags the
    artifact, it never refutes the finding, invariant 2."""
    try:
        ast.parse(source)
    except SyntaxError as exc:
        return f"PoC does not parse as Python: {exc}"
    return ""


def _read_source(p: Path) -> str:
    """The handler source at `p`, truncated past `_SOURCE_CAP` with a marker, empty when unreadable."""
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    if len(text) > _SOURCE_CAP:
        return text[:_SOURCE_CAP] + "\n... source truncated ..."
    return text


class WebPoC:
    """Write a candidate's exploit as a runnable Python script. It writes, a human runs it against
    a sandbox, invariant 6. Adds evidence, never refutes, invariant 2."""

    ext = "py"
    # the web domain never runs its PoC automatically, so the write step writes and the shared run
    # step reports it as manual rather than expecting a toolchain, unlike the evm forge backend
    executes = False

    def __init__(self, *, provider: Provider | None = None, model: str | None = None, max_tokens: int = 4096) -> None:
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def available(self) -> bool:
        """A web PoC is never executed automatically, so nothing here runs it, invariant 6."""
        return False

    def generate(
        self, *, title: str, analysis: str, symbol: str, file: str, line: int | None, root: str, endpoint: str = ""
    ) -> PoCArtifact:
        """Write the Python script that proves the exploit, without running it."""
        if self._provider is None:
            raise ValueError("generating a PoC needs a provider, this backend was built to run only")
        source = _read_source(Path(root) / file) if file else ""
        prompt = _prompt(
            title=title, analysis=analysis, symbol=symbol, file=file, line=line, endpoint=endpoint, source=source
        )
        reply = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=False,
        )
        source = _extract_python(reply.text)
        return PoCArtifact(source=source, ext=self.ext, run_hint=_RUN_HINT, note=_parse_note(source))

    def execute(self, *, source: str, root: str) -> PoCExecResult:
        """Report the web PoC as unrun. Running it hits a live server, so a human does that against
        a sandbox, this never sends a request, invariant 6."""
        return PoCExecResult(
            ran=False, ok=False, detail="a web PoC runs by hand against a sandbox, never automatically, invariant 6"
        )


def _prompt(*, title: str, analysis: str, symbol: str, file: str, line: int | None, endpoint: str, source: str) -> str:
    loc = f"{file}:{line}" if line else file
    parts = [
        f"Vulnerability: {title}",
        f"Location: {loc}",
        f"Function or handler: {symbol}",
    ]
    if endpoint:
        parts.append(f"HTTP endpoint: {endpoint}")
    parts.append(f"Analysis: {analysis}")
    if source:
        parts.append(f"\nSource of the handler file ({file}):\n{source}")
    guide = "\nWrite the script that reproduces this vulnerability against a running instance."
    if endpoint or source:
        guide += " Read the route and the request fields from the endpoint and source above, do not guess them."
    guide += " It passes only when the exploit succeeds."
    parts.append(guide)
    return "\n".join(parts)
