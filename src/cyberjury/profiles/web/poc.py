"""Generate sandbox web PoC scripts without executing them.

For a candidate it writes a standalone Python script that reproduces the exploit, so a
web finding carries a concrete runnable recipe, not only a prose scenario. It grounds
the script on the finding's endpoint and the handler source, so the request shape is
read from the code rather than guessed. Execution remains human controlled under
invariant 6 because a web exploit needs a live server, credentials, and state. The
`execute` method reports the PoC as unrun and never sends a request. A written but unrun
PoC cannot refute or lower a finding under invariant 2.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from cyberjury.profiles.base import PoCArtifact, PoCExecResult
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

_MAX_HANDLER_SOURCE_CHARS = 12_000


def _extract_python(text: str) -> str:
    """The Python body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


def _parse_note(source: str) -> str:
    """Return a parse warning without using invalid output to refute a finding."""
    try:
        ast.parse(source)
    except SyntaxError as exc:
        return f"PoC does not parse as Python: {exc}"
    return ""


def _read_source(p: Path) -> str:
    """Read bounded handler source, returning an empty string when it is unavailable."""
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    if len(text) > _MAX_HANDLER_SOURCE_CHARS:
        return text[:_MAX_HANDLER_SOURCE_CHARS] + "\n... source truncated ..."
    return text


class WebPoC:
    """Write a candidate's exploit as a runnable Python script.

    The script is generated for manual sandbox execution. It can add evidence to a
    finding, but it never refutes or lowers one because execution is operator controlled.
    """

    ext = "py"
    executes = False
    install_hint = ""

    def __init__(self, *, provider: Provider | None = None, model: str | None = None, max_tokens: int = 4096) -> None:
        """Bind the optional model used to write sandbox only web PoCs."""
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
        return PoCArtifact(source=source, run_hint=_RUN_HINT, note=_parse_note(source))

    def execute(self, *, source: str, root: str) -> PoCExecResult:
        """Report the web PoC as unrun.

        Running it hits a live server, so a human does that against a sandbox, this never sends
        a request, invariant 6.
        """
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
