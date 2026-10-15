"""Generate sandbox web PoC scripts without executing them.

For a candidate it writes a standalone Python script that reproduces the exploit, so a
web finding carries a concrete runnable recipe, not only a prose scenario. It grounds
the script on the finding's endpoint and the handler source, so the request shape is
read from the code rather than guessed. Execution remains human controlled because a
web exploit needs a live server, credentials, and state. A written but unrun PoC never
refutes or lowers a finding.
"""

from __future__ import annotations

import ast
import re

from cyberjury.profiles.base import PoCArtifact
from cyberjury.providers.base import Message, Provider
from cyberjury.review.prompts import UNTRUSTED_SOURCE_RULE

_SYSTEM = (
    "You write a single self-contained Python script that reproduces one web application "
    "vulnerability. Use only the requests library and the standard library. Read the target base "
    "url from the BASE_URL environment variable and read any test credential from a named "
    "environment variable, so the script needs no other input. Use the endpoint and the request "
    "shape you can read from the handler source you are given, do not invent a route or a field. "
    "Perform the minimal steps, such as authenticating and then sending the exploit request, and "
    "assert that the exploit succeeded, for example that it read another user's resource or "
    "performed an action it must not. Never perform a destructive action and never target a "
    "production host. Respond with only the Python source of the script, no prose and no fences. "
    + UNTRUSTED_SOURCE_RULE
)

_RUN_HINT = "python the script, set BASE_URL to a sandbox or dev host, never production"

_MAX_HANDLER_SOURCE_CHARS = 12_000


def _extract_python(text: str) -> str:
    """The Python body from a model reply, tolerating a fenced block or bare source."""
    fence = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


def _parse_error(source: str) -> str:
    """Return why a generated script is not runnable Python, or an empty string when it is."""
    try:
        parsed = ast.parse(source)
    except SyntaxError as exc:
        return f"PoC does not parse as Python: {exc}"
    if not parsed.body:
        return "PoC contains no executable Python statements"
    return ""


def _source_window(text: str, *, line: int | None = None) -> str:
    """Keep the cited source line inside the bounded PoC evidence window."""
    lines = text.splitlines(keepends=True)
    if line is not None and (isinstance(line, bool) or line < 1 or line > len(lines)):
        raise ValueError("PoC source location is outside the handler file")
    if len(text) > _MAX_HANDLER_SOURCE_CHARS:
        if line is None:
            raise ValueError("PoC generation needs a cited line for a large handler file")
        left = right = line - 1
        size = len(lines[left])
        if size > _MAX_HANDLER_SOURCE_CHARS:
            raise ValueError("PoC source line exceeds the evidence budget")
        while True:
            advanced = False
            if left > 0 and size + len(lines[left - 1]) <= _MAX_HANDLER_SOURCE_CHARS:
                left -= 1
                size += len(lines[left])
                advanced = True
            if right + 1 < len(lines) and size + len(lines[right + 1]) <= _MAX_HANDLER_SOURCE_CHARS:
                right += 1
                size += len(lines[right])
                advanced = True
            if not advanced:
                break
        excerpt = "".join(lines[left : right + 1])
        before = f"... source before line {left + 1} omitted ...\n" if left else ""
        after = "\n... later source omitted ..." if right + 1 < len(lines) else ""
        return f"{before}{excerpt}{after}"
    return text


class WebPoC:
    """Write a candidate's exploit as a runnable Python script for manual execution."""

    ext = "py"

    def __init__(self, *, provider: Provider, model: str, max_tokens: int = 4096) -> None:
        """Bind the model used to write sandbox only web PoCs."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens

    def generate(
        self, *, title: str, analysis: str, symbol: str, file: str, line: int | None, source: str, endpoint: str = ""
    ) -> PoCArtifact:
        """Write the Python script that proves the exploit, without running it."""
        if not source.strip():
            raise ValueError("PoC generation needs readable handler source")
        prompt = _prompt(
            title=title,
            analysis=analysis,
            symbol=symbol,
            file=file,
            line=line,
            endpoint=endpoint,
            source=_source_window(source, line=line),
        )
        reply = self._provider.complete(
            system=_SYSTEM,
            messages=[Message(role="user", content=prompt)],
            model=self._model,
            max_tokens=self._max_tokens,
            cache=False,
        )
        script = _extract_python(reply.text)
        if not script:
            raise ValueError("PoC generation returned empty Python source")
        if error := _parse_error(script):
            raise ValueError(error)
        return PoCArtifact(source=script, run_hint=_RUN_HINT)


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
    parts.append(f"\nSource of the handler file ({file}):\n{source}")
    return "\n".join(parts)
