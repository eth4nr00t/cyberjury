"""Repository-review backends that run as a headless Claude Code agent via `claude -p`.

A per-unit review, a per-candidate verification, and a refutation audit, each run on the
operator's Claude Code subscription with no provider key, and each a real tool-using
agent that reads the files itself and traces across them, rather than a single grounded
call. The `claude -p` transport, the runner, env scrub, envelope-error fail-loud, and
retry, lives in `cyberjury.providers.claude_agent` so the diff path's
`ClaudeAgentProvider` shares it. These backends subclass `_ClaudeBackend` from there and
pass the read-only tools they need to read files. The names are re-exported below so
existing imports and tests keep resolving here.
"""

from __future__ import annotations

from cyberjury.domains.base import ContentPaths
from cyberjury.json_parse import optional_json_object, require_json_object
from cyberjury.providers.claude_agent import (
    DEFAULT_CLAUDE_ARGS,
    READ_ONLY_TOOLS,
    Runner,
    _ClaudeBackend,
    _compose_claude_args,
    _default_runner,
    _envelope_error,
    _result_text,
    _subscription_env,
)
from cyberjury.resources import FALSE_POSITIVE_TRAPS_FILE, SEVERITY_RUBRIC_FILE, UNIT_REVIEW_FILE
from cyberjury.review.repository.reviewer import (
    RepositoryReviewError,
    UnitReviewer,
    candidates_from_obj,
)
from cyberjury.review.repository.shapes import JSON_SHAPE, Unit, lens_line
from cyberjury.review.repository.union import Candidate
from cyberjury.review.repository.verifier import RefutationChecker, Verdict, Verifier, VerifyError

__all__ = [
    "DEFAULT_CLAUDE_ARGS",
    "READ_ONLY_TOOLS",
    "AgentRefutationChecker",
    "AgentReviewer",
    "AgentVerifier",
    "Runner",
    "_ClaudeBackend",
    "_compose_claude_args",
    "_default_runner",
    "_envelope_error",
    "_result_text",
    "_subscription_env",
]


class AgentReviewer(_ClaudeBackend, UnitReviewer):
    """Per-unit review as a headless Claude Code agent that reads the files itself."""

    def __init__(self, *, content: ContentPaths | None = None, **kw) -> None:
        """Initialize the AgentReviewer instance."""
        super().__init__(**kw)
        mandate_file = content.unit_review_file if content else UNIT_REVIEW_FILE
        rubric_file = content.severity_rubric_file if content else SEVERITY_RUBRIC_FILE
        self._mandate = mandate_file.read_text(encoding="utf-8")
        self._rubric = rubric_file.read_text(encoding="utf-8")

    def review(self, unit: Unit, lens: str, *, shared_context: str = "") -> list[Candidate]:
        """Review one repository unit through the configured backend."""
        files = "\n".join(f"- {f}" for f in unit.files)
        prompt = (
            f"{self._mandate}\n\n---\nSeverity rubric:\n{self._rubric}\n\n---\n{lens_line(lens)}"
            + (f"Stack and authorization model:\n{shared_context}\n\n" if shared_context else "")
            + f"Review unit `{unit.name}`. Read these files yourself and trace into the "
            f"managers, dao, controllers, and libraries they call:\n{files}\n\n"
            f"Respond with a single JSON object exactly like:\n{JSON_SHAPE}"
        )
        obj = require_json_object(
            _result_text(self._ask(prompt, unit.root)),
            required_key="findings",
            error=RepositoryReviewError,
            message="the unit review reply had no JSON object, or a JSON object without a "
            "findings key, so it is a failed review rather than a clean unit",
        )
        return candidates_from_obj(obj)


_VERIFY_SHAPE = '{"real": true, "reason": "the controlling fact at file:line"}'


class AgentVerifier(_ClaudeBackend, Verifier):
    """Per-candidate refutation as a headless Claude Code agent that reads the code."""

    def __init__(self, *, content: ContentPaths | None = None, **kw) -> None:
        """Initialize the AgentVerifier instance."""
        super().__init__(**kw)
        traps_file = content.false_positive_traps_file if content else FALSE_POSITIVE_TRAPS_FILE
        self._traps = traps_file.read_text(encoding="utf-8")

    def verify(self, candidate: Candidate, root: str) -> Verdict:
        """Try to refute one candidate against the source tree."""
        prompt = (
            "Try to REFUTE this proposed finding. Read the cited code yourself and trace "
            "across files, then decide whether a controlling fact makes it genuinely safe, "
            "judging against PRODUCTION semantics, not a shallow read.\n\n"
            f"Traps to check against, in both directions, refuting a real finding as wrongly "
            f"as confirming a safe one:\n{self._traps}\n\n"
            "For a concurrency or lock claim you MUST read BOTH the locking query AND its "
            "caller, tracing across files, before judging whether the lock is taken on the "
            "contended row.\n\n"
            f"Proposed finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- endpoint: {candidate.endpoint}\n- location: {candidate.file}:{candidate.line}\n"
            f"- claimed evidence: {candidate.evidence}\n\n"
            "Read the code under the current directory, starting at the cited file, then "
            f"respond with a single JSON object exactly like:\n{_VERIFY_SHAPE}"
        )
        obj, ok = optional_json_object(_result_text(self._ask(prompt, root)), required_key="real")
        if not ok:
            raise VerifyError("unparseable verification reply")
        return Verdict(real=bool(obj.get("real")), reason=str(obj.get("reason", "")))


_CHECK_SHAPE = '{"holds": true, "reason": "why the controlling fact does or does not neutralize the finding"}'


class AgentRefutationChecker(_ClaudeBackend, RefutationChecker):
    """Audit a refutation as a headless Claude Code agent that reads the code itself.

    The keyless twin of ModelRefutationChecker, so the deletion-confirming judge can ride
    the subscription. It defends the finding rather than refuting it, the second independent
    read a deletion needs, and reads no content file so it takes no constructor content.
    """

    def holds(self, candidate: Candidate, reason: str, root: str) -> bool:
        """Return whether an independent read upholds the refutation."""
        prompt = (
            "Audit this proposed refutation, not the finding. A reviewer claims the finding is safe "
            "because of one controlling fact. Assume the finding is REAL and try to show the fact "
            "does not neutralize it: it may guard a different path, precondition, or function than "
            "the one the finding exploits, the rate==0 branch when the bug bites at rate>0. Read the "
            "cited code yourself, tracing across files, judging PRODUCTION semantics.\n\n"
            f"Finding:\n- {candidate.title}\n- category: {candidate.category}\n"
            f"- location: {candidate.file}:{candidate.line}\n- claimed evidence: {candidate.evidence}\n\n"
            f"Refutation's controlling fact, the reason it is called safe:\n{reason}\n\n"
            "Conclude the refutation holds only when the fact clearly and completely makes the "
            "finding unexploitable on its real path. Any doubt, any gap, it does not hold and the "
            "finding stays. Read the code under the current directory, starting at the cited file, "
            f"then respond with a single JSON object exactly like:\n{_CHECK_SHAPE}"
        )
        obj, ok = optional_json_object(_result_text(self._ask(prompt, root)), required_key="holds")
        if not ok:
            return False
        return bool(obj.get("holds"))
