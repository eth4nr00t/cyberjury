"""Standard diff audit: one model call over a diff, parsed into Findings.

The single call unit the orchestrator in engine.py drives. The cheap, balanced default.
The adversarial Finder/Challenger/Judge runner builds on the same Finding domain for the
cases that need higher coverage and lower false positives.
"""

from __future__ import annotations

import re

from cyberjury.domains.base import ContentPaths
from cyberjury.finding import Finding, findings_from_list
from cyberjury.guides import load_guides, select_guides
from cyberjury.json_parse import require_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.review.diff.prompts import DO_NOT_REPORT, FOCUS, SYSTEM, severity_rubric_text, standard_audit_prompt
from cyberjury.review.diff.vulnerabilities import vulnerabilities_for_diff

_DIFF_PATH = re.compile(r"^(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", re.MULTILINE)


def guides_for_diff(diff: str, content: ContentPaths | None = None) -> str:
    """Concatenated bodies of the language/framework guides relevant to a diff.

    selected by its changed paths and its content. Empty when nothing matches. Lives here,
    not in the shared guides module, because parsing a diff is a diff-path concern. Reads
    the domain's guides, defaulting to the web domain.
    """
    paths = _DIFF_PATH.findall(diff)
    guides = (
        load_guides(content.languages_dir, content.frameworks_dir, content.protocols_dir)
        if content is not None
        else None
    )
    return "\n\n---\n\n".join(g.body for g in select_guides(paths, source_text=diff, guides=guides))


class AuditError(RuntimeError):
    """The model reply could not be parsed into an audit result.

    Raised instead of returning an empty findings list, so a failed or blank call is never
    reported as a clean audit. The prompt requires a JSON object carrying a ``findings``
    key, an empty ``{"findings": []}`` when there is nothing to report, so a reply that
    yields no object, or an object without that key, is a failure, not a pass.
    """


class AuditRunner:
    """Single-call diff audit runner using one provider backend."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = 4096,
        content: ContentPaths | None = None,
        focus: str = FOCUS,
        do_not_report: str = DO_NOT_REPORT,
    ) -> None:
        """Bind one provider to the single call diff prompt configuration."""
        self._provider = provider
        self._model = model
        self._max_tokens = max_tokens
        self._content = content
        self._focus = focus
        self._do_not_report = do_not_report

    def run(self, diff: str, *, vulnerabilities: str = "", context: str = "") -> list[Finding]:
        """Run the CLI command and return a process-style exit code."""
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        if not vulnerabilities:
            vulnerabilities = (
                vulnerabilities_for_diff(diff, directory=vuln_dir)
                if vuln_dir is not None
                else vulnerabilities_for_diff(diff)
            )
        stack = guides_for_diff(diff, self._content)
        result = self._provider.complete(
            system=SYSTEM,
            messages=[
                Message(
                    role="user",
                    content=standard_audit_prompt(
                        diff,
                        vulnerabilities=vulnerabilities,
                        context=context,
                        stack=stack,
                        vulnerabilities_dir=vuln_dir,
                        focus=self._focus,
                        do_not_report=self._do_not_report,
                        severity_rubric=severity_rubric_text(self._content),
                    ),
                )
            ],
            model=self._model,
            max_tokens=self._max_tokens,
        )
        obj = require_json_object(
            result.text,
            required_key="findings",
            error=AuditError,
            message="the model reply was not a valid audit result. it had no JSON object, "
            "or a JSON object without a findings key, so it is a failed audit "
            "rather than a clean pass",
        )
        return findings_from_list(obj.get("findings"))
