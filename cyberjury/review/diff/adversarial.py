"""Adversarial diff audit: Finder, Challenger, Judge over the same diff.

Each round runs the three roles once: the finder scans, the challenger rebuts and
independently re-scans, the judge cross-validates, and the coded loop unions survivors.
Rounds repeat, feeding the union back to the finder, until two clean rounds add nothing
or ``max_rounds`` is hit. The loop costs roughly three role calls per round.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace

from cyberjury.domains.base import ContentPaths
from cyberjury.finding import Finding, findings_from_list
from cyberjury.json_parse import optional_json_object
from cyberjury.numbering import numbered_diff
from cyberjury.providers.base import Message, Provider
from cyberjury.review.diff.prompts import (
    DO_NOT_REPORT,
    FOCUS,
    category_block,
    diff_cache_prefix,
    rubric_block,
    severity_rubric_text,
)
from cyberjury.review.provenance import found_by_tuple, label_judged
from cyberjury.review.vulnerabilities import vulnerabilities_for_diff

_FINDING_FIELDS = (
    '{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "...", "description": "...", "exploit_scenario": "...", '
    '"recommendation": "...", "confidence": 0.0}'
)

FINDER_SYSTEM = (
    "You are a red-team application security engineer. Enumerate every plausible "
    "exploitable vulnerability an attacker could reach. Do not self-censor or pre-filter "
    "for fear of false positives, the Challenger and Judge will do that. Respond with a "
    "single JSON object and nothing else."
)

CHALLENGER_SYSTEM = (
    "You are a blue-team security reviewer. You do two things: refute the reported "
    "findings you believe are false positives with concrete reasoning, and independently "
    "scan the same diff for real issues the finder missed. Respond with a single JSON "
    "object and nothing else."
)

JUDGE_SYSTEM = (
    "You are an impartial security judge. Weigh two independent reviews of the same diff "
    "and rule on each candidate finding, keeping only the ones the evidence supports, with "
    "calibrated severity. Respond with a single JSON object and nothing else."
)


def _diff_block(diff: str, vulnerabilities: str, context: str, stack: str = "") -> str:
    stack_block = f"Conventions of the target's language/framework:\n{stack}\n\n" if stack else ""
    vulnerabilities_block = (
        f"Relevant vulnerability classes for reference:\n{vulnerabilities}\n\n" if vulnerabilities else ""
    )
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    return (
        f"{stack_block}{vulnerabilities_block}Code change (unified diff):\n```diff\n{numbered_diff(diff)}\n```\n\n"
        f"{context_block}"
    )


def finder_prompt(
    diff: str,
    *,
    vulnerabilities: str = "",
    context: str = "",
    prior: list | None = None,
    vulnerabilities_dir=None,
    stack: str = "",
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Build the adversarial finder prompt for one diff round."""
    prior_block = ""
    if prior:
        prior_block = (
            "Findings carried from the previous round (refine: drop any the rebuttals "
            "disprove, keep the valid ones, add anything still missed):\n"
            f"{json.dumps(prior, ensure_ascii=False)}\n\n"
        )
    return (
        "Find every exploitable vulnerability in this code change.\n\n"
        f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
        f"{_diff_block(diff, vulnerabilities, context, stack)}{prior_block}"
        f"{rubric_block(severity_rubric)}"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "]}"
    )


def challenger_prompt(
    diff: str,
    finder_findings: list,
    *,
    vulnerabilities: str = "",
    context: str = "",
    vulnerabilities_dir=None,
    stack: str = "",
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Build the adversarial challenger prompt for one finder result."""
    return (
        "Two tasks on the code change below.\n"
        "1. Rebut a finding when the diff SHOWS the value is handled safely: a parameterized "
        "or bound query, os.path.basename or a containment check, an allowlist, input "
        "validation, or a constant/trusted value. Keep a finding when a dangerous sink (a "
        "query, a shell, a file path, a fetch, deserialization) receives a value with no such "
        "safety visible: an unsanitized function parameter reaching a sink is exploitable by "
        "its caller, so do not dismiss it merely because its origin is not shown. Decide on the "
        "safety the diff shows, not on guessing the input is internal.\n"
        "2. Independently scan the diff yourself and report any real issue the finder missed.\n\n"
        f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
        f"{_diff_block(diff, vulnerabilities, context, stack)}"
        f"Reported findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"{rubric_block(severity_rubric)}"
        "Respond with a single JSON object exactly like: "
        '{"rebuttals": [{"target": "finding description or file:line", "verdict": "dismiss|downgrade", '
        '"reason": "..."}], "new_findings": [' + _FINDING_FIELDS + "]}"
    )


def judge_prompt(
    diff: str,
    finder_findings: list,
    rebuttals: list,
    new_findings: list,
    *,
    context: str = "",
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Build the adversarial judge prompt for challenged findings."""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    policy_block = f"{do_not_report}\n" if do_not_report else ""
    return (
        "Rule on each candidate finding from the two independent reviews below, assigning one verdict:\n"
        "- CONFIRMED: real and exploitable -> put it in `findings` at its severity.\n"
        "- DOWNGRADED: real but lower impact than claimed -> put it in `findings` at the lower severity, "
        "and record it in `downgraded`.\n"
        "- DISMISSED: the diff shows the value is handled safely (a parameterized/bound query, "
        "os.path.basename or a containment check, an allowlist, validation, or a constant). Do "
        "not dismiss a dangerous sink with no visible safety just because the input's origin is "
        "not shown: an unsanitized parameter reaching a sink is exploitable by its caller, so "
        "keep it CONFIRMED.\n"
        "- UNRESOLVED: cannot decide from the code shown -> put it in `unresolved`.\n"
        "- INVESTIGATE: needs a dynamic/runtime check to confirm -> put it in `investigate`.\n\n"
        f"{policy_block}"
        f"Code change (unified diff):\n```diff\n{numbered_diff(diff)}\n```\n\n{context_block}"
        f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        f"{rubric_block(severity_rubric)}"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "], "
        '"downgraded": [{"target": "...", "from": "HIGH", "to": "MEDIUM", "reason": "..."}], '
        '"dismissed": [{"target": "...", "reason": "..."}], '
        '"unresolved": [{"target": "...", "reason": "..."}], '
        '"investigate": [{"target": "...", "reason": "..."}]}'
    )


@dataclass(frozen=True, kw_only=True)
class AdversarialResult:
    """Findings plus degraded-call state from adversarial diff review."""

    findings: list[Finding]
    investigate: list[dict] = field(default_factory=list)
    rounds: int = 0
    converged: bool = False
    degraded: bool = False
    failure_reason: str = ""


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _key(f: Finding) -> tuple:
    return (f.file, f.line, f.category)


def _merge_findings(
    pool: dict[tuple, Finding],
    findings: list[Finding],
    *labels: str,
) -> int:
    source_labels = {label for label in labels if label}
    new = 0
    for finding in findings:
        key = _key(finding)
        incoming = replace(finding, found_by=found_by_tuple(finding.found_by, source_labels))
        if key not in pool:
            pool[key] = incoming
            new += 1
        else:
            labels = found_by_tuple(pool[key].found_by, incoming.found_by)
            if labels != pool[key].found_by:
                pool[key] = replace(pool[key], found_by=labels)
    return new


class AdversarialAuditRunner:
    """Finder, challenger, and judge runner for higher-recall diff review."""

    def __init__(
        self,
        *,
        provider: Provider,
        model: str,
        max_tokens: int = 4096,
        finder_model: str | None = None,
        challenger_model: str | None = None,
        judge_model: str | None = None,
        finder_provider: Provider | None = None,
        challenger_provider: Provider | None = None,
        judge_provider: Provider | None = None,
        finder_label: str | None = None,
        challenger_label: str | None = None,
        judge_label: str | None = None,
        content: ContentPaths | None = None,
        focus: str = FOCUS,
        do_not_report: str = DO_NOT_REPORT,
    ) -> None:
        """Bind finder, challenger, and judge seats for the adversarial pass loop."""
        self._max_tokens = max_tokens
        self._finder = (finder_provider or provider, finder_model or model)
        self._challenger = (challenger_provider or provider, challenger_model or model)
        self._judge = (judge_provider or provider, judge_model or model)
        self._finder_label = finder_label or self._finder[1]
        self._challenger_label = challenger_label or self._challenger[1]
        self._judge_label = judge_label or self._judge[1]
        self._content = content
        self._focus = focus
        self._do_not_report = do_not_report

    def _ask(self, role: str, system: str, prompt: str, backend: tuple) -> tuple[dict, bool, str]:
        """Return the parsed object and an ok flag.

        ok is False when the response could not be parsed into a JSON object, for example a
        provider error page, a blocked request, or prose, so the caller does not treat an
        unusable reply as an empty result. `backend` is the role's provider and model pair.
        """
        provider, model = backend
        try:
            result = provider.complete(
                system=system,
                messages=[Message(role="user", content=prompt)],
                model=model,
                max_tokens=self._max_tokens,
                cache=True,
                cache_prefix=diff_cache_prefix(prompt),
            )
        except Exception as exc:
            return {}, False, f"adversarial {role} call failed: {type(exc).__name__}: {exc}"
        parsed, ok = optional_json_object(result.text)
        if not ok:
            return {}, False, f"adversarial {role} returned unparsable JSON"
        return parsed, True, ""

    def run(
        self,
        diff: str,
        *,
        vulnerabilities: str = "",
        context: str = "",
        stack: str = "",
        max_rounds: int = 3,
    ) -> AdversarialResult:
        """Run finder, challenger, and judge rounds for one diff chunk."""
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        if not vulnerabilities:
            selection_text = f"{diff}\n{context}" if context else diff
            vulnerabilities = (
                vulnerabilities_for_diff(selection_text, directory=vuln_dir)
                if vuln_dir is not None
                else vulnerabilities_for_diff(selection_text)
            )
        rubric = severity_rubric_text(self._content)
        prior: list[dict] = []
        pool: dict[tuple, Finding] = {}
        judged = AdversarialResult(findings=[])
        rounds = 0
        converged = False
        degraded = False
        failure_reason = ""
        quiet_rounds = 0
        for rounds in range(1, max_rounds + 1):
            fp = finder_prompt(
                diff,
                vulnerabilities=vulnerabilities,
                context=context,
                prior=prior,
                vulnerabilities_dir=vuln_dir,
                stack=stack,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            finder, finder_ok, failure_reason = self._ask("finder", FINDER_SYSTEM, fp, self._finder)
            if not finder_ok:
                degraded = True
                break
            finder_findings = _dicts(finder.get("findings"))
            finder_parsed = findings_from_list(finder_findings)

            cp = challenger_prompt(
                diff,
                finder_findings,
                vulnerabilities=vulnerabilities,
                context=context,
                vulnerabilities_dir=vuln_dir,
                stack=stack,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            challenger, challenger_ok, failure_reason = self._ask(
                "challenger",
                CHALLENGER_SYSTEM,
                cp,
                self._challenger,
            )
            if not challenger_ok:
                _merge_findings(pool, finder_parsed, self._finder_label)
                judged = AdversarialResult(
                    findings=list(pool.values()),
                    rounds=rounds,
                    degraded=True,
                    failure_reason=failure_reason,
                )
                degraded = True
                break
            rebuttals = _dicts(challenger.get("rebuttals"))
            new_findings = _dicts(challenger.get("new_findings"))
            challenger_parsed = findings_from_list(new_findings)

            jp = judge_prompt(
                diff,
                finder_findings,
                rebuttals,
                new_findings,
                context=context,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            verdict, judge_ok, failure_reason = self._ask("judge", JUDGE_SYSTEM, jp, self._judge)
            if not judge_ok:
                _merge_findings(pool, finder_parsed, self._finder_label)
                _merge_findings(pool, challenger_parsed, self._challenger_label)
                judged = AdversarialResult(
                    findings=list(pool.values()),
                    rounds=rounds,
                    degraded=True,
                    failure_reason=failure_reason,
                )
                degraded = True
                break

            round_findings = findings_from_list(verdict.get("findings"))
            labeled = label_judged(
                round_findings,
                finder_parsed,
                challenger_parsed,
                key=_key,
                title=lambda finding: finding.description,
                finder_label=self._finder_label,
                challenger_label=self._challenger_label,
                judge_label=self._judge_label,
            )
            new_count = 0
            for finding in labeled:
                new_count += _merge_findings(pool, [finding])
            investigate = _dicts(verdict.get("investigate"))
            judged = AdversarialResult(
                findings=list(pool.values()),
                investigate=investigate,
                rounds=rounds,
            )

            if new_count == 0 and not investigate:
                quiet_rounds += 1
            else:
                quiet_rounds = 0
            if quiet_rounds >= 2:
                converged = True
                break
            prior = [f.to_dict() for f in judged.findings]

        return AdversarialResult(
            findings=judged.findings,
            degraded=degraded,
            failure_reason=failure_reason if degraded else "",
            investigate=judged.investigate,
            rounds=rounds,
            converged=converged,
        )
