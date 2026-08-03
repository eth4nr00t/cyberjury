"""Adversarial diff audit: Finder, Challenger, Judge over the same diff.

Each round runs the three roles once: the finder scans, the challenger rebuts and
independently re-scans, the judge cross-validates and keeps the survivors. Rounds
repeat, feeding the judged set back to the finder, until the confirmed set is
stable or ``max_rounds`` is hit. Higher coverage and lower false positives than
the standard single call, at roughly three times the cost.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cyberjury.domains.base import ContentPaths
from cyberjury.finding import Finding, findings_from_list
from cyberjury.json_parse import optional_json_object
from cyberjury.providers.base import Message, Provider
from cyberjury.review.diff.prompts import DO_NOT_REPORT, FOCUS, category_block, rubric_block, severity_rubric_text
from cyberjury.review.diff.vulnerabilities import vulnerabilities_for_diff

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


def _diff_block(diff: str, vulnerabilities: str, context: str) -> str:
    vulnerabilities_block = (
        f"Relevant vulnerability classes for reference:\n{vulnerabilities}\n\n" if vulnerabilities else ""
    )
    context_block = f"Surrounding code (not under review):\n```\n{context}\n```\n\n" if context else ""
    return f"{vulnerabilities_block}Code change (unified diff):\n```diff\n{diff}\n```\n\n{context_block}"


def finder_prompt(
    diff: str,
    *,
    vulnerabilities: str = "",
    context: str = "",
    prior: list | None = None,
    vulnerabilities_dir=None,
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
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
        f"{_diff_block(diff, vulnerabilities, context)}{prior_block}"
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
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
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
        f"{_diff_block(diff, vulnerabilities, context)}"
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
    severity_rubric: str = "",
) -> str:
    context_block = f"Surrounding code (not under review):\n```\n{context}\n```\n\n" if context else ""
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
        "- INVESTIGATE: needs a dynamic/runtime check to confirm -> put it in `investigate`.\n"
        "Set `converged` to true when this round surfaced no new confirmed finding and nothing is left to "
        "investigate. Set it to false if another round could still change the ruling.\n\n"
        f"Code change (unified diff):\n```diff\n{diff}\n```\n\n{context_block}"
        f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        f"{rubric_block(severity_rubric)}"
        'Respond with a single JSON object exactly like: {"findings": [' + _FINDING_FIELDS + "], "
        '"downgraded": [{"target": "...", "from": "HIGH", "to": "MEDIUM", "reason": "..."}], '
        '"dismissed": [{"target": "...", "reason": "..."}], '
        '"unresolved": [{"target": "...", "reason": "..."}], '
        '"investigate": [{"target": "...", "reason": "..."}], '
        '"converged": true}'
    )


@dataclass(frozen=True, kw_only=True)
class AdversarialResult:
    findings: list[Finding]
    investigate: list[dict] = field(default_factory=list)
    rounds: int = 0
    converged: bool = False
    degraded: bool = False


def _dicts(items: object) -> list[dict]:
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def _key(f: Finding) -> tuple:
    # file, line, class, no description: two phrasings of one finding at a location collapse
    # across rounds, unlike the diff engine dedup which keeps the description to separate them
    return (f.file, f.line, f.category)


def _dedup(items: list[dict]) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for d in items:
        k = (d.get("file"), d.get("line"), d.get("category"))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


_DISMISS_VERDICTS = frozenset({"dismiss", "dismissed", "false_positive", "reject", "rejected"})


def _loc(d: dict) -> str:
    line = d.get("line")
    return f"{d.get('file')}:{line}" if line else str(d.get("file") or "")


def _apply_dismissals(findings: list[dict], rebuttals: list[dict]) -> list[dict]:
    """Drop the findings the challenger dismissed. Used only on the degraded path when the
    judge is unusable. The challenger dismisses when the diff shows a safe pattern such as a
    parameterized query, a basename, an allowlist, or shell=False, so applying its dismissals
    holds down false positives instead of passing the whole finder set through. A wrong
    dismissal is possible, so the fallback that uses this is marked degraded, not a clean
    pass, invariant 4."""
    dismissed = {
        str(r.get("target")) for r in rebuttals if str(r.get("verdict", "")).strip().lower() in _DISMISS_VERDICTS
    }
    if not dismissed:
        return findings
    return [f for f in findings if _loc(f) not in dismissed and str(f.get("file") or "") not in dismissed]


class AdversarialAuditRunner:
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
        content: ContentPaths | None = None,
        focus: str = FOCUS,
        do_not_report: str = DO_NOT_REPORT,
    ) -> None:
        self._max_tokens = max_tokens
        # each role is a provider and model pair, so any seat can use a different vendor
        self._finder = (finder_provider or provider, finder_model or model)
        self._challenger = (challenger_provider or provider, challenger_model or model)
        self._judge = (judge_provider or provider, judge_model or model)
        self._content = content
        self._focus = focus
        self._do_not_report = do_not_report

    def _ask(self, system: str, prompt: str, backend: tuple) -> tuple[dict, bool]:
        """Return the parsed object and an ok flag. ok is False when the response
        could not be parsed into a JSON object, for example a provider error page,
        a blocked request, or prose, so the caller does not treat an unusable reply
        as an empty result. `backend` is the role's provider and model pair."""
        provider, model = backend
        try:
            result = provider.complete(
                system=system,
                messages=[Message(role="user", content=prompt)],
                model=model,
                max_tokens=self._max_tokens,
            )
        except Exception:
            # a provider error such as exhausted retries or a transport failure
            # is an unusable reply, not an empty result, so degrade gracefully
            return {}, False
        return optional_json_object(result.text)

    def run(self, diff: str, *, vulnerabilities: str = "", context: str = "", max_rounds: int = 3) -> AdversarialResult:
        vuln_dir = self._content.vulnerabilities_dir if self._content else None
        if not vulnerabilities:
            vulnerabilities = (
                vulnerabilities_for_diff(diff, directory=vuln_dir)
                if vuln_dir is not None
                else vulnerabilities_for_diff(diff)
            )
        rubric = severity_rubric_text(self._content)
        prior: list[dict] = []
        prev_keys: set | None = None
        judged = AdversarialResult(findings=[])
        rounds = 0
        converged = False
        degraded = False
        for rounds in range(1, max_rounds + 1):
            fp = finder_prompt(
                diff,
                vulnerabilities=vulnerabilities,
                context=context,
                prior=prior,
                vulnerabilities_dir=vuln_dir,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            finder, finder_ok = self._ask(FINDER_SYSTEM, fp, self._finder)
            if not finder_ok:
                finder, finder_ok = self._ask(FINDER_SYSTEM, fp, self._finder)
            if not finder_ok:
                # a finder reply that does not parse even on a retry is a failed step, not a clean
                # empty result, so surface it as degraded rather than report no findings, invariant 4
                degraded = True
                break
            finder_findings = _dicts(finder.get("findings"))

            cp = challenger_prompt(
                diff,
                finder_findings,
                vulnerabilities=vulnerabilities,
                context=context,
                vulnerabilities_dir=vuln_dir,
                focus=self._focus,
                do_not_report=self._do_not_report,
                severity_rubric=rubric,
            )
            challenger, challenger_ok = self._ask(CHALLENGER_SYSTEM, cp, self._challenger)
            if not challenger_ok:
                challenger, challenger_ok = self._ask(CHALLENGER_SYSTEM, cp, self._challenger)
            if not challenger_ok:
                degraded = True
                break
            rebuttals = _dicts(challenger.get("rebuttals"))
            new_findings = _dicts(challenger.get("new_findings"))

            jp = judge_prompt(diff, finder_findings, rebuttals, new_findings, context=context, severity_rubric=rubric)
            verdict, judge_ok = self._ask(JUDGE_SYSTEM, jp, self._judge)
            if not judge_ok:
                verdict, judge_ok = self._ask(JUDGE_SYSTEM, jp, self._judge)
            if not judge_ok:
                # judge still unusable: degrade, and apply the challenger's dismissals so a
                # transient judge outage does not pass through the findings it dismissed. this
                # trusts the challenger without the judge, trading a recall risk for fewer false
                # positives, which is why the result is marked degraded
                fallback = _dedup(_apply_dismissals(finder_findings, rebuttals) + new_findings)
                judged = AdversarialResult(findings=findings_from_list(fallback), rounds=rounds, degraded=True)
                degraded = True
                break

            judged = AdversarialResult(
                findings=findings_from_list(verdict.get("findings")),
                investigate=_dicts(verdict.get("investigate")),
                rounds=rounds,
            )

            keys = {_key(f) for f in judged.findings}
            judge_converged = bool(verdict.get("converged", False))
            stable = prev_keys is not None and keys == prev_keys
            if (judge_converged or stable) and not judged.investigate:
                converged = True
                break
            prev_keys = keys
            prior = [f.to_dict() for f in judged.findings]

        return AdversarialResult(
            findings=judged.findings,
            degraded=degraded,
            investigate=judged.investigate,
            rounds=rounds,
            converged=converged,
        )
