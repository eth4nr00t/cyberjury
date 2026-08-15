"""Standard diff audit prompts backed by profile knowledge.

The
focus, do-not-report, and severity-rubric blocks are the selected profile's, the default
profile's when a caller names none, naming the high-value classes to hunt, the noise to
skip, and how to grade what is found, and the prompt asks for findings as a single JSON
object.
"""

from __future__ import annotations

import json

from cyberjury.numbering import numbered_diff
from cyberjury.profiles.registry import default_profile
from cyberjury.review.prompts import CHALLENGER_SYSTEM as _CHALLENGER_SYSTEM
from cyberjury.review.prompts import FINDER_SYSTEM as _FINDER_SYSTEM
from cyberjury.review.prompts import JUDGE_SYSTEM as _JUDGE_SYSTEM
from cyberjury.review.prompts import (
    REVIEW_SYSTEM,
    PromptPlan,
    challenger_task,
    finder_task,
    judge_task,
    knowledge_judgment,
)

CHALLENGER_SYSTEM = _CHALLENGER_SYSTEM
FINDER_SYSTEM = _FINDER_SYSTEM
JUDGE_SYSTEM = _JUDGE_SYSTEM

SYSTEM = REVIEW_SYSTEM + " The target evidence is a code change."

FOCUS = default_profile().diff_focus
DO_NOT_REPORT = default_profile().diff_do_not_report

_JSON_SHAPE = (
    '{"findings": [{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "<one id from the category set>", "description": "...", '
    '"exploit_scenario": "end to end steps", "recommendation": "...", "confidence": 0.0}]}'
)
_CODE_CHANGE_MARKER = "Code change (unified diff):\n"
_FINDING_FIELDS = (
    '{"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"category": "...", "description": "...", "exploit_scenario": "...", '
    '"recommendation": "...", "confidence": 0.0}'
)
_DIFF_SCOPE = """Patch scope rules:
- Treat lines prefixed with '-' as historical code, not as code that exists after the patch.
- Report a finding only at a file and line that exist in the post-change tree. A deleted file
  cannot be a current report location.
- A deletion can still be vulnerable when surviving code loses a security control. Report that
  only at the surviving code and explain the changed exploit path.
"""


def diff_cache_prefix(prompt: str) -> str:
    """The reusable diff prompt prefix before the changed code body."""
    head, marker, _tail = prompt.partition(_CODE_CHANGE_MARKER)
    return f"{head}{marker}" if marker else ""


def category_block(vulnerabilities_dir=None) -> str:
    """The closed category set the model must choose from, the vulnerability ids.

    Reads the profile's vulnerability classes, defaulting to the web profile.
    """
    from cyberjury.review.vulnerabilities import allowed_categories

    cats = allowed_categories() if vulnerabilities_dir is None else allowed_categories(vulnerabilities_dir)
    return (
        "Each finding's `category` must be exactly one of these ids "
        "(use `other` only if none fit):\n" + ", ".join(cats) + "\n\n"
        if cats
        else ""
    )


def severity_rubric_text(content=None) -> str:
    """The profile's severity rubric, defaulting to the web profile.

    This keeps a diff finding on the same calibrated levels and firm rules the repository
    path applies.
    """
    from cyberjury.resources import SEVERITY_RUBRIC_FILE

    path = content.severity_rubric_file if content is not None else SEVERITY_RUBRIC_FILE
    return path.read_text(encoding="utf-8")


def rubric_block(severity_rubric: str) -> str:
    """Load the selected profile severity rubric for the diff prompt."""
    return f"Grade each finding's severity on this rubric:\n{severity_rubric}\n\n" if severity_rubric else ""


def standard_audit_prompt(
    diff: str,
    *,
    vulnerabilities: str = "",
    vulnerability_categories: tuple[str, ...] = (),
    selected_vulnerability_categories: tuple[str, ...] = (),
    context: str = "",
    stack: str = "",
    vulnerabilities_dir=None,
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> str:
    """Keep the string API for callers that do not need cache boundaries."""
    return standard_audit_prompt_plan(
        diff,
        vulnerabilities=vulnerabilities,
        vulnerability_categories=vulnerability_categories,
        selected_vulnerability_categories=selected_vulnerability_categories,
        context=context,
        stack=stack,
        vulnerabilities_dir=vulnerabilities_dir,
        focus=focus,
        do_not_report=do_not_report,
        severity_rubric=severity_rubric,
    ).text


def standard_audit_prompt_plan(
    diff: str,
    *,
    vulnerabilities: str = "",
    vulnerability_categories: tuple[str, ...] = (),
    selected_vulnerability_categories: tuple[str, ...] = (),
    context: str = "",
    stack: str = "",
    vulnerabilities_dir=None,
    focus: str = FOCUS,
    do_not_report: str = DO_NOT_REPORT,
    severity_rubric: str = "",
) -> PromptPlan:
    """Keep one diff's evidence stable across bounded knowledge judgments."""
    stack_block = f"Conventions of the target's language/framework:\n{stack}\n\n" if stack else ""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    stable_prefix = (
        "Review the following code change for security vulnerabilities.\n\n"
        f"{_DIFF_SCOPE}\n"
        f"{focus}\n{do_not_report}\n"
        f"{category_block(vulnerabilities_dir)}"
        f"{stack_block}"
        f"{_CODE_CHANGE_MARKER}```diff\n{numbered_diff(diff)}\n```\n\n"
        f"{context_block}"
        f"{rubric_block(severity_rubric)}"
    )
    judgment = knowledge_judgment(
        vulnerability_categories,
        vulnerabilities,
        selected_categories=selected_vulnerability_categories,
    )
    judgment_suffix = (
        judgment + "Report each real vulnerability with a precise file and line, a concrete "
        "exploit scenario, and a calibrated confidence. If there are none, return an "
        "empty findings list.\n\n"
        "Respond with a single JSON object exactly like:\n" + _JSON_SHAPE
    )
    return PromptPlan(stable_prefix=stable_prefix, judgment_suffix=judgment_suffix)


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
        f"{_DIFF_SCOPE}\n{stack_block}{vulnerabilities_block}"
        f"Code change (unified diff):\n```diff\n{numbered_diff(diff)}\n```\n\n"
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
    """Build the adversarial Finder prompt for one diff round."""
    prior_block = ""
    if prior:
        prior_block = (
            "Findings carried from the previous round (refine: drop any the rebuttals "
            "disprove, keep the valid ones, add anything still missed):\n"
            f"{json.dumps(prior, ensure_ascii=False)}\n\n"
        )
    return (
        finder_task("diff unit") + f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
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
    """Build the adversarial Challenger prompt for one Finder result."""
    return (
        challenger_task("diff unit") + f"{focus}\n{do_not_report}\n{category_block(vulnerabilities_dir)}"
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
    """Build the adversarial Judge prompt for challenged findings."""
    context_block = (
        f"Surrounding code for tracing where values come from (not under review):\n```\n{context}\n```\n\n"
        if context
        else ""
    )
    policy_block = f"{do_not_report}\n" if do_not_report else ""
    return (
        judge_task("diff unit") + "- CONFIRMED: real and exploitable -> put it in `findings` at its severity.\n"
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
        f"{_DIFF_SCOPE}\n"
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
