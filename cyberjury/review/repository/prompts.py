"""Finder, Challenger, and Judge prompts for repository review units."""

from __future__ import annotations

import json

from cyberjury.review.prompts import PromptPlan, knowledge_judgment

FINDER_SYSTEM = (
    "You are a senior application security engineer reviewing one slice of a codebase. "
    "Report only real, evidenced findings, each graded by the rubric and located at a "
    "file:line. Respond with a single JSON object and nothing else."
)

CHALLENGER_SYSTEM = (
    "You are a skeptical security reviewer. Refute unsafe claims only when the unit shows "
    "a controlling safety fact, and independently report real issues the finder missed. "
    "Respond with a single JSON object and nothing else."
)

JUDGE_SYSTEM = (
    "You are an impartial security judge. Weigh the finder and challenger evidence for "
    "one repository unit and keep every candidate the code supports. Respond with a "
    "single JSON object and nothing else."
)

FINDING_SHAPE = (
    '{"findings": [{"title": "...", "category": "<class id>", '
    '"symbol": "exact function or method name the finding lives in, identifier only", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": "controlling fact at file:line", '
    '"status": "confirmed|blocked"}]}'
)

_CHALLENGE_SHAPE = (
    '{"rebuttals": [{"target": "finding title or file:line", "verdict": "dismiss|downgrade", '
    '"reason": "controlling fact at file:line"}], "new_findings": '
    '[{"title": "...", "category": "<class id>", "symbol": "identifier", "endpoint": "METHOD /path or empty", '
    '"file": "path", "line": 0, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
    '"evidence": "controlling fact at file:line", "status": "confirmed|blocked"}]}'
)

_JUDGE_SHAPE = (
    '{"findings": [{"title": "...", "category": "<class id>", "symbol": "identifier", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": "controlling fact at file:line", '
    '"status": "confirmed|blocked"}], "investigate": [{"target": "...", "reason": "..."}], '
    '"converged": true}'
)


def _known_block(known: list[dict]) -> str:
    if not known:
        return ""
    return (
        "Findings carried from earlier repository passes. Do not rewrite these unless the "
        "current unit adds a stronger location, evidence, or a distinct exploit path:\n"
        f"{json.dumps(known, ensure_ascii=False)}\n\n"
    )


def standard_finder_prompt_plan(
    stable_prefix: str,
    *,
    vulnerability_categories: tuple[str, ...],
    selected_vulnerability_categories: tuple[str, ...],
    vulnerabilities: str,
    known: list[dict],
) -> PromptPlan:
    """Keep reusable unit evidence outside the changing knowledge task."""
    suffix = (
        knowledge_judgment(
            vulnerability_categories,
            vulnerabilities,
            selected_categories=selected_vulnerability_categories,
        )
        + f"Respond with a single JSON object exactly like:\n{FINDING_SHAPE}"
    )
    return PromptPlan(stable_prefix=stable_prefix + _known_block(known), judgment_suffix=suffix)


def finder_prompt(stable_prefix: str, known: list[dict]) -> str:
    """Keep adversarial roles on the complete selected knowledge set."""
    return (
        stable_prefix
        + "Find every exploitable vulnerability in this unit.\n\n"
        + _known_block(known)
        + f"Respond with a single JSON object exactly like:\n{FINDING_SHAPE}"
    )


def challenger_prompt(stable_prefix: str, finder_findings: list[dict], known: list[dict]) -> str:
    """Build one repository Challenger prompt."""
    return (
        stable_prefix
        + "Two tasks for this repository unit.\n"
        + "1. Rebut a reported finding only when this unit shows the controlling fact that makes it safe.\n"
        + "2. Independently scan the same unit and report any real issue the finder missed.\n\n"
        + _known_block(known)
        + f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        + f"Respond with a single JSON object exactly like:\n{_CHALLENGE_SHAPE}"
    )


def judge_prompt(
    stable_prefix: str,
    finder_findings: list[dict],
    rebuttals: list[dict],
    new_findings: list[dict],
    known: list[dict],
) -> str:
    """Build one repository Judge prompt."""
    return (
        stable_prefix
        + "Rule on each candidate finding from the two independent reviews below.\n"
        + "Keep every finding the unit supports. Dismiss only when this unit shows the controlling safety fact.\n\n"
        + _known_block(known)
        + f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        + f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        + f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        + f"Respond with a single JSON object exactly like:\n{_JUDGE_SHAPE}"
    )
