"""Finder, Challenger, and Judge prompts for repository review units."""

from __future__ import annotations

import json

from cyberjury.review.prompts import CHALLENGER_SYSTEM as _CHALLENGER_SYSTEM
from cyberjury.review.prompts import FINDER_SYSTEM as _FINDER_SYSTEM
from cyberjury.review.prompts import JUDGE_SYSTEM as _JUDGE_SYSTEM
from cyberjury.review.prompts import (
    PromptPlan,
    challenger_task,
    finder_task,
    judge_task,
    knowledge_judgment,
)

CHALLENGER_SYSTEM = _CHALLENGER_SYSTEM
FINDER_SYSTEM = _FINDER_SYSTEM
JUDGE_SYSTEM = _JUDGE_SYSTEM

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
        + finder_task("repository unit")
        + _known_block(known)
        + f"Respond with a single JSON object exactly like:\n{FINDING_SHAPE}"
    )


def challenger_prompt(stable_prefix: str, finder_findings: list[dict], known: list[dict]) -> str:
    """Build one repository Challenger prompt."""
    return (
        stable_prefix
        + challenger_task("repository unit")
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
        + judge_task("repository unit")
        + _known_block(known)
        + f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        + f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        + f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        + f"Respond with a single JSON object exactly like:\n{_JUDGE_SHAPE}"
    )
