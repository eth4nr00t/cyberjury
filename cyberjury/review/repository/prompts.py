"""Finder, Challenger, and Judge prompts for repository review units."""

from __future__ import annotations

import json

from cyberjury.review.prompts import CHALLENGER_SYSTEM as _CHALLENGER_SYSTEM
from cyberjury.review.prompts import FINDER_SYSTEM as _FINDER_SYSTEM
from cyberjury.review.prompts import JUDGE_SYSTEM as _JUDGE_SYSTEM
from cyberjury.review.prompts import (
    PromptPlan,
    candidate_decision_rules,
    challenger_task,
    decision_rule_assessment_shape,
    decision_rule_request_task,
    finder_task,
    judge_task,
    knowledge_judgment,
)
from cyberjury.review.schemas import (
    challenger_response_schema,
    closed_object,
    finder_response_schema,
    judge_response_schema,
    string_array,
)

CHALLENGER_SYSTEM = _CHALLENGER_SYSTEM
FINDER_SYSTEM = _FINDER_SYSTEM
JUDGE_SYSTEM = _JUDGE_SYSTEM

_FINDING_EXAMPLE = (
    '{"title": "...", "category": "<category id>", '
    '"decision_rule_id": "rule id from the security rule index, or empty only for other", '
    '"symbol": "exact function or method name the finding lives in, identifier only", '
    '"endpoint": "METHOD /path or empty", "file": "path", "line": 0, '
    '"severity": "CRITICAL|HIGH|MEDIUM|LOW", "attack_path": "end to end exploit steps", '
    '"evidence": "controlling fact at file:line", "status": "confirmed", '
    '"evidence_refs": ["seed|ev-id|src-id"]}'
)

REPOSITORY_FINDING_SCHEMA = closed_object(
    {
        "title": {"type": "string"},
        "category": {"type": "string"},
        "decision_rule_id": {"type": "string"},
        "symbol": {"type": "string"},
        "endpoint": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "attack_path": {"type": "string"},
        "evidence": {"type": "string"},
        "status": {"type": "string", "enum": ["confirmed"]},
        "evidence_refs": string_array(),
    }
)
FINDER_RESPONSE_SCHEMA = finder_response_schema("repository_finder_reply", REPOSITORY_FINDING_SCHEMA)
CHALLENGER_RESPONSE_SCHEMA = challenger_response_schema(
    "repository_challenger_reply",
    REPOSITORY_FINDING_SCHEMA,
)
JUDGE_RESPONSE_SCHEMA = judge_response_schema("repository_judge_reply", REPOSITORY_FINDING_SCHEMA)


def _standard_finding_shape() -> str:
    return (
        '{"findings": [' + _FINDING_EXAMPLE + "], " + decision_rule_assessment_shape() + ", "
        '"decision_rule_requests": ["rule-id"], '
        '"evidence_requests": ["ev-id|src-id"], "source_queries": []}'
    )


def _judge_shape() -> str:
    return (
        '{"findings": [' + _FINDING_EXAMPLE + "], " + decision_rule_assessment_shape() + ", "
        '"investigate": [{"kind": "missing_source|runtime_check|environment_check", '
        '"question": "...", "required_evidence": ["..."], '
        '"candidate_id": "candidate-id when applicable"}], '
        '"decision_rule_requests": ["rule-id"], '
        '"evidence_requests": ["ev-id|src-id"], "source_queries": []}'
    )


FINDING_SHAPE = _standard_finding_shape()


_ADVERSARIAL_FINDING_SHAPE = (
    '{"findings": ['
    + _FINDING_EXAMPLE
    + "], "
    + decision_rule_assessment_shape()
    + ', "decision_rule_requests": ["rule-id"], '
    '"evidence_requests": ["ev-id|src-id"], "source_queries": []}'
)

_CHALLENGE_SHAPE = (
    '{"rebuttals": [{"candidate_id": "candidate-id", "disposition": "dispute|lower_severity", '
    '"reason": "controlling fact at file:line", "evidence_refs": ["seed|ev-id|src-id"]}], "new_findings": '
    "[" + _FINDING_EXAMPLE + "], " + decision_rule_assessment_shape() + ', "evidence_requests": ["ev-id|src-id"], '
    '"decision_rule_requests": ["rule-id"], "source_queries": []}'
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
    review_brief: str,
    known: list[dict],
    context_controls: str = "",
) -> PromptPlan:
    """Keep reusable unit evidence outside the changing knowledge task."""
    suffix = (
        (f"Repository grounding controls:\n{context_controls}\n\n" if context_controls else "")
        + knowledge_judgment(review_brief)
        + "If a controlling fact is missing and the unit publishes an evidence id for it, "
        "request that id. Do not infer the missing fact or invent an evidence id. Use `source_queries` "
        "only to search under the published navigation contract. Request every exact `ev-*` or `src-*` id "
        "through `evidence_requests`. Each finding must cite `seed` or a delivered evidence id whose source "
        "range covers the finding file and line.\n\n"
        + f"Respond with a single JSON object exactly like:\n{_standard_finding_shape()}"
    )
    return PromptPlan(stable_prefix=stable_prefix + _known_block(known), judgment_suffix=suffix)


def finder_prompt(stable_prefix: str, known: list[dict], *, decision_rule_details: str = "") -> str:
    """Keep adversarial roles on the complete review brief."""
    return (
        stable_prefix
        + finder_task("repository unit")
        + _known_block(known)
        + candidate_decision_rules(decision_rule_details)
        + decision_rule_request_task()
        + "If a controlling fact is missing and the unit publishes an evidence id for it, "
        "request that id. Do not infer the missing fact. Each finding must cite `seed` or a delivered "
        "evidence id whose source range covers the finding file and line.\n\n"
        + f"Respond with a single JSON object exactly like:\n{_ADVERSARIAL_FINDING_SHAPE}"
    )


def challenger_prompt(
    stable_prefix: str,
    finder_findings: list[dict],
    known: list[dict],
    *,
    decision_rule_details: str = "",
) -> str:
    """Build one repository Challenger prompt."""
    return (
        stable_prefix
        + challenger_task("repository unit")
        + _known_block(known)
        + f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        + candidate_decision_rules(decision_rule_details)
        + decision_rule_request_task()
        + "Request exact source when a controlling fact or independent attack path is missing. "
        "Do not infer it.\n\n" + f"Respond with a single JSON object exactly like:\n{_CHALLENGE_SHAPE}"
    )


def judge_prompt(
    stable_prefix: str,
    finder_findings: list[dict],
    rebuttals: list[dict],
    new_findings: list[dict],
    known: list[dict],
    pending: list[dict] | None = None,
    decision_rule_details: str = "",
) -> str:
    """Build one repository Judge prompt."""
    pending_block = (
        "Previously unresolved work. Preserve each item in `investigate` with its `id`, or put its id in "
        "`resolved_pending` only when current source evidence resolves it:\n"
        f"{json.dumps(pending, ensure_ascii=False)}\n\n"
        if pending
        else ""
    )
    shape = _judge_shape()
    shape = shape.removesuffix("}") + ', "resolved_pending": ["pending-id"]}'
    return (
        stable_prefix
        + judge_task("repository unit")
        + _known_block(known)
        + pending_block
        + f"Finder findings:\n{json.dumps(finder_findings, ensure_ascii=False)}\n\n"
        + f"Challenger rebuttals:\n{json.dumps(rebuttals, ensure_ascii=False)}\n\n"
        + f"Challenger independent findings:\n{json.dumps(new_findings, ensure_ascii=False)}\n\n"
        + candidate_decision_rules(decision_rule_details)
        + decision_rule_request_task()
        + "Request exact source when a controlling fact needed for the ruling is missing. "
        "Do not infer it.\n\n" + f"Respond with a single JSON object exactly like:\n{shape}"
    )
