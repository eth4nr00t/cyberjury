"""Strict provider output schemas shared by review role adapters."""

from __future__ import annotations

from cyberjury.providers.base import ResponseSchema


def closed_object(properties: dict[str, object]) -> dict[str, object]:
    """Build the strict object subset supported by both providers."""
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
    }


def string_array() -> dict[str, object]:
    """Build a shared array of string identifiers or questions."""
    return {"type": "array", "items": {"type": "string"}}


def decision_rule_assessments() -> dict[str, object]:
    """Build the bounded conclusions required after exact rule expansion."""
    item = closed_object(
        {
            "decision_rule_id": {"type": "string"},
            "decision": {
                "type": "string",
                "enum": ["finding", "not_exploitable", "insufficient_evidence"],
            },
            "reason": {"type": "string"},
            "evidence_refs": string_array(),
        }
    )
    return {"type": "array", "items": item}


SOURCE_QUERY_SCHEMA: dict[str, object] = {
    "anyOf": [
        closed_object(
            {
                "kind": {"type": "string", "enum": ["search_symbols", "search_text"]},
                "query": {"type": "string"},
                "page": {"type": "integer"},
            }
        ),
        closed_object(
            {
                "kind": {"type": "string", "enum": ["search_call_candidates"]},
                "definition_id": {"type": "string"},
                "direction": {"type": "string", "enum": ["callers", "callees", "both"]},
                "page": {"type": "integer"},
            }
        ),
    ]
}


def finder_response_schema(name: str, finding: dict[str, object]) -> ResponseSchema:
    """Require findings and the shared bounded navigation fields."""
    return ResponseSchema(
        name=name,
        schema=closed_object(
            {
                "findings": {"type": "array", "items": finding},
                "decision_rule_assessments": decision_rule_assessments(),
                "decision_rule_requests": string_array(),
                "evidence_requests": string_array(),
                "source_queries": {"type": "array", "items": SOURCE_QUERY_SCHEMA},
            }
        ),
    )


def challenger_response_schema(name: str, finding: dict[str, object]) -> ResponseSchema:
    """Require rebuttals, independent findings, and bounded navigation."""
    rebuttal = closed_object(
        {
            "candidate_id": {"type": "string"},
            "disposition": {"type": "string", "enum": ["dispute", "lower_severity"]},
            "reason": {"type": "string"},
            "evidence_refs": string_array(),
        }
    )
    return ResponseSchema(
        name=name,
        schema=closed_object(
            {
                "rebuttals": {"type": "array", "items": rebuttal},
                "new_findings": {"type": "array", "items": finding},
                "decision_rule_assessments": decision_rule_assessments(),
                "decision_rule_requests": string_array(),
                "evidence_requests": string_array(),
                "source_queries": {"type": "array", "items": SOURCE_QUERY_SCHEMA},
            }
        ),
    )


def judge_response_schema(name: str, finding: dict[str, object]) -> ResponseSchema:
    """Require final findings, pending work, and bounded navigation."""
    pending = closed_object(
        {
            "kind": {"type": "string", "enum": ["missing_source", "runtime_check", "environment_check"]},
            "question": {"type": "string"},
            "required_evidence": string_array(),
            "candidate_id": {"type": "string"},
        }
    )
    return ResponseSchema(
        name=name,
        schema=closed_object(
            {
                "findings": {"type": "array", "items": finding},
                "decision_rule_assessments": decision_rule_assessments(),
                "investigate": {"type": "array", "items": pending},
                "resolved_pending": string_array(),
                "decision_rule_requests": string_array(),
                "evidence_requests": string_array(),
                "source_queries": {"type": "array", "items": SOURCE_QUERY_SCHEMA},
            }
        ),
    )
