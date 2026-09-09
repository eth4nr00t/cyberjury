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


def nullable_string() -> dict[str, object]:
    """Represent an optional string in strict provider schemas."""
    return {"anyOf": [{"type": "string"}, {"type": "null"}]}


def validate_response_object(value: object, response_schema: ResponseSchema) -> dict[str, object]:
    """Validate provider output against the exact provider neutral schema."""
    _validate_schema_value(value, response_schema.schema, path="$response")
    if not isinstance(value, dict):
        raise ValueError("$response must be an object")
    return value


def _validate_schema_value(value: object, schema: object, *, path: str) -> None:
    if not isinstance(schema, dict):
        raise ValueError(f"{path} has an invalid schema")
    alternatives = schema.get("anyOf")
    if alternatives is not None:
        if not isinstance(alternatives, list) or not alternatives:
            raise ValueError(f"{path} has an invalid anyOf schema")
        for alternative in alternatives:
            try:
                _validate_schema_value(value, alternative, path=path)
            except ValueError:
                continue
            return
        raise ValueError(f"{path} does not match any allowed shape")
    allowed = schema.get("enum")
    if isinstance(allowed, list) and value not in allowed:
        raise ValueError(f"{path} has a value outside the allowed set")
    value_type = schema.get("type")
    if value_type == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path} must be an object")
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ValueError(f"{path} has an invalid object schema")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path} is missing fields: {', '.join(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value).difference(properties)
            if extra:
                raise ValueError(f"{path} has unknown fields: {', '.join(sorted(extra))}")
        for key, item in value.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                _validate_schema_value(item, child_schema, path=f"{path}.{key}")
        return
    if value_type == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path} must be an array")
        item_schema = schema.get("items")
        for index, item in enumerate(value):
            _validate_schema_value(item, item_schema, path=f"{path}[{index}]")
        return
    valid = {
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "null": value is None,
    }
    if value_type not in valid:
        raise ValueError(f"{path} has an unsupported schema type")
    if not valid[value_type]:
        raise ValueError(f"{path} must be {value_type}")


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
            "id": nullable_string(),
            "candidate_id": nullable_string(),
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
