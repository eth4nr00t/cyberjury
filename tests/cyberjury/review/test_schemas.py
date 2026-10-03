"""Review schema tests keep role outputs closed and target neutral."""

import pytest

from cyberjury.providers.base import ResponseSchema
from cyberjury.review.schemas import (
    challenger_response_schema,
    closed_object,
    finder_response_schema,
    judge_response_schema,
    validate_response_object,
    with_dependency_source_queries,
)

_FINDING = closed_object({"file": {"type": "string"}})


def test_role_schemas_require_navigation_and_decision_rule_fields():
    schemas = (
        finder_response_schema("finder", _FINDING),
        challenger_response_schema("challenger", _FINDING),
        judge_response_schema("judge", _FINDING),
    )

    for response in schemas:
        root = response.schema
        required = set(root["required"])
        assert root["additionalProperties"] is False
        assert {
            "decision_rule_assessments",
            "decision_rule_requests",
            "evidence_requests",
            "source_queries",
        } <= required
        assert required == set(root["properties"])


def test_local_response_validation_enforces_the_closed_provider_contract():
    schema = finder_response_schema("finder", _FINDING)
    valid = {
        "findings": [{"file": "app.py"}],
        "decision_rule_assessments": [],
        "decision_rule_requests": [],
        "evidence_requests": [],
        "source_queries": [],
    }

    assert validate_response_object(valid, schema) == valid
    with pytest.raises(ValueError, match="unknown fields: ignored"):
        validate_response_object({**valid, "ignored": []}, schema)
    with pytest.raises(ValueError, match=r"findings\[0\] is missing fields: file"):
        validate_response_object({**valid, "findings": [{}]}, schema)


def test_role_schema_accepts_only_complete_dependency_searches():
    base_schema = finder_response_schema("finder", _FINDING)
    schema = with_dependency_source_queries(base_schema)
    response = {
        "findings": [],
        "decision_rule_assessments": [],
        "decision_rule_requests": [],
        "evidence_requests": [],
        "source_queries": [{"kind": "search_dependency", "package": "library", "query": "is_safe", "page": 0}],
    }

    assert validate_response_object(response, schema) == response
    with pytest.raises(ValueError, match="does not match any allowed shape"):
        validate_response_object(response, base_schema)
    with pytest.raises(ValueError, match="does not match any allowed shape"):
        validate_response_object(
            {**response, "source_queries": [{"kind": "search_dependency", "query": "is_safe", "page": 0}]},
            schema,
        )


def test_role_schema_accepts_only_complete_structural_candidate_searches():
    schema = finder_response_schema("finder", _FINDING)
    response = {
        "findings": [],
        "decision_rule_assessments": [],
        "decision_rule_requests": [],
        "evidence_requests": [],
        "source_queries": [
            {
                "kind": "search_structural_candidates",
                "definition_id": "def-one",
                "direction": "outgoing",
                "page": 0,
            }
        ],
    }

    assert validate_response_object(response, schema) == response
    with pytest.raises(ValueError, match="does not match any allowed shape"):
        validate_response_object(
            {
                **response,
                "source_queries": [
                    {
                        "kind": "search_structural_candidates",
                        "definition_id": "def-one",
                        "direction": "callees",
                        "page": 0,
                    }
                ],
            },
            schema,
        )


def test_local_response_validation_supports_json_booleans_without_accepting_integers():
    schema = ResponseSchema(name="boolean", schema=closed_object({"accepted": {"type": "boolean"}}))

    assert validate_response_object({"accepted": True}, schema) == {"accepted": True}
    with pytest.raises(ValueError, match="must be boolean"):
        validate_response_object({"accepted": 1}, schema)


def test_judge_pending_schema_preserves_ids_without_requiring_a_candidate():
    schema = judge_response_schema("judge", _FINDING)
    pending = {
        "kind": "runtime_check",
        "question": "Is the route reachable?",
        "required_evidence": ["sandbox result"],
        "id": "pending-one",
        "candidate_id": None,
    }
    response = {
        "findings": [],
        "decision_rule_assessments": [],
        "investigate": [pending],
        "resolved_pending": [],
        "decision_rule_requests": [],
        "evidence_requests": [],
        "source_queries": [],
    }

    assert validate_response_object(response, schema) == response
