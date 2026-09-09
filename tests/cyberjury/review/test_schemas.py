"""Review schema tests keep role outputs closed and target neutral."""

from cyberjury.review.schemas import (
    challenger_response_schema,
    closed_object,
    finder_response_schema,
    judge_response_schema,
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
