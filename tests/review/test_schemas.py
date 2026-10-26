"""Review schema tests keep role outputs closed and target neutral."""

import pytest

from cyberjury.providers.base import ResponseSchema
from cyberjury.review.diff import prompts as diff
from cyberjury.review.repository import prompts as repository
from cyberjury.review.schemas import closed_object, finder_response_schema, validate_response_object

_FINDING = closed_object({"file": {"type": "string"}})


def test_every_finder_system_explains_each_schema_field_without_an_example():
    """Diff and repository finder prompts name every schema field in backticks and give no JSON example."""
    systems = (
        (diff.diff_finder_system(review_brief="", severity_rubric="", navigation=""), diff.FINDER_RESPONSE_SCHEMA),
        (
            repository.repository_finder_system(review_brief="", severity_rubric="", navigation=""),
            repository.FINDER_RESPONSE_SCHEMA,
        ),
    )
    for system, schema in systems:
        root = schema.schema["properties"]
        for field in (*root, *root["findings"]["items"]["properties"]):
            assert f"`{field}`" in system
        assert '{"findings"' not in system


def test_finder_schema_requires_navigation_fields():
    """The finder schema is closed, requires every property, and has evidence_requests and source_queries."""
    root = finder_response_schema("finder", _FINDING).schema
    required = set(root["required"])
    assert root["additionalProperties"] is False
    assert {"evidence_requests", "source_queries"} <= required
    assert required == set(root["properties"])


def test_local_response_validation_enforces_the_closed_provider_contract():
    """A valid reply passes unchanged, and an extra ignored field or a finding missing file raises ValueError."""
    schema = finder_response_schema("finder", _FINDING)
    valid = {
        "findings": [{"file": "app.py"}],
        "evidence_requests": [],
        "source_queries": [],
    }

    assert validate_response_object(valid, schema) == valid
    with pytest.raises(ValueError, match="unknown fields: ignored"):
        validate_response_object({**valid, "ignored": []}, schema)
    with pytest.raises(ValueError, match=r"findings\[0\] is missing fields: file"):
        validate_response_object({**valid, "findings": [{}]}, schema)


def test_role_schema_rejects_an_unpublished_search_kind():
    """A search_dependency source query raises ValueError because it matches no allowed shape."""
    schema = finder_response_schema("finder", _FINDING)
    response = {
        "findings": [],
        "evidence_requests": [],
        "source_queries": [{"kind": "search_dependency", "package": "library", "query": "is_safe", "page": 0}],
    }

    with pytest.raises(ValueError, match="does not match any allowed shape"):
        validate_response_object(response, schema)


def test_role_schema_accepts_only_complete_structural_candidate_searches():
    """A structural candidate search with direction outgoing passes, and direction callees raises ValueError."""
    schema = finder_response_schema("finder", _FINDING)
    response = {
        "findings": [],
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
    """A boolean field accepts True but rejects the integer 1 as not boolean."""
    schema = ResponseSchema(name="boolean", schema=closed_object({"accepted": {"type": "boolean"}}))

    assert validate_response_object({"accepted": True}, schema) == {"accepted": True}
    with pytest.raises(ValueError, match="must be boolean"):
        validate_response_object({"accepted": 1}, schema)
