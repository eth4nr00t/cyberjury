"""Provider base tests cover the public structured response contract."""

import pytest

from cyberjury.providers.base import ResponseSchema


def test_response_schema_requires_a_named_closed_object():
    """An object schema named review_reply with additionalProperties false is accepted."""
    schema = ResponseSchema(
        name="review_reply",
        schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {},
            "required": [],
        },
    )

    assert schema.name == "review_reply"


@pytest.mark.parametrize(
    ("name", "schema"),
    [
        ("bad name", {"type": "object", "additionalProperties": False}),
        ("review", []),
        ("review", {"type": "array", "additionalProperties": False}),
        ("review", {"type": "object", "additionalProperties": True}),
    ],
)
def test_response_schema_rejects_unsupported_roots(name, schema):
    """A name with a space, a list or array root, or additionalProperties true raises ValueError."""
    with pytest.raises(ValueError, match="response schema"):
        ResponseSchema(name=name, schema=schema)
