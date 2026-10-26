"""Role reply tests cover parsing a model response against its declared schema."""

import pytest

from cyberjury.review.replies import RoleResponseError, parse_role_response
from cyberjury.review.schemas import closed_object, finder_response_schema


def test_role_response_requires_every_declared_field():
    """A partial role object is failed work rather than a clean empty result."""
    with pytest.raises(RoleResponseError, match="source_queries"):
        parse_role_response(
            '{"findings": [], "evidence_requests": []}',
            role="finder",
            response_schema=finder_response_schema("test_finder", closed_object({})),
        )
