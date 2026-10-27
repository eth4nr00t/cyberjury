"""Parse one role reply against its closed response schema."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyberjury.json_parse import parse_json_object
from cyberjury.providers.base import ResponseSchema
from cyberjury.providers.metering import record_model_parse
from cyberjury.review.schemas import validate_response_object

if TYPE_CHECKING:
    from cyberjury.review.finding import Finding


class RoleResponseError(RuntimeError):
    """A role reply cannot support a complete judgment."""


class CorrectableRoleResponseError(RoleResponseError):
    """A response needs one bounded correction using deterministic local facts."""

    def __init__(
        self,
        instruction: str,
        response_findings: tuple[Finding, ...] = (),
        fallback_findings: tuple[Finding, ...] = (),
    ) -> None:
        """Separate valid carried candidates from invalid correction fallbacks."""
        self.instruction = instruction
        self.response_findings = response_findings
        self.fallback_findings = fallback_findings
        super().__init__(instruction)


type RoleReply = dict[str, object]


def parse_role_response(
    text: str,
    *,
    role: str,
    response_schema: ResponseSchema,
) -> RoleReply:
    """Require the role contract so malformed output cannot become a clean result."""
    parsed = parse_json_object(text)
    if parsed is None:
        message = f"{role} reply had no complete JSON object"
        record_model_parse(message)
        raise CorrectableRoleResponseError(
            f"{message}. Return exactly one JSON object that follows the response schema."
        )
    try:
        obj = validate_response_object(parsed, response_schema)
    except ValueError as exc:
        message = f"{role} reply violates {response_schema.name}: {exc}"
        record_model_parse(message)
        raise RoleResponseError(message) from exc
    record_model_parse()
    return obj
