"""Strict extraction of the JSON object a schema-bound model reply must contain.

Every model call carries a strict response schema, so a usable reply is exactly one JSON
object. Prose, code fences, and truncated output are rejected rather than recovered, so
malformed output can never become a decision.
"""

from __future__ import annotations

import json


def parse_json_object(text: str) -> dict | None:
    """Return the reply object, or None when the reply is not exactly one JSON object."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
