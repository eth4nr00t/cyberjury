"""Strict extraction of the JSON object a schema-bound model reply must contain."""

from __future__ import annotations

import json

_DECODER = json.JSONDecoder()


def parse_json_object(text: str) -> dict | None:
    """Return the reply object, or None when the reply is not one JSON object, possibly repeated."""
    objects, index = [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        try:
            obj, index = _DECODER.raw_decode(text, index)
        except json.JSONDecodeError:
            return None
        objects.append(obj)
    if not objects or not isinstance(objects[0], dict) or any(obj != objects[0] for obj in objects[1:]):
        return None
    return objects[0]
