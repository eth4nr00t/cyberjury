"""Best-effort extraction of a JSON object from model output.

Models often wrap JSON in prose or code fences, and sometimes emit slightly
malformed JSON, for example an unescaped quote, a trailing comma, or a reply
truncated at the token limit. This recovers the object: a direct parse, then a
fenced ```json block, then the first balanced-brace span, which is string-aware
so braces inside string values do not throw off the count, then a json-repair
fallback for malformed or truncated output. The repair step keeps a single bad
character from silently dropping an entire findings list.
"""

from __future__ import annotations

import json
import re

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

# bound the scan: the balanced-brace pass is superlinear, so never run it on an unbounded string
_MAX_SCAN = 1_000_000


def extract_json_object(text: str) -> dict | None:
    """Return the first JSON object found in `text`, or None if there is none."""
    text = text.strip()[:_MAX_SCAN]

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    fenced = _FENCE.search(text)
    if fenced:
        try:
            obj = json.loads(fenced.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    balanced = _first_balanced_object(text)
    if balanced is not None:
        return balanced

    return _repair(text)


def require_json_object(text: str, *, required_key: str, error: type[Exception], message: str) -> dict:
    """Extract a JSON object that must carry `required_key`, or raise the requested error.
    For the fail-loud callers: a reply with no JSON object, or one missing the key, is a
    failed model call, not an empty result, so it raises rather than returning nothing.
    The caller owns the exception type and the message, this owns only the mechanics."""
    obj = extract_json_object(text)
    if obj is None or required_key not in obj:
        raise error(message)
    return obj


def optional_json_object(text: str, *, required_key: str | None = None) -> tuple[dict, bool]:
    """Extract a JSON object and report whether it is usable, never raising. For the
    callers that degrade rather than fail: an unusable reply yields an empty object with
    a false ok flag. A usable reply yields the object with a true ok flag. When `required_key` is set,
    usable also means the key is present. The caller owns the fallback policy."""
    obj = extract_json_object(text)
    ok = bool(obj) and (required_key is None or required_key in obj)
    return (obj or {}), ok


def _first_balanced_object(text: str) -> dict | None:
    """The first complete top-level {...} span, counting braces only outside of
    string literals so braces inside a value, for example code in a description like "{x}", do not
    corrupt the depth count."""
    depth = 0
    start = -1
    in_str = False
    escaped = False
    for i, ch in enumerate(text):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1
                    continue
                if isinstance(obj, dict):
                    return obj
    return None


def _repair(text: str) -> dict | None:
    """Last resort: repair malformed or truncated JSON such as unescaped quotes, trailing
    commas, or an unterminated reply. Optional dependency, a no-op if absent."""
    try:
        from json_repair import repair_json
    except ImportError:
        return None
    try:
        obj = repair_json(text, return_objects=True)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None
