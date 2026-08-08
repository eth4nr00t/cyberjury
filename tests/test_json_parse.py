"""JSON object extraction separates fail loud callers from fallback callers."""

import pytest

from cyberjury.json_parse import extract_json_object, optional_json_object, require_json_object


class _Boom(RuntimeError):
    pass


def test_extracts_a_direct_object():
    """Extracts a direct object."""
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_extracts_from_a_fenced_block():
    """Extracts from a fenced block."""
    text = 'here you go:\n```json\n{"a": 1, "b": [2, 3]}\n```\nthanks'
    assert extract_json_object(text) == {"a": 1, "b": [2, 3]}


def test_extracts_an_object_amid_prose():
    """Extracts an object amid prose."""
    text = 'The verdict is {"status": "SECURE"} as shown.'
    assert extract_json_object(text) == {"status": "SECURE"}


def test_extracts_nested_braces():
    """Extracts nested braces."""
    text = 'noise {"outer": {"inner": {"x": 1}}} trailing'
    assert extract_json_object(text) == {"outer": {"inner": {"x": 1}}}


def test_extracts_the_next_object_when_the_first_is_invalid():
    """Extracts the next object when the first is invalid."""
    assert extract_json_object('note {not: json} then {"findings": []}') == {"findings": []}


def test_extracts_an_object_at_the_start_of_a_very_large_input():
    """Extracts an object at the start of a very large input."""
    assert extract_json_object('{"findings": []}' + " noise" * 300_000) == {"findings": []}


@pytest.mark.parametrize("text", ["", "no json here", "{not valid}", "[1, 2, 3]"])
def test_no_object_returns_none(text):
    """No object returns none."""
    assert extract_json_object(text) is None


def test_braces_inside_string_value_do_not_corrupt_depth():
    """Braces inside string value do not corrupt depth."""
    text = '{"description": "the sink is cursor.execute({user})", "line": 7}'
    assert extract_json_object(text) == {"description": "the sink is cursor.execute({user})", "line": 7}


def test_trailing_comma_is_repaired():
    """Trailing comma is repaired."""
    assert extract_json_object('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_truncated_object_is_repaired():
    """Truncated object is repaired."""
    out = extract_json_object('{"findings": [{"file": "a.py", "description": "unterminated')
    assert isinstance(out, dict)
    assert "findings" in out


def test_require_json_object_returns_the_object_when_the_key_is_present():
    """Require JSON object returns the object when the key is present."""
    result = require_json_object('{"findings": []}', required_key="findings", error=_Boom, message="x")
    assert result == {"findings": []}


def test_require_json_object_raises_when_no_object_is_found():
    """Require JSON object raises when no object is found."""
    with pytest.raises(_Boom, match="bad reply"):
        require_json_object("a refusal, no json", required_key="findings", error=_Boom, message="bad reply")


def test_require_json_object_raises_when_the_key_is_missing():
    """Require JSON object raises when the key is missing."""
    with pytest.raises(_Boom):
        require_json_object('{"other": 1}', required_key="findings", error=_Boom, message="missing key")


def test_optional_json_object_reports_usable_when_the_key_is_present():
    """Optional JSON object reports usable when the key is present."""
    obj, ok = optional_json_object('{"real": true}', required_key="real")
    assert obj == {"real": True}
    assert ok is True


def test_optional_json_object_reports_unusable_for_no_object():
    """Optional JSON object reports unusable for no object."""
    obj, ok = optional_json_object("not json at all", required_key="real")
    assert obj == {}
    assert ok is False


def test_optional_json_object_returns_the_object_but_not_usable_when_the_key_is_missing():
    """Optional JSON object returns the object but not usable when the key is missing."""
    obj, ok = optional_json_object('{"other": 1}', required_key="real")
    assert obj == {"other": 1}
    assert ok is False


def test_optional_json_object_without_a_required_key_is_usable_for_any_object():
    """Optional JSON object without a required key is usable for any object."""
    assert optional_json_object('{"x": 1}') == ({"x": 1}, True)
    assert optional_json_object("garbage") == ({}, False)
