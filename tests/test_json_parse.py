"""The shared JSON-object extraction.

require_json_object fails loud for callers that must not pass an unusable reply,
optional_json_object degrades for the ones that fall back.
"""

import pytest

from cyberjury.json_parse import extract_json_object, optional_json_object, require_json_object


class _Boom(RuntimeError):
    pass


def test_extracts_a_direct_object():
    """Exercise the extracts a direct object case."""
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_extracts_from_a_fenced_block():
    """Exercise the extracts from a fenced block case."""
    text = 'here you go:\n```json\n{"a": 1, "b": [2, 3]}\n```\nthanks'
    assert extract_json_object(text) == {"a": 1, "b": [2, 3]}


def test_extracts_an_object_amid_prose():
    """Exercise the extracts an object amid prose case."""
    text = 'The verdict is {"status": "SECURE"} as shown.'
    assert extract_json_object(text) == {"status": "SECURE"}


def test_extracts_nested_braces():
    """Exercise the extracts nested braces case."""
    text = 'noise {"outer": {"inner": {"x": 1}}} trailing'
    assert extract_json_object(text) == {"outer": {"inner": {"x": 1}}}


def test_extracts_the_next_object_when_the_first_is_invalid():
    """Exercise the extracts the next object when the first is invalid case."""
    assert extract_json_object('note {not: json} then {"findings": []}') == {"findings": []}


def test_extracts_an_object_at_the_start_of_a_very_large_input():
    """Exercise the extracts an object at the start of a very large input case."""
    assert extract_json_object('{"findings": []}' + " noise" * 300_000) == {"findings": []}


@pytest.mark.parametrize("text", ["", "no json here", "{not valid}", "[1, 2, 3]"])
def test_no_object_returns_none(text):
    """Exercise the no object returns none case."""
    assert extract_json_object(text) is None


def test_braces_inside_string_value_do_not_corrupt_depth():
    """Exercise the braces inside string value do not corrupt depth case."""
    text = '{"description": "the sink is cursor.execute({user})", "line": 7}'
    assert extract_json_object(text) == {"description": "the sink is cursor.execute({user})", "line": 7}


def test_trailing_comma_is_repaired():
    """Exercise the trailing comma is repaired case."""
    assert extract_json_object('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_truncated_object_is_repaired():
    """Exercise the truncated object is repaired case."""
    out = extract_json_object('{"findings": [{"file": "a.py", "description": "unterminated')
    assert isinstance(out, dict)
    assert "findings" in out


def test_require_json_object_returns_the_object_when_the_key_is_present():
    """Exercise the require json object returns the object when the key is present case."""
    result = require_json_object('{"findings": []}', required_key="findings", error=_Boom, message="x")
    assert result == {"findings": []}


def test_require_json_object_raises_when_no_object_is_found():
    """Exercise the require json object raises when no object is found case."""
    with pytest.raises(_Boom, match="bad reply"):
        require_json_object("a refusal, no json", required_key="findings", error=_Boom, message="bad reply")


def test_require_json_object_raises_when_the_key_is_missing():
    """Exercise the require json object raises when the key is missing case."""
    with pytest.raises(_Boom):
        require_json_object('{"other": 1}', required_key="findings", error=_Boom, message="missing key")


def test_optional_json_object_reports_usable_when_the_key_is_present():
    """Exercise the optional json object reports usable when the key is present case."""
    obj, ok = optional_json_object('{"real": true}', required_key="real")
    assert obj == {"real": True}
    assert ok is True


def test_optional_json_object_reports_unusable_for_no_object():
    """Exercise the optional json object reports unusable for no object case."""
    obj, ok = optional_json_object("not json at all", required_key="real")
    assert obj == {}
    assert ok is False


def test_optional_json_object_returns_the_object_but_not_usable_when_the_key_is_missing():
    """Exercise the optional json object returns the object but not usable when the key is missing case."""
    obj, ok = optional_json_object('{"other": 1}', required_key="real")
    assert obj == {"other": 1}
    assert ok is False


def test_optional_json_object_without_a_required_key_is_usable_for_any_object():
    """Exercise the optional json object without a required key is usable for any object case."""
    assert optional_json_object('{"x": 1}') == ({"x": 1}, True)
    assert optional_json_object("garbage") == ({}, False)
