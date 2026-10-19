"""JSON object extraction accepts only one complete reply object, possibly repeated verbatim."""

import pytest

from cyberjury.json_parse import parse_json_object


def test_parses_a_direct_object():
    assert parse_json_object('{"a": 1}') == {"a": 1}


def test_a_reply_repeating_one_object_is_that_object():
    assert parse_json_object('{"a": 1, "b": [2]} \n{"b": [2], "a": 1}') == {"a": 1, "b": [2]}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no json here",
        "{not valid}",
        "[1, 2, 3]",
        '{"findings": [',
        '{"a": 1, "b": 2,}',
        'The verdict is {"status": "SECURE"} as shown.',
        '```json\n{"a": 1}\n```',
        '{"a": 1} {"a": 2}',
        '{"a": 1} trailing',
    ],
)
def test_rejects_anything_but_one_complete_object(text):
    assert parse_json_object(text) is None
