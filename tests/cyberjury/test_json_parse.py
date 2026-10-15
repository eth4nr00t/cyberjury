"""JSON object extraction accepts only one complete reply object."""

import pytest

from cyberjury.json_parse import parse_json_object


def test_parses_a_direct_object():
    assert parse_json_object('{"a": 1}') == {"a": 1}


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
    ],
)
def test_rejects_anything_but_one_complete_object(text):
    assert parse_json_object(text) is None
