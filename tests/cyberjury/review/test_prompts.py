"""Source fences remain intact when repository text contains Markdown markers."""

from cyberjury.review.prompts import fenced_source, inline_source, one_line_source


def test_fenced_source_preserves_the_common_prompt_shape():
    assert fenced_source("value = 1") == "```\nvalue = 1\n```"
    assert fenced_source("+value = 1", "diff") == "```diff\n+value = 1\n```"


def test_fenced_source_uses_a_delimiter_absent_from_the_source():
    assert fenced_source('value = "```"') == '~~~\nvalue = "```"\n~~~'
    assert fenced_source("first\n```\nsecond") == "~~~\nfirst\n```\nsecond\n~~~"
    assert fenced_source('value = "~~~"') == '```\nvalue = "~~~"\n```'
    assert fenced_source("````\n~~~~", "diff") == "`````diff\n````\n~~~~\n`````"


def test_inline_source_and_labels_cannot_break_their_prompt_line():
    assert inline_source("plain") == "`plain`"
    assert inline_source("part`next") == "`` part`next ``"
    assert inline_source("`leading") == "`` `leading ``"
    assert one_line_source("first\nsecond\rthird\u2028fourth") == "first\\nsecond\\rthird\\u2028fourth"
