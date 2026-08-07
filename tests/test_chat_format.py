"""choice_text: pull the assistant text out of the Chat Completions response shapes.

and return empty on a missing or malformed choice rather than raising.
"""

from types import SimpleNamespace

from cyberjury.providers.chat_format import choice_text


def test_extracts_plain_string_content():
    """Extracts plain string content."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="hello"))])
    assert choice_text(resp) == "hello"


def test_extracts_content_block_list():
    """Extracts content block list."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message={"content": [{"text": "a"}, {"text": "b"}, "c"]})])
    assert choice_text(resp) == "abc"


def test_no_choices_returns_empty():
    """No choices returns empty."""
    assert choice_text(SimpleNamespace(choices=[])) == ""
    assert choice_text(SimpleNamespace(choices=None)) == ""


def test_none_content_returns_empty():
    """None content returns empty."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None))])
    assert choice_text(resp) == ""


def test_dict_message_without_content_returns_empty():
    """Dict message without content returns empty."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message={})])
    assert choice_text(resp) == ""
