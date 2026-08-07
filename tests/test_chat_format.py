"""choice_text: pull the assistant text out of the Chat Completions response shapes.

and return empty on a missing or malformed choice rather than raising.
"""

from types import SimpleNamespace

from cyberjury.providers.chat_format import choice_text


def test_extracts_plain_string_content():
    """Exercise the extracts plain string content case."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="hello"))])
    assert choice_text(resp) == "hello"


def test_extracts_content_block_list():
    """Exercise the extracts content block list case."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message={"content": [{"text": "a"}, {"text": "b"}, "c"]})])
    assert choice_text(resp) == "abc"


def test_no_choices_returns_empty():
    """Exercise the no choices returns empty case."""
    assert choice_text(SimpleNamespace(choices=[])) == ""
    assert choice_text(SimpleNamespace(choices=None)) == ""


def test_none_content_returns_empty():
    """Exercise the none content returns empty case."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None))])
    assert choice_text(resp) == ""


def test_dict_message_without_content_returns_empty():
    """Exercise the dict message without content returns empty case."""
    resp = SimpleNamespace(choices=[SimpleNamespace(message={})])
    assert choice_text(resp) == ""
