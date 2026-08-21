"""Web proof generation stays grounded and never executes provider output."""

import pytest

from cyberjury.profiles.web import WEB_PROFILE


def test_web_profile_binds_a_poc_backend():
    assert WEB_PROFILE.poc_backend is not None


def test_web_poc_writes_a_python_script_and_never_runs_it(tmp_path):
    from cyberjury.profiles.web.poc import WebPoC
    from cyberjury.providers.mock import MockProvider

    poc = WebPoC(provider=MockProvider(default="import requests\nassert True\n"), model="m")
    art = poc.generate(
        title="idor", analysis="no owner check", symbol="get_order", file="views.py", line=3, root=str(tmp_path)
    )
    assert poc.ext == "py"
    assert "requests" in art.source
    assert art.run_hint
    assert art.note == ""
    assert poc.available() is False
    assert poc.executes is False
    res = poc.execute(source=art.source, root=str(tmp_path))
    assert res.ran is False


def test_web_poc_generate_needs_a_provider(tmp_path):
    from cyberjury.profiles.web.poc import WebPoC

    with pytest.raises(ValueError, match="needs a provider"):
        WebPoC().generate(title="t", analysis="a", symbol="s", file="v.py", line=1, root=str(tmp_path))


def test_web_poc_flags_a_script_that_does_not_parse(tmp_path):
    from cyberjury.profiles.web.poc import WebPoC
    from cyberjury.providers.mock import MockProvider

    poc = WebPoC(provider=MockProvider(default="def broken(:\n"), model="m")
    art = poc.generate(title="idor", analysis="a", symbol="s", file="v.py", line=1, root=str(tmp_path))
    assert art.source == "def broken(:"
    assert "does not parse" in art.note


class _RecordingProvider:
    """A provider records the user prompt so grounding can be asserted."""

    def __init__(self, text: str):
        self._text = text
        self.last_user = ""

    def complete(self, *, system, messages, model, max_tokens, cache):
        from types import SimpleNamespace

        self.last_user = messages[-1].content
        return SimpleNamespace(text=self._text)


def test_web_poc_feeds_the_endpoint_and_handler_source_into_the_prompt(tmp_path):
    from cyberjury.profiles.web.poc import WebPoC

    src = tmp_path / "models" / "memories.py"
    src.parent.mkdir(parents=True)
    src.write_text(
        "def update_memory_by_id(id, form):\n    return db.query(Memory).filter(Memory.id == id)\n", encoding="utf-8"
    )
    rec = _RecordingProvider("import requests\n")
    WebPoC(provider=rec, model="m").generate(
        title="idor",
        analysis="a",
        symbol="update_memory_by_id",
        file="models/memories.py",
        line=None,
        root=str(tmp_path),
        endpoint="POST /memories/{id}/update",
    )
    assert "POST /memories/{id}/update" in rec.last_user
    assert "filter(Memory.id == id)" in rec.last_user


def test_web_poc_prompt_drops_the_read_from_above_line_with_no_endpoint_or_source():
    from cyberjury.profiles.web.poc import _prompt

    grounded = _prompt(
        title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="POST /x", source="def h(): ..."
    )
    bare = _prompt(title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="", source="")
    assert "do not guess" in grounded
    assert "do not guess" not in bare


def test_web_poc_marks_a_truncated_handler_source(tmp_path):
    from cyberjury.profiles.web.poc import _MAX_HANDLER_SOURCE_CHARS, _read_source

    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * _MAX_HANDLER_SOURCE_CHARS, encoding="utf-8")
    out = _read_source(big)
    assert "source truncated" in out
    assert len(out) < _MAX_HANDLER_SOURCE_CHARS + 100
