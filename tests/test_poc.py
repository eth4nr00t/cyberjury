"""Test Web and Forge proof of concept generation and execution boundaries."""

import shutil

import pytest

from cyberjury.profiles.web import WEB_PROFILE


def test_profile_poc_backends_implement_the_shared_contracts():
    from cyberjury.profiles.base import PoCBackend, ReproducingPoCBackend
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.profiles.web.poc import WebPoC

    web = WebPoC()
    evm = ForgePoC()

    assert isinstance(web, PoCBackend)
    assert isinstance(evm, PoCBackend)
    assert not isinstance(web, ReproducingPoCBackend)
    assert isinstance(evm, ReproducingPoCBackend)


def test_evm_poc_backend_fails_loud_without_forge(monkeypatch):
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider
    from cyberjury.review.facts import BackendUnavailable

    poc = ForgePoC(provider=MockProvider(default="x"), model="m")
    monkeypatch.setattr(poc, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        poc.reproduce(title="x", analysis="", symbol="", file="A.sol", line=1, root=".")


def test_forge_poc_repairs_its_test_after_a_failure(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.base import CompletionResult

    class SeqProvider:
        def __init__(self, texts):
            self._it = iter(texts)

        def complete(self, **kw):
            return CompletionResult(text=next(self._it))

    (tmp_path / "A.sol").write_text("contract A {}")
    poc = ForgePoC(provider=SeqProvider(["broken source", "good source"]), model="m", attempts=2)
    monkeypatch.setattr(poc, "available", lambda: True)

    @contextmanager
    def fake_project(root, sources, foundry):
        yield tmp_path, "test/PoC.t.sol"

    runs = []

    def fake_run(proj, test_source, test_path):
        runs.append(test_source)
        ok = test_source == "good source"
        return ok, "PoC passed" if ok else "compile failed: bad literal"

    monkeypatch.setattr(poc, "_project", fake_project)
    monkeypatch.setattr(poc, "_run_test", fake_run)
    res = poc.reproduce(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))
    assert res.reproduced
    assert runs == ["broken source", "good source"]


def test_forge_poc_generate_writes_a_test_without_running_it(tmp_path):
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider

    (tmp_path / "A.sol").write_text("contract A {}")
    poc = ForgePoC(provider=MockProvider(default="contract PoC {}"), model="m")
    art = poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))
    assert poc.ext == "t.sol"
    assert "PoC" in art.source
    assert art.run_hint


def test_forge_poc_generate_needs_a_provider(tmp_path):
    from cyberjury.profiles.evm.poc import ForgePoC

    poc = ForgePoC()
    with pytest.raises(ValueError, match="needs a provider"):
        poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))


def test_forge_poc_execute_skips_and_notes_when_forge_is_absent(monkeypatch, tmp_path):
    from cyberjury.profiles.evm.poc import ForgePoC

    poc = ForgePoC()
    monkeypatch.setattr(poc, "available", lambda: False)
    res = poc.execute(source="contract PoC {}", root=str(tmp_path))
    assert res.ran is False
    assert res.ok is False
    assert "not installed" in res.detail


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


def test_forge_poc_exposes_one_install_hint_source():
    from cyberjury.profiles.evm.poc import _FOUNDRY_URL, _INSTALL_HINT, ForgePoC

    assert _FOUNDRY_URL in ForgePoC.install_hint
    assert _FOUNDRY_URL in _INSTALL_HINT


_POC_TEST = """\
pragma solidity ^0.8.0;
import "../src/C.sol";
contract PoCTest {
    function testExploit() public {
        C c = new C();
        require(c.v() == 42, "unexpected");
    }
}
"""


@pytest.mark.skipif(shutil.which("forge") is None, reason="Foundry not installed")
def test_forge_poc_compiles_and_runs_a_local_test(tmp_path):
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider

    (tmp_path / "C.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract C { function v() public pure returns (uint) { return 42; } }\n"
    )
    poc = ForgePoC(provider=MockProvider(default=_POC_TEST), model="m", timeout=120)
    res = poc.reproduce(title="t", analysis="a", symbol="v", file="C.sol", line=1, root=str(tmp_path))
    if not res.reproduced and "compile failed" in res.detail:
        pytest.skip("solc toolchain or network unavailable for compile")
    assert res.reproduced
    assert res.test_source == _POC_TEST.strip()
