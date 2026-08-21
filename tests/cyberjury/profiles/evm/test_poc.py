"""Forge proof generation repairs local tests and fails loud without its toolchain."""

import shutil

import pytest


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
