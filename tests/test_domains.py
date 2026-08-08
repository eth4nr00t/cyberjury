"""The domain layer resolves content, detects domains, and fails loud on unavailable domains."""

import shutil

import pytest

from cyberjury.domains.base import content_paths
from cyberjury.domains.evm import EVM
from cyberjury.domains.registry import detect_domain, get_domain, resolve_domain
from cyberjury.domains.web import WEB
from cyberjury.markdown_docs import iter_md_docs


def test_web_domain_resolves_shipped_content():
    """Web domain resolves shipped content."""
    paths = WEB.paths
    assert paths.vulnerabilities_dir.is_dir()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert paths.severity_rubric_file.is_file()
    assert paths.knowledge_index.parent == paths.vulnerabilities_dir.parent


def test_content_paths_layout_follows_the_root():
    """Content paths layout follows the root."""
    paths = content_paths("/srv/x")
    assert str(paths.vulnerabilities_dir) == "/srv/x/knowledge/vulnerabilities"
    assert str(paths.detection_file) == "/srv/x/detection.yaml"
    assert str(paths.unit_review_file) == "/srv/x/playbook/unit-review.md"


def test_get_domain_returns_registered_and_fails_loud_on_unknown():
    """Get domain returns registered and fails loud on unknown."""
    assert get_domain("web") is WEB
    assert get_domain("evm") is EVM
    with pytest.raises(ValueError, match="unknown or unavailable review domain"):
        get_domain("nonsense")


def test_detect_domain_names_evm_for_solidity_web_otherwise():
    """Detect domain names EVM for solidity web otherwise."""
    assert detect_domain(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_domain(["Vault.sol", "Token.sol"]) == "evm"
    assert detect_domain(["Vault.sol", "deploy.py"]) == "evm"
    assert detect_domain([]) == "web"


def test_resolve_domain_auto_detects_then_looks_up():
    """Resolve domain auto detects then looks up."""
    assert resolve_domain("auto", ["a.py"]) is WEB
    assert resolve_domain("web", []) is WEB
    assert resolve_domain("auto", ["Vault.sol", "Token.sol"]) is EVM
    assert resolve_domain("evm", []) is EVM


def test_evm_domain_resolves_shipped_content_and_strategy():
    """EVM domain resolves shipped content and strategy."""
    paths = EVM.paths
    assert (paths.languages_dir / "solidity.md").is_file()
    assert (paths.vulnerabilities_dir / "reentrancy.md").is_file()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert "reentrancy" in EVM.lenses
    assert EVM.lenses != WEB.lenses
    assert "reentrancy" in EVM.diff_focus.lower()
    assert EVM.dedup_by_file is True
    assert WEB.dedup_by_file is False


@pytest.mark.parametrize("domain", [WEB, EVM])
def test_every_class_declares_a_domain_lens_and_every_lens_is_claimed(domain):
    """Every class declares a domain lens and every lens is claimed."""
    named = {lens for lens in domain.lenses if lens}
    claimed = set()
    for path, meta, _body in iter_md_docs(domain.paths.vulnerabilities_dir):
        lens = meta.get("lens")
        assert lens, f"{path.name} declares no lens"
        assert lens in named, f"{path.name} lens {lens!r} is not a {domain.name} lens"
        claimed.add(lens)
    assert claimed == named, f"{domain.name} lenses with no class: {named - claimed}"


@pytest.mark.parametrize("domain", [WEB, EVM])
def test_lens_naming_is_uniform(domain):
    """Lens naming is uniform."""
    class_ids = set()
    members: dict[str, list[str]] = {}
    for _path, meta, _body in iter_md_docs(domain.paths.vulnerabilities_dir):
        class_ids.add(meta["id"])
        members.setdefault(meta["lens"], []).append(meta["id"])
    for lens, claimed in members.items():
        if len(claimed) == 1:
            assert lens == claimed[0], (
                f"{domain.name} single-class lens {lens!r} must equal its class id {claimed[0]!r}"
            )
        else:
            assert lens not in class_ids, f"{domain.name} umbrella lens {lens!r} collides with a class id"


_EVM_NO_SWC = {"accounting-precision", "oracle-price-manipulation", "weird-erc20"}


def _class_tags(domain):
    for path, meta, _body in iter_md_docs(domain.paths.vulnerabilities_dir):
        yield path.name[:-3], [str(t) for t in (meta.get("tags") or [])]


@pytest.mark.parametrize("domain", [WEB, EVM])
def test_tags_lead_with_registry_codes(domain):
    """Tags lead with registry codes."""
    for cid, tags in _class_tags(domain):
        seen_keyword = False
        for t in tags:
            if not t.startswith(("swc-", "cwe-", "owasp-")):
                seen_keyword = True
            elif seen_keyword:
                pytest.fail(f"{domain.name}/{cid}: code {t!r} after a keyword, tags={tags}")


def test_every_web_class_tags_a_cwe_and_an_owasp():
    """Web knowledge anchors on the CWE and OWASP taxonomies, so every class carries both."""
    for cid, tags in _class_tags(WEB):
        assert any(t.startswith("cwe-") for t in tags), f"web/{cid} has no cwe tag: {tags}"
        assert any(t.startswith("owasp-") for t in tags), f"web/{cid} has no owasp tag: {tags}"


def test_every_evm_class_tags_swc_unless_post_swc_defi():
    """Every EVM class tags SWC unless post SWC DeFi."""
    for cid, tags in _class_tags(EVM):
        has_swc = any(t.startswith("swc-") for t in tags)
        if cid in _EVM_NO_SWC:
            assert not has_swc, f"evm/{cid} now has an swc id, drop it from the no-swc allowlist"
            assert tags, f"evm/{cid} has no tags at all"
        else:
            assert has_swc, f"evm/{cid} has no swc tag and is not an allowed exception: {tags}"


@pytest.mark.parametrize("domain", [WEB, EVM])
def test_every_class_carries_a_code_example(domain):
    """Every class carries a code example."""
    for path, _meta, body in iter_md_docs(domain.paths.vulnerabilities_dir):
        assert "```" in body, f"{domain.name}/{path.name[:-3]} has no fenced code example"


def test_evm_facts_backend_fails_loud_without_slither(monkeypatch):
    """EVM facts backend fails loud without slither."""
    from cyberjury.domains.base import BackendUnavailable, FactsBackend
    from cyberjury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    assert isinstance(backend, FactsBackend)
    monkeypatch.setattr(backend, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        backend.extract(".")


def test_evm_poc_backend_fails_loud_without_forge(monkeypatch):
    """EVM PoC backend fails loud without forge."""
    from cyberjury.domains.base import BackendUnavailable
    from cyberjury.domains.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider

    poc = ForgePoC(provider=MockProvider(default="x"), model="m")
    monkeypatch.setattr(poc, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        poc.reproduce(title="x", analysis="", symbol="", file="A.sol", line=1, root=".")


def test_forge_poc_repairs_its_test_after_a_failure(monkeypatch, tmp_path):
    """Forge PoC repairs its test after a failure."""
    from contextlib import contextmanager

    from cyberjury.domains.evm.poc import ForgePoC
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
    """Forge PoC generate writes a test without running it."""
    from cyberjury.domains.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider

    (tmp_path / "A.sol").write_text("contract A {}")
    poc = ForgePoC(provider=MockProvider(default="contract PoC {}"), model="m")
    art = poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))
    assert art.ext == "t.sol"
    assert "PoC" in art.source
    assert art.run_hint


def test_forge_poc_generate_needs_a_provider(tmp_path):
    """Forge PoC generate needs a provider."""
    from cyberjury.domains.evm.poc import ForgePoC

    poc = ForgePoC()
    with pytest.raises(ValueError, match="needs a provider"):
        poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))


def test_forge_poc_execute_skips_and_notes_when_forge_is_absent(monkeypatch, tmp_path):
    """Forge PoC execute skips and notes when forge is absent."""
    from cyberjury.domains.evm.poc import ForgePoC

    poc = ForgePoC()
    monkeypatch.setattr(poc, "available", lambda: False)
    res = poc.execute(source="contract PoC {}", root=str(tmp_path))
    assert res.ran is False
    assert res.ok is False
    assert "not installed" in res.detail


def test_web_domain_binds_a_poc_backend():
    """Web domain binds a PoC backend."""
    assert WEB.poc_backend is not None


def test_web_poc_writes_a_python_script_and_never_runs_it(tmp_path):
    """Web PoC writes a python script and never runs it."""
    from cyberjury.domains.web.poc import WebPoC
    from cyberjury.providers.mock import MockProvider

    poc = WebPoC(provider=MockProvider(default="import requests\nassert True\n"), model="m")
    art = poc.generate(
        title="idor", analysis="no owner check", symbol="get_order", file="views.py", line=3, root=str(tmp_path)
    )
    assert art.ext == "py"
    assert "requests" in art.source
    assert art.run_hint
    assert art.note == ""
    assert poc.available() is False
    assert poc.executes is False
    res = poc.execute(source=art.source, root=str(tmp_path))
    assert res.ran is False


def test_web_poc_generate_needs_a_provider(tmp_path):
    """Web PoC generate needs a provider."""
    from cyberjury.domains.web.poc import WebPoC

    with pytest.raises(ValueError, match="needs a provider"):
        WebPoC().generate(title="t", analysis="a", symbol="s", file="v.py", line=1, root=str(tmp_path))


def test_web_poc_flags_a_script_that_does_not_parse(tmp_path):
    """Web PoC flags a script that does not parse."""
    from cyberjury.domains.web.poc import WebPoC
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
    """Web PoC feeds the endpoint and handler source into the prompt."""
    from cyberjury.domains.web.poc import WebPoC

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
    """Web PoC prompt drops the read from above line with no endpoint or source."""
    from cyberjury.domains.web.poc import _prompt

    grounded = _prompt(
        title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="POST /x", source="def h(): ..."
    )
    bare = _prompt(title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="", source="")
    assert "do not guess" in grounded
    assert "do not guess" not in bare


def test_web_poc_marks_a_truncated_handler_source(tmp_path):
    """Web PoC marks a truncated handler source."""
    from cyberjury.domains.web.poc import _SOURCE_CAP, _read_source

    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * _SOURCE_CAP, encoding="utf-8")
    out = _read_source(big)
    assert "source truncated" in out
    assert len(out) < _SOURCE_CAP + 100


def test_forge_poc_exposes_one_install_hint_source():
    """Forge PoC exposes one install hint source."""
    from cyberjury.domains.evm.poc import _FOUNDRY_URL, _INSTALL_HINT, ForgePoC

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
    """Forge PoC compiles and runs a local test."""
    from cyberjury.domains.evm.poc import ForgePoC
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


_REENTRANT_VAULT = """\
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function _check(uint256 a) internal view returns (bool) { return balances[msg.sender] >= a; }
    function withdraw(uint256 amount) external {
        require(_check(amount), "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


def test_slither_facts_extract_grounds_a_real_contract(tmp_path):
    """Slither facts extract grounds a real contract."""
    from shutil import which

    from cyberjury.domains.base import BackendUnavailable
    from cyberjury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    if not backend.available() or which("solc") is None:
        pytest.skip("Slither or solc not installed, the extraction path needs both")
    sol = tmp_path / "Vault.sol"
    sol.write_text(_REENTRANT_VAULT, encoding="utf-8")

    try:
        facts = backend.extract(sol)
    except BackendUnavailable:
        pytest.skip("the solc on PATH cannot compile, no usable Solidity toolchain")
    assert not facts.empty
    vault = facts.data["contracts"]["Vault"]
    assert "balances" in {v["name"] for v in vault["state"]}
    withdraw = vault["functions"]["withdraw(uint256)"]
    assert withdraw["visibility"] == "external"
    assert "balances" in withdraw["writes"]
    assert withdraw["external_call"]
    assert withdraw["sends_eth"]
    assert "_check(uint256)" in withdraw["calls"]
    assert "ext-call" in facts.summary
    key = next(k for k in facts.data["by_file"] if k.endswith("Vault.sol"))
    assert "contract Vault" in facts.data["by_file"][key]
    assert "reenter" in facts.data["by_file"][key]
    text = sol.read_text()
    withdraw_unit = next(u for u in facts.data["units"] if "withdraw" in u["name"])
    body = "".join(text[s:e] for _f, s, e in withdraw_unit["fragments"])
    assert "function withdraw" in body
    assert "_check" in body


def test_by_file_groups_contract_facts_by_source_path():
    """The by_file map groups contract facts by source path."""
    from cyberjury.domains.evm.facts.slither import _by_file

    def fn(**kw):
        base = {
            "visibility": "external",
            "modifiers": [],
            "reads": [],
            "writes": [],
            "calls": [],
            "external_call": False,
            "sends_eth": False,
            "can_reenter": False,
        }
        return {**base, **kw}

    contracts = {
        "Vault": {
            "file": "src/Vault.sol",
            "state": [],
            "functions": {"withdraw()": fn(external_call=True, can_reenter=True)},
        },
        "Token": {"file": "src/Token.sol", "state": [], "functions": {}},
        "Lib": {"file": "", "state": [], "functions": {}},
    }
    by = _by_file(contracts)
    assert set(by) == {"src/Vault.sol", "src/Token.sol"}
    assert "contract Vault" in by["src/Vault.sol"]
    assert "reenter" in by["src/Vault.sol"]
    assert "contract Token" in by["src/Token.sol"]


def test_evm_facts_callgraph_uses_the_shared_definition_graph_shape():
    """EVM facts callgraph uses the shared definition graph shape."""
    from cyberjury.domains.evm.facts.slither import _callgraph

    contracts = {
        "Vault": {
            "file": "src/Vault.sol",
            "state": [],
            "functions": {
                "pause()": _fn([5, 10]),
                "withdraw(uint256)": _fn([100, 300], calls=["_check(uint256)", "_check(address)"]),
                "_check(uint256)": _fn([20, 80]),
            },
        },
        "Admin": {
            "file": "src/Vault.sol",
            "state": [],
            "functions": {"pause()": _fn([320, 370])},
        },
        "Missing": {"file": "", "state": [], "functions": {"ghost()": _fn([0, 1])}},
    }
    graph = _callgraph(contracts)
    assert set(graph) == {"src/Vault.sol"}
    assert graph["src/Vault.sol"]["withdraw"] == [{"range": [100, 300], "calls": ["_check"]}]
    assert graph["src/Vault.sol"]["_check"] == [{"range": [20, 80], "calls": []}]
    assert graph["src/Vault.sol"]["pause"] == [
        {"range": [5, 10], "calls": []},
        {"range": [320, 370], "calls": []},
    ]


def _fn(rng, **flags):
    base = {
        "visibility": "internal",
        "modifiers": [],
        "reads": [],
        "writes": [],
        "calls": [],
        "external_call": False,
        "sends_eth": False,
        "can_reenter": False,
        "range": rng,
    }
    return {**base, **flags}


def test_call_path_units_anchor_on_risk_functions_with_neighborhood():
    """Call path units anchor on risk functions with neighborhood."""
    from cyberjury.domains.evm.facts.call_path import call_path_units

    contracts = {
        "Vault": {
            "file": "src/Vault.sol",
            "state": [],
            "functions": {
                "getBalance()": _fn([0, 100]),
                "liquidate()": _fn([100, 300], external_call=True, can_reenter=True, calls=["_cleanupLoan()"]),
                "_cleanupLoan()": _fn([300, 420], external_call=True, can_reenter=True, calls=["_update()"]),
                "_update()": _fn([420, 480]),
            },
        }
    }
    units = call_path_units(contracts)
    assert len(units) == 1
    u = units[0]
    assert "_cleanupLoan" in u["name"]
    assert u["files"] == ["src/Vault.sol"]
    starts = [f[1] for f in u["fragments"]]
    assert starts == sorted(starts) == [100, 300, 420]
    assert all(f[0] == "src/Vault.sol" for f in u["fragments"])
    assert not any(f[1] == 0 for f in u["fragments"])


def test_call_path_units_skip_no_range_and_respect_the_char_cap():
    """Call path units skip no range and respect the char cap."""
    from cyberjury.domains.evm.facts.call_path import _UNIT_CHAR_CAP, call_path_units

    contracts = {
        "C": {
            "file": "a.sol",
            "state": [],
            "functions": {
                "f()": _fn([0, 50], external_call=True, calls=["big()", "noRange()"]),
                "big()": _fn([50, 50 + _UNIT_CHAR_CAP + 100]),
                "noRange()": _fn(None),
            },
        }
    }
    units = call_path_units(contracts)
    assert len(units) == 1
    frags = units[0]["fragments"]
    assert [f[1] for f in frags] == [0]


def test_rel_file_relativizes_to_root_and_falls_back(tmp_path):
    """Rel file relativizes to root and falls back."""
    from cyberjury.domains.evm.facts.slither import _rel_file

    class _Name:
        def __init__(self, absolute="", short=""):
            self.absolute = absolute
            self.short = short
            self.used = ""

    def contract(name):
        return type("C", (), {"source_mapping": type("M", (), {"filename": name})()})()

    root = tmp_path.resolve()
    assert _rel_file(contract(_Name(absolute=str(root / "src" / "Vault.sol"))), root) == "src/Vault.sol"
    assert _rel_file(contract(_Name(absolute="/elsewhere/Ownable.sol")), root) == "Ownable.sol"
    assert _rel_file(contract(_Name(absolute=str(root / "Vault.sol"))), root / "Vault.sol") == "Vault.sol"
    assert _rel_file(type("C2", (), {"source_mapping": None})(), root) == ""


def _fake_contract(absolute: str):
    name = type("N", (), {"absolute": absolute, "short": "", "used": ""})()
    return type("C", (), {"source_mapping": type("M", (), {"filename": name})()})()


def test_compile_root_widens_to_the_framework_config(tmp_path):
    """Compile root widens to the framework config."""
    from cyberjury.domains.evm.facts.slither import _compile_root

    repository = tmp_path / "proj"
    (repository / "contracts").mkdir(parents=True)
    (repository / ".git").mkdir()
    (repository / "hardhat.config.js").write_text("module.exports = {}")
    assert _compile_root((repository / "contracts").resolve()) == repository.resolve()


def test_compile_root_stays_put_when_the_scope_is_already_the_framework_root(tmp_path):
    """Compile root stays put when the scope is already the framework root."""
    from cyberjury.domains.evm.facts.slither import _compile_root

    repository = tmp_path / "proj"
    repository.mkdir()
    (repository / ".git").mkdir()
    (repository / "foundry.toml").write_text("[profile.default]")
    assert _compile_root(repository.resolve()) == repository.resolve()


def test_compile_root_never_leaves_the_repository(tmp_path):
    """Compile root never leaves the repository."""
    from cyberjury.domains.evm.facts.slither import _compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    repository = tmp_path / "proj"
    (repository / "src").mkdir(parents=True)
    (repository / ".git").mkdir()
    scope = (repository / "src").resolve()
    assert _compile_root(scope) == scope


def test_compile_root_does_not_widen_without_a_repository(tmp_path):
    """Compile root does not widen without a repository."""
    from cyberjury.domains.evm.facts.slither import _compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    scope = (tmp_path / "sources").resolve()
    scope.mkdir()
    assert _compile_root(scope) == scope


def test_single_file_explorer_tree_uses_the_source_file_as_the_slither_target(tmp_path):
    """Single file explorer tree uses the source file as the Slither target."""
    from cyberjury.domains.evm.facts.slither import _slither_target

    source = tmp_path / "Token.sol"
    source.write_text("contract Token {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == source.resolve()


def test_configured_single_file_tree_uses_the_directory_as_the_slither_target(tmp_path):
    """Configured single file tree uses the directory as the Slither target."""
    from cyberjury.domains.evm.facts.slither import _slither_target

    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_multi_file_explorer_tree_uses_the_directory_as_the_slither_target(tmp_path):
    """Multi file explorer tree uses the directory as the Slither target."""
    from cyberjury.domains.evm.facts.slither import _slither_target

    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    (tmp_path / "Ownable.sol").write_text("contract Ownable {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_in_scope_keeps_the_review_tree_and_drops_the_rest(tmp_path):
    """In scope keeps the review tree and drops the rest."""
    from cyberjury.domains.evm.facts.slither import _in_scope

    scope = (tmp_path / "contracts").resolve()
    scope.mkdir()
    assert _in_scope(_fake_contract(str(scope / "Token.sol")), scope) is True
    assert _in_scope(_fake_contract(str(tmp_path / "test" / "Token.t.sol")), scope) is False
    assert _in_scope(_fake_contract(""), scope) is True


def test_a_widened_compile_that_covers_no_scoped_contract_fails_loud(tmp_path):
    """Widened compile that covers no scoped contract fails loud."""
    from shutil import which

    from cyberjury.domains.base import BackendUnavailable
    from cyberjury.domains.evm.facts.slither import SlitherFacts

    backend = SlitherFacts()
    if not backend.available() or which("forge") is None:
        pytest.skip("Slither or Foundry not installed, this needs a real widened compile")
    repository = tmp_path / "proj"
    (repository / "src").mkdir(parents=True)
    (repository / "views").mkdir()
    (repository / ".git").mkdir()
    (repository / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repository / "src" / "Vault.sol").write_text(_REENTRANT_VAULT, encoding="utf-8")
    with pytest.raises(BackendUnavailable, match="no contract under the review scope"):
        backend.extract(repository / "views")


def test_importing_the_evm_domain_does_not_pull_the_heavy_tools():
    """Importing the EVM domain does not pull the heavy tools."""
    import subprocess
    import sys

    code = (
        "import cyberjury.domains.evm, sys\n"
        "assert 'slither' not in sys.modules\n"
        "assert 'cyberjury.domains.evm.poc' not in sys.modules\n"
        "assert 'cyberjury.review' not in sys.modules\n"
        "assert not [m for m in sys.modules if 'domains.web' in m]\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_both_domains_bind_a_facts_backend():
    """Both domains bind a facts backend."""
    from cyberjury.domains.base import FactsBackend

    assert isinstance(EVM.facts_backend, FactsBackend)
    assert isinstance(WEB.facts_backend, FactsBackend)


def test_each_backend_names_its_own_toolchain_in_its_install_hint():
    """Each backend names its own toolchain in its install hint."""
    assert "solc" in EVM.facts_backend.install_hint
    assert "tree-sitter" in WEB.facts_backend.install_hint
    assert "solc" not in WEB.facts_backend.install_hint
