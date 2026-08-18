"""The profile layer resolves content, detects profiles, and fails loud on unavailable profiles."""

import re
import shutil

import pytest

from cyberjury.markdown_docs import iter_md_docs
from cyberjury.profiles.base import content_paths
from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.registry import detect_profile, get_profile, resolve_profile
from cyberjury.profiles.web import WEB_PROFILE

_VULNERABILITY_REQUIRED_FIELDS = {"id", "title", "impact", "tags", "selection_hints"}
_VULNERABILITY_OPTIONAL_FIELDS = {"aliases"}
_VULNERABILITY_FIELD_ORDER = ("id", "title", "impact", "tags", "selection_hints", "aliases")
_LOW_SIGNAL_SELECTION_HINTS = {
    "/ ",
    ".length",
    "@app.route",
    "@router",
    "amount",
    "auth",
    "check",
    "constructor",
    "cursor",
    "external",
    "find(",
    "form",
    "location",
    "merge",
    "open(",
    "origin",
    "price",
    "public",
    "request.args",
    "resource",
    "session",
    "status",
    "transfer(",
    "while",
}


def test_web_profile_resolves_shipped_content():
    """Shipped Web assets must remain discoverable through the profile boundary."""
    paths = WEB_PROFILE.paths
    assert paths.vulnerabilities_dir.is_dir()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert paths.severity_rubric_file.is_file()
    assert paths.knowledge_index.parent == paths.vulnerabilities_dir.parent


def test_content_paths_layout_follows_the_root():
    """A custom content root must preserve the documented directory contract."""
    paths = content_paths("/srv/x")
    assert str(paths.vulnerabilities_dir) == "/srv/x/knowledge/vulnerabilities"
    assert str(paths.detection_file) == "/srv/x/detection.yaml"
    assert str(paths.unit_review_file) == "/srv/x/playbook/unit-review.md"


def test_get_profile_returns_registered_and_fails_loud_on_unknown():
    """Registry lookup must reject unsupported profiles instead of falling back silently."""
    assert get_profile("web") is WEB_PROFILE
    assert get_profile("evm") is EVM_PROFILE
    with pytest.raises(ValueError, match="unknown or unavailable review profile"):
        get_profile("nonsense")


def test_detect_profile_names_evm_for_any_solidity_source():
    """Any Solidity source must select EVM knowledge regardless of neighboring files."""
    assert detect_profile(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_profile(["Vault.sol", "Token.sol"]) == "evm"
    assert detect_profile(["Vault.sol", "deploy.py"]) == "evm"
    assert detect_profile(["Vault.sol", "README.md", "foundry.toml", "explorer-raw.json"]) == "evm"
    assert detect_profile([]) == "web"


def test_resolve_profile_auto_detects_then_looks_up():
    """Automatic and explicit selection must converge on registered profile objects."""
    assert resolve_profile("auto", ["a.py"]) is WEB_PROFILE
    assert resolve_profile("web", []) is WEB_PROFILE
    assert resolve_profile("auto", ["Vault.sol", "Token.sol"]) is EVM_PROFILE
    assert resolve_profile("evm", []) is EVM_PROFILE


def test_evm_profile_resolves_shipped_content_and_strategy():
    """Shipped EVM assets and deduplication policy must remain bound to one profile."""
    paths = EVM_PROFILE.paths
    assert (paths.languages_dir / "solidity.md").is_file()
    assert (paths.vulnerabilities_dir / "reentrancy.md").is_file()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert "reentrancy" in EVM_PROFILE.diff_focus.lower()
    assert EVM_PROFILE.dedup_by_file is True
    assert WEB_PROFILE.dedup_by_file is False


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_frontmatter_uses_the_shared_schema(profile):
    """The class metadata contract is shared across review profiles."""
    allowed = _VULNERABILITY_REQUIRED_FIELDS | _VULNERABILITY_OPTIONAL_FIELDS
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        fields = set(meta)
        assert fields >= _VULNERABILITY_REQUIRED_FIELDS, f"{profile.name}/{path.name}: missing schema fields"
        assert fields <= allowed, f"{profile.name}/{path.name}: unknown schema fields {fields - allowed}"
        assert meta["id"] == path.stem, f"{profile.name}/{path.name}: id must match the file stem"
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", meta["id"]), (
            f"{profile.name}/{path.name}: id must use lowercase kebab-case"
        )
        assert meta["impact"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, f"{profile.name}/{path.name}: bad impact"
        for key in ("tags", "selection_hints", "aliases"):
            values = meta.get(key, [])
            assert isinstance(values, list), f"{profile.name}/{path.name}: {key} must be a list"
            assert all(isinstance(v, str) and v for v in values), f"{profile.name}/{path.name}: bad {key}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_frontmatter_field_order_is_stable(profile):
    """Stable field order keeps knowledge diffs readable across profiles."""
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        expected = tuple(k for k in _VULNERABILITY_FIELD_ORDER if k in meta)
        assert tuple(meta) == expected, f"{profile.name}/{path.name}: field order should be {expected}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_selection_hints_are_unique(profile):
    """Case-folded hints should not double weight one class."""
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        hints = [str(t).lower() for t in meta["selection_hints"]]
        assert len(hints) == len(set(hints)), f"{profile.name}/{path.name}: duplicate selection hints"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_selection_hints_avoid_known_low_signal_literals(profile):
    """Hints should route knowledge by sinks and protocols, not common syntax."""
    deny = {h.lower() for h in _LOW_SIGNAL_SELECTION_HINTS}
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        hints = {str(t).lower() for t in meta["selection_hints"]}
        assert not (hints & deny), f"{profile.name}/{path.name}: low signal hints {sorted(hints & deny)}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_aliases_are_optional_and_canonical(profile):
    """Alias variants must not collide before category canonicalization."""
    docs = list(iter_md_docs(profile.paths.vulnerabilities_dir))
    canonical_ids = {meta["id"] for _path, meta, _body in docs}
    seen: dict[str, str] = {}
    for path, meta, _body in docs:
        cid = meta["id"]
        for alias in meta.get("aliases", []):
            norm = alias.strip().lower().replace("_", "-").replace(" ", "-")
            assert norm != cid, f"{profile.name}/{path.name}: alias repeats the canonical id"
            assert norm not in canonical_ids, f"{profile.name}/{path.name}: alias collides with class id {norm}"
            assert norm not in seen, f"{profile.name}/{path.name}: alias also owned by {seen[norm]}"
            seen[norm] = cid


_EVM_NO_SWC = {"accounting-precision", "oracle-price-manipulation", "weird-erc20"}


def _class_tags(profile):
    for path, meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir):
        yield path.name[:-3], [str(t) for t in (meta.get("tags") or [])]


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_tags_lead_with_registry_codes(profile):
    """Each class tags taxonomies before free form routing labels."""
    rows = list(_class_tags(profile))
    assert rows, f"{profile.name} has no vulnerability classes"
    for cid, tags in rows:
        assert tags, f"{profile.name}/{cid} has no tags"
        seen_keyword = False
        for t in tags:
            if not t.startswith(("swc-", "cwe-", "owasp-")):
                seen_keyword = True
            elif seen_keyword:
                pytest.fail(f"{profile.name}/{cid}: code {t!r} after a keyword, tags={tags}")


def test_every_web_class_tags_a_cwe_and_an_owasp():
    """Web knowledge anchors on the CWE and OWASP taxonomies, so every class carries both."""
    for cid, tags in _class_tags(WEB_PROFILE):
        assert any(t.startswith("cwe-") for t in tags), f"web/{cid} has no cwe tag: {tags}"
        assert any(t.startswith("owasp-") for t in tags), f"web/{cid} has no owasp tag: {tags}"


def test_every_evm_class_tags_swc_unless_post_swc_defi():
    for cid, tags in _class_tags(EVM_PROFILE):
        has_swc = any(t.startswith("swc-") for t in tags)
        if cid in _EVM_NO_SWC:
            assert not has_swc, f"evm/{cid} now has an swc id, drop it from the no-swc allowlist"
            assert tags, f"evm/{cid} has no tags at all"
        else:
            assert has_swc, f"evm/{cid} has no swc tag and is not an allowed exception: {tags}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_every_class_carries_a_code_example(profile):
    """Model guidance must include concrete code rather than prose alone."""
    for path, _meta, body in iter_md_docs(profile.paths.vulnerabilities_dir):
        assert "```" in body, f"{profile.name}/{path.name[:-3]} has no fenced code example"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_vulnerability_bodies_follow_the_document_contract(profile):
    """Class bodies keep their title, safe boundary, and fenced example contract."""
    supported_languages = {
        "web": {"go", "javascript", "python", "typescript"},
        "evm": {"solidity"},
    }
    for path, meta, body in iter_md_docs(profile.paths.vulnerabilities_dir):
        headings = re.findall(r"^# (.+)$", body, re.MULTILINE)
        assert headings == [meta["title"]], f"{profile.name}/{path.name}: H1 must match title"
        safe_boundaries = re.findall(r"^## Not a Finding$", body, re.MULTILINE)
        assert len(safe_boundaries) == 1, f"{profile.name}/{path.name}: safe boundary required"
        fence_lines = re.findall(r"^```(.*)$", body, re.MULTILINE)
        opening_fences = fence_lines[::2]
        closing_fences = fence_lines[1::2]
        assert len(fence_lines) % 2 == 0, f"{profile.name}/{path.name}: unbalanced code fences"
        assert all(language.strip() for language in opening_fences), f"{profile.name}/{path.name}: untagged fence"
        assert not any(language.strip() for language in closing_fences), f"{profile.name}/{path.name}: bad close fence"
        unsupported = set(opening_fences) - supported_languages[profile.name]
        assert not unsupported, f"{profile.name}/{path.name}: unsupported fence languages {sorted(unsupported)}"


@pytest.mark.parametrize("profile", [WEB_PROFILE, EVM_PROFILE])
def test_knowledge_index_matches_each_profile_catalog(profile):
    """Each documentation index lists every class id once and no unknown class."""
    expected = {path.stem for path, _meta, _body in iter_md_docs(profile.paths.vulnerabilities_dir)}
    text = profile.paths.knowledge_index.read_text(encoding="utf-8")
    listed = re.findall(r"^- `([a-z0-9-]+)`", text, re.MULTILINE)
    assert len(listed) == len(set(listed)), f"{profile.name}: duplicate class in index"
    assert set(listed) == expected, f"{profile.name}: index differs from class files"
    assert not text.startswith("---\n"), f"{profile.name}: documentation index must not be loadable"


def test_evm_facts_backend_fails_loud_without_slither(monkeypatch):
    """Missing static analysis cannot be reported as complete EVM grounding."""
    from cyberjury.profiles.evm.facts.backend import SlitherFacts
    from cyberjury.review.facts import BackendUnavailable, FactsBackend

    backend = SlitherFacts()
    assert isinstance(backend, FactsBackend)
    monkeypatch.setattr(backend, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        backend.extract(".")


def test_evm_poc_backend_fails_loud_without_forge(monkeypatch):
    """Missing Foundry cannot be reported as a completed EVM reproduction."""
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider
    from cyberjury.review.facts import BackendUnavailable

    poc = ForgePoC(provider=MockProvider(default="x"), model="m")
    monkeypatch.setattr(poc, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        poc.reproduce(title="x", analysis="", symbol="", file="A.sol", line=1, root=".")


def test_forge_poc_repairs_its_test_after_a_failure(monkeypatch, tmp_path):
    """A failed first attempt must feed diagnostics into the bounded repair attempt."""
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
    """Generation must remain separate from operator controlled execution."""
    from cyberjury.profiles.evm.poc import ForgePoC
    from cyberjury.providers.mock import MockProvider

    (tmp_path / "A.sol").write_text("contract A {}")
    poc = ForgePoC(provider=MockProvider(default="contract PoC {}"), model="m")
    art = poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))
    assert art.ext == "t.sol"
    assert "PoC" in art.source
    assert art.run_hint


def test_forge_poc_generate_needs_a_provider(tmp_path):
    """Generation without a configured model must fail before creating an artifact."""
    from cyberjury.profiles.evm.poc import ForgePoC

    poc = ForgePoC()
    with pytest.raises(ValueError, match="needs a provider"):
        poc.generate(title="t", analysis="a", symbol="s", file="A.sol", line=1, root=str(tmp_path))


def test_forge_poc_execute_skips_and_notes_when_forge_is_absent(monkeypatch, tmp_path):
    """Unavailable execution must remain explicit in the reproduction result."""
    from cyberjury.profiles.evm.poc import ForgePoC

    poc = ForgePoC()
    monkeypatch.setattr(poc, "available", lambda: False)
    res = poc.execute(source="contract PoC {}", root=str(tmp_path))
    assert res.ran is False
    assert res.ok is False
    assert "not installed" in res.detail


def test_web_profile_binds_a_poc_backend():
    """The Web profile must expose its safe generation-only reproduction seam."""
    assert WEB_PROFILE.poc_backend is not None


def test_web_poc_writes_a_python_script_and_never_runs_it(tmp_path):
    """Web reproduction must generate inspectable code without executing target actions."""
    from cyberjury.profiles.web.poc import WebPoC
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
    """Web reproduction without a configured model must fail before writing code."""
    from cyberjury.profiles.web.poc import WebPoC

    with pytest.raises(ValueError, match="needs a provider"):
        WebPoC().generate(title="t", analysis="a", symbol="s", file="v.py", line=1, root=str(tmp_path))


def test_web_poc_flags_a_script_that_does_not_parse(tmp_path):
    """Invalid generated Python must be surfaced in the artifact note."""
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
    """Reproduction prompts need reachable endpoint and source evidence rather than guesses."""
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
    """Ungrounded prompts must not claim that source evidence was supplied."""
    from cyberjury.profiles.web.poc import _prompt

    grounded = _prompt(
        title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="POST /x", source="def h(): ..."
    )
    bare = _prompt(title="t", analysis="a", symbol="s", file="v.py", line=1, endpoint="", source="")
    assert "do not guess" in grounded
    assert "do not guess" not in bare


def test_web_poc_marks_a_truncated_handler_source(tmp_path):
    """Source truncation must remain visible to the model and operator."""
    from cyberjury.profiles.web.poc import _MAX_HANDLER_SOURCE_CHARS, _read_source

    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * _MAX_HANDLER_SOURCE_CHARS, encoding="utf-8")
    out = _read_source(big)
    assert "source truncated" in out
    assert len(out) < _MAX_HANDLER_SOURCE_CHARS + 100


def test_forge_poc_exposes_one_install_hint_source():
    """Availability errors and backend metadata must share one Foundry install source."""
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
    """A successful reproduction requires a real local compile and test execution."""
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
    """Grounding must preserve state, call, write, and reentrancy facts from real Solidity."""
    from shutil import which

    from cyberjury.profiles.evm.facts.backend import SlitherFacts
    from cyberjury.review.facts import BackendUnavailable

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
    withdraw_unit = next(u for u in facts.data["unit_specs"] if "withdraw" in u["name"])
    body = "".join(text[s:e] for _f, s, e in withdraw_unit["fragments"])
    assert "function withdraw" in body
    assert "_check" in body


def test_by_file_groups_contract_facts_by_source_path():
    """Per-file prompt context must not mix contracts from different source files."""
    from cyberjury.profiles.evm.facts.backend import _by_file

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
    """EVM call facts must satisfy the graph contract consumed by shared unit slicing."""
    from cyberjury.profiles.evm.facts.backend import _callgraph

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


def test_fact_unit_specs_anchor_on_risk_functions_with_neighborhood():
    """Risk units must include the reachable neighborhood without unrelated functions."""
    from cyberjury.profiles.evm.facts.backend import _RISK_FLAGS
    from cyberjury.review.facts import pack_unit_specs

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
    units = pack_unit_specs(contracts, focus_flags=_RISK_FLAGS, max_source_chars=16_000)
    assert len(units) == 1
    u = units[0]
    assert "_cleanupLoan" in u["name"]
    assert u["files"] == ["src/Vault.sol"]
    starts = [f[1] for f in u["fragments"]]
    assert starts == sorted(starts) == [100, 300, 420]
    assert all(f[0] == "src/Vault.sol" for f in u["fragments"])
    assert not any(f[1] == 0 for f in u["fragments"])


def test_fact_unit_specs_skip_no_range_and_respect_the_char_cap():
    """Missing ranges and oversized callees must not break bounded unit construction."""
    from cyberjury.profiles.evm.facts.backend import _RISK_FLAGS, _TARGET_FACT_UNIT_SOURCE_CHARS
    from cyberjury.review.facts import pack_unit_specs

    contracts = {
        "C": {
            "file": "a.sol",
            "state": [],
            "functions": {
                "f()": _fn([0, 50], external_call=True, calls=["big()", "noRange()"]),
                "big()": _fn([50, 50 + _TARGET_FACT_UNIT_SOURCE_CHARS + 100]),
                "noRange()": _fn(None),
            },
        }
    }
    units = pack_unit_specs(
        contracts,
        focus_flags=_RISK_FLAGS,
        max_source_chars=_TARGET_FACT_UNIT_SOURCE_CHARS,
    )
    assert len(units) == 1
    frags = units[0]["fragments"]
    assert [f[1] for f in frags] == [0]


def test_rel_file_relativizes_to_root_and_falls_back(tmp_path):
    """Fact locations must stay stable for in-root, external, and single-file targets."""
    from cyberjury.profiles.evm.facts.backend import _rel_file

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
    """Nested scopes need the nearest repository build configuration for complete analysis."""
    from cyberjury.profiles.evm.facts.backend import resolve_compile_root

    repository = tmp_path / "proj"
    (repository / "contracts").mkdir(parents=True)
    (repository / ".git").mkdir()
    (repository / "hardhat.config.js").write_text("module.exports = {}")
    assert resolve_compile_root((repository / "contracts").resolve()) == repository.resolve()


def test_compile_root_stays_put_when_the_scope_is_already_the_framework_root(tmp_path):
    """A configured repository root must not be widened beyond itself."""
    from cyberjury.profiles.evm.facts.backend import resolve_compile_root

    repository = tmp_path / "proj"
    repository.mkdir()
    (repository / ".git").mkdir()
    (repository / "foundry.toml").write_text("[profile.default]")
    assert resolve_compile_root(repository.resolve()) == repository.resolve()


def test_compile_root_never_leaves_the_repository(tmp_path):
    """External build files must not expand analysis beyond the selected repository."""
    from cyberjury.profiles.evm.facts.backend import resolve_compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    repository = tmp_path / "proj"
    (repository / "src").mkdir(parents=True)
    (repository / ".git").mkdir()
    scope = (repository / "src").resolve()
    assert resolve_compile_root(scope) == scope


def test_compile_root_does_not_widen_without_a_repository(tmp_path):
    """Loose source directories must not inherit unrelated parent build configuration."""
    from cyberjury.profiles.evm.facts.backend import resolve_compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    scope = (tmp_path / "sources").resolve()
    scope.mkdir()
    assert resolve_compile_root(scope) == scope


def test_single_file_explorer_tree_uses_the_source_file_as_the_slither_target(tmp_path):
    """An unconfigured explorer export must compile its only Solidity source directly."""
    from cyberjury.profiles.evm.facts.backend import _slither_target

    source = tmp_path / "Token.sol"
    source.write_text("contract Token {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == source.resolve()


def test_configured_single_file_tree_uses_the_directory_as_the_slither_target(tmp_path):
    """Framework configuration must take precedence over single-file compilation."""
    from cyberjury.profiles.evm.facts.backend import _slither_target

    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_multi_file_explorer_tree_uses_the_directory_as_the_slither_target(tmp_path):
    """Multiple Solidity sources require directory-level dependency resolution."""
    from cyberjury.profiles.evm.facts.backend import _slither_target

    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    (tmp_path / "Ownable.sol").write_text("contract Ownable {}\n")
    assert _slither_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_in_scope_keeps_the_review_tree_and_drops_the_rest(tmp_path):
    """Widened compilation must expose facts only for the requested review scope."""
    from cyberjury.profiles.evm.facts.backend import _in_scope

    scope = (tmp_path / "contracts").resolve()
    scope.mkdir()
    assert _in_scope(_fake_contract(str(scope / "Token.sol")), scope) is True
    assert _in_scope(_fake_contract(str(tmp_path / "test" / "Token.t.sol")), scope) is False
    assert _in_scope(_fake_contract(""), scope) is True


def test_evm_fact_source_filter_uses_detection_noise_rules(tmp_path):
    """Fact units must not reintroduce dependency paths skipped by the profile."""
    from cyberjury.detection import Detection
    from cyberjury.profiles.evm.facts.backend import _reviewable_contract

    root = tmp_path.resolve()
    detection = Detection(
        skip_dirs=frozenset({"cache"}),
        skip_root_dirs=frozenset({"lib", "dependencies"}),
        source_extensions=frozenset({".sol"}),
        config_extensions=frozenset(),
        manifests=(),
        test_dirs=frozenset({"test"}),
        test_name_patterns=("*.t.sol",),
        doc_extensions=frozenset(),
        lockfiles=frozenset(),
    )

    assert _reviewable_contract(_fake_contract(str(root / "src" / "Vault.sol")), root, detection)
    assert not _reviewable_contract(_fake_contract(str(root / "lib" / "Token.sol")), root, detection)
    assert _reviewable_contract(_fake_contract(str(root / "src" / "lib" / "Math.sol")), root, detection)
    assert not _reviewable_contract(_fake_contract(str(root / "test" / "Vault.t.sol")), root, detection)
    outside_root = tmp_path.parent / f"{tmp_path.name}-external" / "Token.sol"
    assert not _reviewable_contract(_fake_contract(str(outside_root)), root, detection)
    assert _reviewable_contract(_fake_contract(""), root, detection)


def test_a_widened_compile_that_covers_no_scoped_contract_fails_loud(tmp_path):
    """A successful build with zero in-scope contracts is an incomplete review, not clean."""
    from shutil import which

    from cyberjury.profiles.evm.facts.backend import SlitherFacts
    from cyberjury.review.facts import BackendUnavailable

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


def test_importing_the_evm_profile_does_not_pull_the_heavy_tools():
    """Profile discovery must stay cheap and isolated from optional runtime toolchains."""
    import subprocess
    import sys

    code = (
        "import cyberjury.profiles.evm, sys\n"
        "assert 'slither' not in sys.modules\n"
        "assert 'cyberjury.profiles.evm.poc' not in sys.modules\n"
        "assert 'cyberjury.review.facts' in sys.modules\n"
        "assert not [m for m in sys.modules if 'profiles.web' in m]\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_both_profiles_bind_a_facts_backend():
    """Every shipped profile must ground review units through the common backend contract."""
    from cyberjury.review.facts import FactsBackend

    assert isinstance(EVM_PROFILE.facts_backend, FactsBackend)
    assert isinstance(WEB_PROFILE.facts_backend, FactsBackend)


def test_each_backend_names_its_own_toolchain_in_its_install_hint():
    """Failure guidance must identify the missing profile-specific toolchain precisely."""
    assert "solc" in EVM_PROFILE.facts_backend.install_hint
    assert "tree-sitter" in WEB_PROFILE.facts_backend.install_hint
    assert "solc" not in WEB_PROFILE.facts_backend.install_hint
