"""Test the EVM facts analyzer, resolver, graph, and backend pipeline."""

import pytest


def test_evm_facts_backend_fails_loud_without_slither(monkeypatch):
    from cyberjury.profiles.evm.facts.backend import SlitherFacts
    from cyberjury.review.facts import BackendUnavailable, FactsBackend

    backend = SlitherFacts()
    assert isinstance(backend, FactsBackend)
    monkeypatch.setattr(backend, "available", lambda: False)
    with pytest.raises(BackendUnavailable):
        backend.extract(".")


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


def _analyzed_source(*, absolute="", short="", used="", start=None, length=None):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedSource

    return AnalyzedSource(absolute=absolute, short=short, used=used, start=start, length=length)


def _analyzed_function(*, key=1, name="function()", source=None, calls=()):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedFunction

    return AnalyzedFunction(
        key=key,
        name=name,
        visibility="internal",
        modifiers=(),
        reads=(),
        writes=(),
        calls=calls,
        external_call=False,
        sends_eth=False,
        can_reenter=False,
        source=source or _analyzed_source(),
    )


def _resolved_function(name, span, **flags):
    from cyberjury.profiles.evm.facts.resolver import ResolvedFunction

    values = {
        "visibility": "internal",
        "modifiers": (),
        "reads": (),
        "writes": (),
        "calls": (),
        "external_call": False,
        "sends_eth": False,
        "can_reenter": False,
    }
    values.update(flags)
    return ResolvedFunction(name=name, span=span, **values)


def _resolved_contract(name, file, *, state=(), functions=()):
    from cyberjury.profiles.evm.facts.resolver import ResolvedContract

    identity = f"{file}::{name}" if file else name
    return ResolvedContract(identity=identity, name=name, file=file, state=state, functions=functions)


def test_evm_analyzer_normalizes_slither_objects_and_exact_call_endpoints():
    from cyberjury.profiles.evm.facts.analyzer import normalize_analysis

    class InternalCall:
        def __init__(self, function):
            self.function = function

    class Function:
        def __init__(self, name):
            self.name = name
            self.full_name = f"{name}()"
            self.visibility = "external"
            self.modifiers = []
            self.state_variables_read = []
            self.state_variables_written = []
            self.internal_calls = []
            self.high_level_calls = []
            self.low_level_calls = []
            self.source_mapping = None

        def can_send_eth(self):
            return False

        def can_reenter(self):
            return False

    target = Function("target")
    entry = Function("entry")
    entry.internal_calls = [InternalCall(target)]
    contract = type(
        "Contract",
        (),
        {
            "name": "Vault",
            "is_interface": False,
            "source_mapping": None,
            "state_variables": [],
            "functions_declared": [entry, target],
        },
    )()

    analyzed = normalize_analysis((contract,), InternalCall)

    normalized_entry = analyzed.contracts[0].functions[0]
    assert analyzed.contracts[0].identity == "Vault"
    assert normalized_entry.name == "entry()"
    assert normalized_entry.calls[0].target_key == id(target)
    assert normalized_entry.calls[0].target_name == "target()"


def test_evm_analyzer_qualifies_same_name_contracts_with_their_sources():
    from cyberjury.profiles.evm.facts.analyzer import normalize_analysis

    def contract(short):
        filename = type("Filename", (), {"absolute": f"/repo/{short}", "short": short, "used": short})()
        source_mapping = type("SourceMapping", (), {"filename": filename, "start": 0, "length": 1})()
        return type(
            "Contract",
            (),
            {
                "name": "Vault",
                "is_interface": False,
                "source_mapping": source_mapping,
                "state_variables": [],
                "functions_declared": [],
            },
        )()

    analyzed = normalize_analysis((contract("src/one/Vault.sol"), contract("src/two/Vault.sol")), object)

    assert [item.identity for item in analyzed.contracts] == [
        "/repo/src/one/Vault.sol::Vault",
        "/repo/src/two/Vault.sol::Vault",
    ]


def test_slither_facts_extract_grounds_a_real_contract(tmp_path):
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
    vault = facts.data["contracts"]["Vault.sol::Vault"]
    assert vault["name"] == "Vault"
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


def test_slither_ranges_slice_normalized_utf8_and_crlf_source(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import function_range
    from cyberjury.review.context import definition_evidence
    from cyberjury.review.facts import DefinitionFragment, DefinitionUnitPlan

    raw_prefix = "// café\r\ncontract Vault {\r\n    "
    raw_body = "function withdraw() external {\r\n        transfer();\r\n    }"
    source = f"{raw_prefix}{raw_body}\r\n}}\r\n"
    path = tmp_path / "Vault.sol"
    path.write_bytes(source.encode("utf-8"))
    start = len(raw_prefix.encode("utf-8"))
    length = len(raw_body.encode("utf-8"))
    function = _analyzed_function(source=_analyzed_source(absolute=str(path), start=start, length=length))

    span = function_range(function, {})
    fragment = DefinitionFragment("Vault.sol", "withdraw()", span[0], span[1])
    plan = DefinitionUnitPlan(seeds=(fragment,))
    evidence = definition_evidence(tmp_path, plan, include_seeds=True)

    assert len(evidence) == 1
    assert "function withdraw() external" in evidence[0].text
    assert "transfer();" in evidence[0].text
    assert "}" in evidence[0].text


def test_by_file_groups_contract_facts_by_source_path():
    from cyberjury.profiles.evm.facts.graph import render_by_file

    contracts = (
        _resolved_contract(
            "Vault",
            "src/Vault.sol",
            functions=(_resolved_function("withdraw()", None, external_call=True, can_reenter=True),),
        ),
        _resolved_contract("Token", "src/Token.sol"),
        _resolved_contract("Lib", ""),
    )
    by = render_by_file(contracts)
    assert set(by) == {"src/Vault.sol", "src/Token.sol"}
    assert "contract Vault" in by["src/Vault.sol"]
    assert "reenter" in by["src/Vault.sol"]
    assert "contract Token" in by["src/Token.sol"]


def test_contract_serialization_and_unit_specs_keep_same_names_from_different_files():
    from cyberjury.profiles.evm.facts.graph import build_graph, facts_from_graph
    from cyberjury.profiles.evm.facts.resolver import ResolvedProject

    contracts = (
        _resolved_contract(
            "Vault",
            "src/one/Vault.sol",
            functions=(_resolved_function("withdraw()", (10, 40), external_call=True),),
        ),
        _resolved_contract(
            "Vault",
            "src/two/Vault.sol",
            functions=(_resolved_function("withdraw()", (50, 90), external_call=True),),
        ),
    )

    facts = facts_from_graph(build_graph(ResolvedProject(contracts=contracts, dependencies=())))

    assert set(facts.data["contracts"]) == {
        "src/one/Vault.sol::Vault",
        "src/two/Vault.sol::Vault",
    }
    assert {record["name"] for record in facts.data["contracts"].values()} == {"Vault"}
    assert {tuple(spec["files"]) for spec in facts.data["unit_specs"]} == {
        ("src/one/Vault.sol",),
        ("src/two/Vault.sol",),
    }


def test_contract_serialization_rejects_an_identity_collision():
    from cyberjury.profiles.evm.facts.graph import contracts_data
    from cyberjury.review.facts import BackendUnavailable

    contract = _resolved_contract("Vault", "src/Vault.sol")

    with pytest.raises(BackendUnavailable, match="share identity"):
        contracts_data((contract, contract))


def test_evm_facts_callgraph_uses_the_shared_definition_graph_shape():
    from cyberjury.profiles.evm.facts.graph import callgraph_data

    contracts = (
        _resolved_contract(
            "Vault",
            "src/Vault.sol",
            functions=(
                _resolved_function("pause()", (5, 10)),
                _resolved_function(
                    "withdraw(uint256)",
                    (100, 300),
                    calls=("_check(uint256)", "_check(address)"),
                ),
                _resolved_function("_check(uint256)", (20, 80)),
            ),
        ),
        _resolved_contract(
            "Admin",
            "src/Vault.sol",
            functions=(_resolved_function("pause()", (320, 370)),),
        ),
        _resolved_contract("Missing", "", functions=(_resolved_function("ghost()", (0, 1)),)),
    )
    graph = callgraph_data(contracts)
    assert set(graph) == {"src/Vault.sol"}
    assert graph["src/Vault.sol"]["withdraw(uint256)"] == [
        {"range": [100, 300], "calls": ["_check(uint256)", "_check(address)"]}
    ]
    assert graph["src/Vault.sol"]["_check(uint256)"] == [{"range": [20, 80], "calls": []}]
    assert graph["src/Vault.sol"]["pause()"] == [
        {"range": [5, 10], "calls": []},
        {"range": [320, 370], "calls": []},
    ]


def test_evm_dependencies_keep_slithers_exact_same_name_target():
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedCall
    from cyberjury.profiles.evm.facts.resolver import resolve_dependencies
    from cyberjury.review.facts import DefinitionDependency, DefinitionFragment

    withdraw = _analyzed_function(
        key=1,
        name="withdraw()",
        calls=(AnalyzedCall(target_key=3, target_name="transfer()"),),
    )
    source = DefinitionFragment("Vault.sol", "withdraw()", 0, 40)
    targets = {
        2: DefinitionFragment("Vault.sol", "transfer()", 50, 80),
        3: DefinitionFragment("Token.sol", "transfer()", 10, 30),
        4: DefinitionFragment("OtherToken.sol", "transfer()", 10, 30),
    }

    dependencies = resolve_dependencies([(withdraw, source)], targets)

    assert dependencies == (
        DefinitionDependency("Vault.sol", DefinitionFragment("Token.sol", "transfer()", 10, 30), source),
    )


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
    from cyberjury.profiles.evm.facts.graph import RISK_FLAGS
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
    units = pack_unit_specs(contracts, focus_flags=RISK_FLAGS, max_source_chars=16_000)
    assert len(units) == 1
    u = units[0]
    assert "_cleanupLoan" in u["name"]
    assert u["files"] == ["src/Vault.sol"]
    starts = [f[1] for f in u["fragments"]]
    assert starts == sorted(starts) == [100, 300, 420]
    assert all(f[0] == "src/Vault.sol" for f in u["fragments"])
    assert not any(f[1] == 0 for f in u["fragments"])


def test_fact_unit_specs_skip_no_range_and_respect_the_char_cap():
    from cyberjury.profiles.evm.facts.graph import RISK_FLAGS, TARGET_FACT_UNIT_SOURCE_CHARS
    from cyberjury.review.facts import pack_unit_specs

    contracts = {
        "C": {
            "file": "a.sol",
            "state": [],
            "functions": {
                "f()": _fn([0, 50], external_call=True, calls=["big()", "noRange()"]),
                "big()": _fn([50, 50 + TARGET_FACT_UNIT_SOURCE_CHARS + 100]),
                "noRange()": _fn(None),
            },
        }
    }
    units = pack_unit_specs(
        contracts,
        focus_flags=RISK_FLAGS,
        max_source_chars=TARGET_FACT_UNIT_SOURCE_CHARS,
    )
    assert len(units) == 1
    frags = units[0]["fragments"]
    assert [f[1] for f in frags] == [0]


def test_rel_file_relativizes_to_root_and_falls_back(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import relative_file

    root = tmp_path.resolve()
    assert relative_file(_analyzed_source(absolute=str(root / "src" / "Vault.sol")), root) == "src/Vault.sol"
    assert relative_file(_analyzed_source(absolute="/elsewhere/Ownable.sol"), root) == "Ownable.sol"
    assert relative_file(_analyzed_source(absolute=str(root / "Vault.sol")), root / "Vault.sol") == "Vault.sol"
    assert relative_file(_analyzed_source(), root) == ""


def _fake_contract(absolute: str):
    from cyberjury.profiles.evm.facts.analyzer import AnalyzedContract

    return AnalyzedContract(
        identity=f"{absolute}::Contract" if absolute else "Contract",
        name="Contract",
        is_interface=False,
        source=_analyzed_source(absolute=absolute),
        state=(),
        functions=(),
    )


def test_compile_root_widens_to_the_framework_config(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import resolve_compile_root

    repository = tmp_path / "proj"
    (repository / "contracts").mkdir(parents=True)
    (repository / ".git").mkdir()
    (repository / "hardhat.config.js").write_text("module.exports = {}")
    assert resolve_compile_root((repository / "contracts").resolve()) == repository.resolve()


def test_compile_root_stays_put_when_the_scope_is_already_the_framework_root(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import resolve_compile_root

    repository = tmp_path / "proj"
    repository.mkdir()
    (repository / ".git").mkdir()
    (repository / "foundry.toml").write_text("[profile.default]")
    assert resolve_compile_root(repository.resolve()) == repository.resolve()


def test_compile_root_never_leaves_the_repository(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import resolve_compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    repository = tmp_path / "proj"
    (repository / "src").mkdir(parents=True)
    (repository / ".git").mkdir()
    scope = (repository / "src").resolve()
    assert resolve_compile_root(scope) == scope


def test_compile_root_does_not_widen_without_a_repository(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import resolve_compile_root

    (tmp_path / "foundry.toml").write_text("[profile.default]")
    scope = (tmp_path / "sources").resolve()
    scope.mkdir()
    assert resolve_compile_root(scope) == scope


def test_single_file_explorer_tree_uses_the_source_file_as_the_slither_target(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import analyzer_target

    source = tmp_path / "Token.sol"
    source.write_text("contract Token {}\n")
    assert analyzer_target(tmp_path.resolve(), tmp_path.resolve()) == source.resolve()


def test_configured_single_file_tree_uses_the_directory_as_the_slither_target(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import analyzer_target

    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    assert analyzer_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_multi_file_explorer_tree_uses_the_directory_as_the_slither_target(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import analyzer_target

    (tmp_path / "Token.sol").write_text("contract Token {}\n")
    (tmp_path / "Ownable.sol").write_text("contract Ownable {}\n")
    assert analyzer_target(tmp_path.resolve(), tmp_path.resolve()) == tmp_path.resolve()


def test_in_scope_keeps_the_review_tree_and_drops_the_rest(tmp_path):
    from cyberjury.profiles.evm.facts.resolver import in_scope

    scope = (tmp_path / "contracts").resolve()
    scope.mkdir()
    assert in_scope(_analyzed_source(absolute=str(scope / "Token.sol")), scope) is True
    assert in_scope(_analyzed_source(absolute=str(tmp_path / "test" / "Token.t.sol")), scope) is False
    assert in_scope(_analyzed_source(), scope) is True


def test_evm_fact_source_filter_uses_detection_noise_rules(tmp_path):
    from cyberjury.detection import Detection
    from cyberjury.profiles.evm.facts.resolver import reviewable_contract

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

    assert reviewable_contract(_fake_contract(str(root / "src" / "Vault.sol")), root, detection)
    assert not reviewable_contract(_fake_contract(str(root / "lib" / "Token.sol")), root, detection)
    assert reviewable_contract(_fake_contract(str(root / "src" / "lib" / "Math.sol")), root, detection)
    assert not reviewable_contract(_fake_contract(str(root / "test" / "Vault.t.sol")), root, detection)
    outside_root = tmp_path.parent / f"{tmp_path.name}-external" / "Token.sol"
    assert not reviewable_contract(_fake_contract(str(outside_root)), root, detection)
    assert reviewable_contract(_fake_contract(""), root, detection)


def test_a_widened_compile_that_covers_no_scoped_contract_fails_loud(tmp_path):
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
