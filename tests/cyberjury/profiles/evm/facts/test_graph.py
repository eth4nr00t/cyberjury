"""EVM graph output preserves contract identity, dependencies, and unit bounds."""

import pytest


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
