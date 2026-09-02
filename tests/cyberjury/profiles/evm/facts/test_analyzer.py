"""EVM analysis converts Slither objects into source qualified records."""

from pathlib import Path
from shutil import which

import pytest


class _Function:
    def __init__(self, name, *, source_mapping=None, parameters=()):
        self.name = name
        self.full_name = f"{name}()"
        self.visibility = "external"
        self.modifiers = []
        self.state_variables_read = []
        self.state_variables_written = []
        self.internal_calls = []
        self.high_level_calls = []
        self.low_level_calls = []
        self.source_mapping = source_mapping
        self.parameters = parameters

    def can_send_eth(self):
        return False

    def can_reenter(self):
        return False


def _source_mapping(path, start=0, length=1, *, absolute_root="/repo"):
    filename = type(
        "Filename",
        (),
        {"absolute": f"{absolute_root}/{path}", "short": path, "used": path},
    )()
    return type("SourceMapping", (), {"filename": filename, "start": start, "length": length})()


def _contract(path, name, functions=()):
    return type(
        "Contract",
        (),
        {
            "name": name,
            "is_interface": False,
            "source_mapping": _source_mapping(path),
            "state_variables": [],
            "functions_declared": list(functions),
            "modifiers_declared": [],
            "immediate_inheritance": [],
        },
    )()


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
    normalized_target = analyzed.contracts[0].functions[1]
    assert analyzed.contracts[0].identity == "Vault"
    assert normalized_entry.name == "entry()"
    assert normalized_entry.calls[0].target_key == normalized_target.key
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

    analyzed = normalize_analysis((contract("src/two/Vault.sol"), contract("src/one/Vault.sol")), object)

    assert [item.identity for item in analyzed.contracts] == [
        "src/one/Vault.sol::Vault",
        "src/two/Vault.sol::Vault",
    ]


def test_evm_analyzer_keys_and_order_do_not_depend_on_slither_enumeration():
    from cyberjury.profiles.evm.facts.analyzer import normalize_analysis

    first_function = _Function("first", source_mapping=_source_mapping("src/A.sol", 20, 10))
    second_function = _Function("second", source_mapping=_source_mapping("src/B.sol", 20, 10))
    first = _contract("src/A.sol", "A", (first_function,))
    second = _contract("src/B.sol", "B", (second_function,))

    forward = normalize_analysis((first, second), object)
    reverse = normalize_analysis((second, first), object)

    assert forward == reverse
    assert [contract.key for contract in forward.contracts] == [1, 2]
    assert [contract.functions[0].key for contract in forward.contracts] == [1, 2]


def test_evm_analyzer_does_not_invent_names_for_unnamed_parameters():
    parameter = type(
        "Parameter",
        (),
        {"name": "", "type": "uint256", "source_mapping": _source_mapping("src/Vault.sol", 30, 7)},
    )()
    function = _Function("load", source_mapping=_source_mapping("src/Vault.sol", 10, 40), parameters=(parameter,))
    contract = _contract("src/Vault.sol", "Vault", (function,))

    from cyberjury.profiles.evm.facts.analyzer import normalize_analysis

    analyzed = normalize_analysis((contract,), object)

    assert analyzed.contracts[0].functions[0].parameters[0].name == ""


def test_evm_analysis_evidence_ignores_temporary_absolute_root_prefixes():
    from cyberjury.profiles.evm.facts.analyzer import analysis_evidence, normalize_analysis

    def project(absolute_root):
        function = _Function(
            "load",
            source_mapping=_source_mapping("src/Vault.sol", 10, 20, absolute_root=absolute_root),
        )
        contract = _contract("src/Vault.sol", "Vault", (function,))
        contract.source_mapping = _source_mapping("src/Vault.sol", absolute_root=absolute_root)
        return normalize_analysis((contract,), object)

    assert analysis_evidence(project("/tmp/first")) == analysis_evidence(project("/tmp/second"))


def test_evm_analysis_evidence_normalizes_temporary_used_and_short_paths():
    from cyberjury.profiles.evm.facts.analyzer import analysis_evidence, normalize_analysis

    def project(absolute_root):
        mapping = _source_mapping("src/Vault.sol", 10, 20, absolute_root=absolute_root)
        mapping.filename.used = f"{absolute_root}/src/Vault.sol"
        mapping.filename.short = f"../../..{absolute_root}/src/Vault.sol"
        function = _Function("load", source_mapping=mapping)
        contract = _contract("src/Vault.sol", "Vault", (function,))
        contract.source_mapping = mapping
        return normalize_analysis((contract,), object)

    first = analysis_evidence(project("/tmp/first"), source_root=Path("/tmp/first"))
    second = analysis_evidence(project("/tmp/second"), source_root=Path("/tmp/second"))

    assert first == second
    assert first["contracts"][0]["source"]["used"] == "src/Vault.sol"
    assert first["contracts"][0]["identity"] == "src/Vault.sol::Vault"


def test_real_slither_analyzer_matches_the_solidity_structure_oracle(tmp_path):
    from cyberjury.profiles.evm.facts.analyzer import analyze, available
    from cyberjury.review.facts import BackendUnavailable

    if not available() or not (which("solc") or which("forge")):
        pytest.skip("Slither and a Solidity compiler are required for the native analyzer oracle")
    compile_input = tmp_path
    if which("solc"):
        source = tmp_path / "Vault.sol"
        compile_input = source
    else:
        (tmp_path / "src").mkdir()
        (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
        source = tmp_path / "src" / "Vault.sol"
    source.write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Base {\n"
        "    uint256 internal total;\n"
        "    modifier onlyPositive(uint256 amount) { require(amount > 0); _; }\n"
        "}\n"
        "contract Vault is Base {\n"
        "    function deposit(uint256 amount) external onlyPositive(amount) { total += amount; }\n"
        "    function _debit(uint256 amount) internal { total -= amount; }\n"
        "    function withdraw(address payable to, uint256 amount) external {\n"
        "        _debit(amount);\n"
        '        to.call{value: amount}("");\n'
        "    }\n"
        "}\n"
    )

    try:
        analyses = [analyze(compile_input) for _ in range(3)]
    except BackendUnavailable:
        pytest.skip("the solc on PATH cannot compile the analyzer oracle")
    assert analyses[0] == analyses[1] == analyses[2]
    analyzed = analyses[0]
    contracts = {contract.name: contract for contract in analyzed.contracts}
    vault = contracts["Vault"]
    functions = {function.name: function for function in vault.functions}
    deposit = functions["deposit(uint256)"]
    debit = functions["_debit(uint256)"]
    withdraw = functions["withdraw(address,uint256)"]

    assert [(base.target_key, base.target_name) for base in vault.bases] == [(contracts["Base"].key, "Base")]
    assert "onlyPositive" in deposit.modifiers
    assert deposit.writes == ("total",)
    assert debit.reads == ("total",)
    assert debit.writes == ("total",)
    assert [parameter.name for parameter in withdraw.parameters] == ["to", "amount"]
    assert "_debit(uint256)" in {call.target_name for call in withdraw.calls}
    assert {call.kind for call in withdraw.callsites} >= {"internal", "low_level"}
    assert withdraw.external_call is True
    raw = source.read_bytes()
    for function in (deposit, debit, withdraw):
        assert function.source.start is not None
        assert function.source.length is not None
        body = raw[function.source.start : function.source.start + function.source.length]
        assert function.name.split("(", 1)[0].encode() in body
