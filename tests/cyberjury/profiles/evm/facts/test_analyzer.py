"""EVM analysis converts Slither objects into source qualified records."""


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

    analyzed = normalize_analysis((contract("src/two/Vault.sol"), contract("src/one/Vault.sol")), object)

    assert [item.identity for item in analyzed.contracts] == [
        "/repo/src/one/Vault.sol::Vault",
        "/repo/src/two/Vault.sol::Vault",
    ]
