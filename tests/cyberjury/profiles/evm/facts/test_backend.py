"""EVM facts select a bounded compile target and fail loud without Slither."""

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
