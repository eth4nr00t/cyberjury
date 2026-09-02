"""Profile registration and automatic detection resolve one available profile."""

import pytest

from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.registry import detect_profile, get_profile, resolve_profile, resolve_profile_binding
from cyberjury.profiles.web import WEB_PROFILE


def test_get_profile_returns_registered_and_fails_loud_on_unknown():
    assert get_profile("web") is WEB_PROFILE
    assert get_profile("evm") is EVM_PROFILE
    with pytest.raises(ValueError, match="unknown or unavailable review profile"):
        get_profile("nonsense")


def test_detect_profile_names_evm_for_any_solidity_source():
    assert detect_profile(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_profile(["Vault.sol", "Token.sol"]) == "evm"
    assert detect_profile(["Vault.sol", "README.md", "foundry.toml", "explorer-raw.json"]) == "evm"
    with pytest.raises(ValueError, match="does not match any"):
        detect_profile([])


def test_detect_profile_fails_loud_on_mixed_source_profiles():
    with pytest.raises(ValueError, match=r"multiple review profiles.*deploy\.py.*Vault\.sol"):
        detect_profile(["Vault.sol", "deploy.py"])


def test_detect_profile_uses_an_exclusive_manifest_to_resolve_tooling_files():
    assert detect_profile(["contracts/Vault.sol", "scripts/deploy.ts", "hardhat.config.ts", "package.json"]) == "evm"
    assert detect_profile(["app.py", "contracts/Fixture.sol", "pyproject.toml"]) == "web"


def test_detect_profile_ignores_extension_signals_under_profile_noise_directories():
    assert detect_profile(["app.py", "node_modules/dependency/Token.sol"]) == "web"


def test_resolve_profile_auto_detects_then_looks_up():
    assert resolve_profile("auto", ["a.py"]).name == WEB_PROFILE.name
    assert resolve_profile("web", []).name == WEB_PROFILE.name
    assert resolve_profile("auto", ["Vault.sol", "Token.sol"]).name == EVM_PROFILE.name
    assert resolve_profile("evm", []).name == EVM_PROFILE.name


def test_resolve_profile_binding_returns_the_runtime_profile_and_content_receipt():
    resolution = resolve_profile_binding("auto", ["contracts/Vault.sol"])

    assert resolution.profile.name == EVM_PROFILE.name
    assert resolution.profile.content_root == EVM_PROFILE.content_root
    assert resolution.binding.name == "evm"
    assert resolution.binding.content_snapshot_id == resolution.content_snapshot.snapshot_id


def test_evm_profile_resolves_shipped_content_and_strategy():
    paths = EVM_PROFILE.paths
    assert (paths.languages_dir / "solidity.md").is_file()
    assert (paths.vulnerabilities_dir / "reentrancy.md").is_file()
    assert paths.detection_file.is_file()
    assert paths.methodology_file.is_file()
    assert "reentrancy" in EVM_PROFILE.diff_focus.lower()
    assert EVM_PROFILE.dedup_by_file is True
    assert WEB_PROFILE.dedup_by_file is False


def test_both_profiles_bind_a_facts_backend():
    from cyberjury.review.facts import FactsBackend

    assert isinstance(EVM_PROFILE.facts_backend, FactsBackend)
    assert isinstance(WEB_PROFILE.facts_backend, FactsBackend)


def test_each_backend_names_its_own_toolchain_in_its_install_hint():
    assert "solc" in EVM_PROFILE.facts_backend.install_hint
    assert "tree-sitter" in WEB_PROFILE.facts_backend.install_hint
    assert "solc" not in WEB_PROFILE.facts_backend.install_hint
