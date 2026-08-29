"""Profile registration and automatic detection resolve one available profile."""

import pytest

from cyberjury.profiles.evm import EVM_PROFILE
from cyberjury.profiles.registry import detect_profile, get_profile, resolve_profile
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
    assert detect_profile([]) == "web"


def test_detect_profile_fails_loud_on_mixed_source_profiles():
    with pytest.raises(ValueError, match=r"multiple review profiles.*deploy\.py.*Vault\.sol"):
        detect_profile(["Vault.sol", "deploy.py"])


def test_resolve_profile_auto_detects_then_looks_up():
    assert resolve_profile("auto", ["a.py"]) is WEB_PROFILE
    assert resolve_profile("web", []) is WEB_PROFILE
    assert resolve_profile("auto", ["Vault.sol", "Token.sol"]) is EVM_PROFILE
    assert resolve_profile("evm", []) is EVM_PROFILE


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
