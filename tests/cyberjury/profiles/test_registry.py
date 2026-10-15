"""Profile registration and automatic detection resolve one available profile."""

import pytest

from cyberjury.profiles.registry import detect_profile, get_profile, resolve_profile_binding
from cyberjury.profiles.web import WEB_PROFILE


def test_get_profile_returns_registered_and_fails_loud_on_unknown():
    assert get_profile("web") is WEB_PROFILE
    with pytest.raises(ValueError, match="unknown or unavailable review profile"):
        get_profile("evm")


def test_detect_profile_accepts_any_production_source():
    assert detect_profile(["app.py", "views.py", "go.mod"]) == "web"
    assert detect_profile(["Vault.sol", "Token.sol"]) == "web"
    assert detect_profile(["handler.rb"]) == "web"
    with pytest.raises(ValueError, match="no reviewable source"):
        detect_profile([])


def test_detect_profile_ignores_unsupported_tooling_files():
    assert detect_profile(["app.py", "contracts/Fixture.sol", "pyproject.toml"]) == "web"


def test_detect_profile_ignores_extension_signals_under_profile_noise_directories():
    assert detect_profile(["app.py", "node_modules/dependency/Token.sol"]) == "web"


def test_resolve_profile_auto_detects_then_looks_up():
    assert resolve_profile_binding("auto", ["a.py"]).profile.name == WEB_PROFILE.name
    assert resolve_profile_binding("web", []).profile.name == WEB_PROFILE.name


def test_resolve_profile_binding_returns_the_runtime_profile_and_content_receipt():
    resolution = resolve_profile_binding("auto", ["app.py"])

    assert resolution.profile.name == WEB_PROFILE.name
    assert resolution.profile.content_root == WEB_PROFILE.content_root
    assert resolution.binding.name == "web"
    assert resolution.binding.content_snapshot_id == resolution.content_snapshot.snapshot_id


def test_web_profile_resolves_shipped_content_and_strategy():
    paths = WEB_PROFILE.paths
    assert paths.security_kernel_file.is_file()
    assert paths.detection_file.is_file()
    assert paths.severity_rubric_file.is_file()


def test_web_profile_binds_a_facts_backend():
    from cyberjury.review.facts import FactsBackend

    assert isinstance(WEB_PROFILE.facts_backend, FactsBackend)
