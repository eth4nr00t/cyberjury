"""Detection config data drives source, manifest, noise, and test path classification."""

import pytest

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import available_profiles, resolve_profile


def test_detection_config_loads_with_content():
    d = load_detection()
    assert ".py" in d.source_extensions
    assert ".go" in d.source_extensions
    assert ".yaml" in d.config_extensions
    assert ".py" in d.detection_extensions
    assert ".yaml" in d.detection_extensions
    assert "requirements.txt" in d.manifests
    assert "package.json" in d.manifests
    assert ".venv" in d.skip_dirs
    assert "node_modules" in d.skip_dirs


@pytest.mark.parametrize("profile", available_profiles())
def test_profile_detection_configs_are_valid(profile):
    d = load_detection(resolve_profile(profile).paths.detection_file)
    assert d.source_extensions
    assert d.skip_dirs


def test_detection_config_rejects_unknown_keys(tmp_path):
    path = tmp_path / "detection.yaml"
    path.write_text(_MINIMAL_DETECTION + "source_extension: ['.py']\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown detection keys"):
        load_detection(path)


def test_detection_config_rejects_wrong_field_types(tmp_path):
    path = tmp_path / "detection.yaml"
    path.write_text(
        _MINIMAL_DETECTION.replace("source_extensions: ['.py']", "source_extensions: '.py'"), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="source_extensions"):
        load_detection(path)


def test_detection_config_rejects_missing_core_fields(tmp_path):
    path = tmp_path / "detection.yaml"
    path.write_text(_MINIMAL_DETECTION.replace("lockfiles: []\n", ""), encoding="utf-8")
    with pytest.raises(ValueError, match="lockfiles"):
        load_detection(path)


def test_is_test_path_by_directory_segment():
    d = load_detection()
    assert d.is_test_path("app/tests/views.py")
    assert d.is_test_path("spec/billing.js")
    assert not d.is_test_path("app/views.py")


def test_is_test_path_by_naming_convention_across_ecosystems():
    d = load_detection()
    assert d.is_test_path("app/test_views.py")
    assert d.is_test_path("app/views_test.go")
    assert d.is_test_path("app/billing.spec.js")
    assert d.is_test_path("app/api.test.ts")


def test_is_test_path_keeps_production_sampleish_names():
    d = load_detection()
    for f in ("app/sample_rate.py", "app/mock_billing.py", "app/example_config.py", "app/latest.py"):
        assert not d.is_test_path(f), f


def test_is_noise_path_drops_docs_lockfiles_tests_and_vendored():
    d = load_detection()
    for f in (
        "README.md",
        "docs/guide.rst",
        "NOTES.txt",
        "site/intro.mdx",
        "package-lock.json",
        "frontend/yarn.lock",
        "go.sum",
        "uv.lock",
        "bun.lock",
        "deno.lock",
        "app/tests/test_views.py",
        "app/views_test.go",
        "node_modules/left-pad/index.js",
        "dist/bundle.js",
        "vendor/github.com/pkg/errors.go",
        "coverage/lcov.info",
    ):
        assert d.is_noise_path(f), f


def test_is_noise_path_keeps_source_and_security_relevant_non_source():
    d = load_detection()
    for f in (
        "app/views.py",
        "src/main.go",
        "migrations/001_users.sql",
        "deploy/entrypoint.sh",
        "Dockerfile",
        "infra/main.tf",
        "config/settings.yaml",
    ):
        assert not d.is_noise_path(f), f


def test_skip_root_dirs_prunes_at_root_only():
    from cyberjury.profiles.registry import resolve_profile

    evm = load_detection(resolve_profile("evm").paths.detection_file)
    assert evm.is_noise_path("lib/openzeppelin-contracts/token/ERC20.sol")
    assert not evm.is_noise_path("contracts/lib/Math.sol")


_MINIMAL_DETECTION = """\
skip_dirs: []
source_extensions: ['.py']
config_extensions: ['.yaml']
manifests: []
test_dirs: []
test_name_patterns: []
doc_extensions: ['.md']
lockfiles: []
"""
