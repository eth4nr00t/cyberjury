"""The file and path classification config loads from data and drives what the
engine treats as a source file, a manifest, a noise dir, or test code, so the
implementation enumerates no language itself."""

from cyberjury.detection import load_detection


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
    # a denylist, not the inverse of source_extensions, so a non-source file that can still
    # carry an exploit stays in review, invariant 2
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
    from cyberjury.domains.registry import resolve_domain

    evm = load_detection(resolve_domain("evm").paths.detection_file)
    assert evm.is_noise_path("lib/openzeppelin-contracts/token/ERC20.sol")
    assert not evm.is_noise_path("contracts/lib/Math.sol")
