"""Detection config data drives source, noise, and test path classification."""

from cyberjury.review.detection import load_detection


def test_detection_skips_dependency_directories():
    """The loaded detection config lists .venv and node_modules among its skipped directories."""
    d = load_detection()
    assert ".venv" in d.skip_dirs
    assert "node_modules" in d.skip_dirs


def test_is_test_path_by_directory_segment():
    """Paths under tests/ or spec/ count as tests, while app/views.py does not."""
    d = load_detection()
    assert d.is_test_path("app/tests/views.py")
    assert d.is_test_path("spec/billing.js")
    assert not d.is_test_path("app/views.py")


def test_is_test_path_by_naming_convention_across_ecosystems():
    """Python test_ prefixes, Go _test suffixes, and JS/TS .spec and .test names count as tests."""
    d = load_detection()
    assert d.is_test_path("app/test_views.py")
    assert d.is_test_path("app/views_test.go")
    assert d.is_test_path("app/billing.spec.js")
    assert d.is_test_path("app/api.test.ts")


def test_is_test_path_keeps_production_sampleish_names():
    """Files like sample_rate.py, mock_billing.py, example_config.py, and latest.py are not test paths."""
    d = load_detection()
    for f in ("app/sample_rate.py", "app/mock_billing.py", "app/example_config.py", "app/latest.py"):
        assert not d.is_test_path(f), f


def test_is_noise_path_drops_docs_lockfiles_tests_and_vendored():
    """Docs, lockfiles, test files, node_modules, dist, vendor, and coverage paths are classified as noise."""
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
    """Source plus SQL migrations, shell entrypoints, Dockerfile, Terraform, and YAML config are not noise."""
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
