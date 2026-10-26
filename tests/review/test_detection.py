"""Detection config data drives source, noise, and test path classification."""

from cyberjury.review.detection import MAX_SOURCE_BYTES, detection_for, load_detection


def test_detection_ignores_tool_directories_and_marks_dependency_directories():
    """.venv and node_modules paths are ignored, while vendor and third_party paths are dependencies."""
    d = load_detection()
    assert d.is_ignored(".venv/lib/site.py")
    assert d.is_ignored("web/node_modules/left-pad/index.js")
    assert d.is_dependency("vendor/github.com/pkg/errors/errors.go")
    assert d.is_dependency("src/third_party/zlib/inflate.c")
    assert not d.is_dependency("src/vendor_api.go")


def test_is_test_path_by_directory_segment():
    """Paths under tests/, test/, and __tests__/ count as tests, while app/views.py and spec/openapi.yaml do not."""
    d = load_detection()
    assert d.is_test_path("app/tests/views.py")
    assert d.is_test_path("src/test/java/app/UserServiceTest.java")
    assert d.is_test_path("web/__tests__/billing.js")
    assert not d.is_test_path("app/views.py")
    assert not d.is_test_path("spec/openapi.yaml")


def test_is_test_path_by_naming_convention_across_ecosystems():
    """Python test_ prefixes, Go _test suffixes, JS/TS .spec and .test, and Solidity .t.sol names count as tests."""
    d = load_detection()
    assert d.is_test_path("app/test_views.py")
    assert d.is_test_path("app/views_test.go")
    assert d.is_test_path("app/billing.spec.js")
    assert d.is_test_path("app/api.test.ts")
    assert d.is_test_path("src/Vault.t.sol")


def test_is_test_path_keeps_production_sampleish_names():
    """Files like sample_rate.py, mock_billing.py, example_config.py, and latest.py are not test paths."""
    d = load_detection()
    for f in ("app/sample_rate.py", "app/mock_billing.py", "app/example_config.py", "app/latest.py"):
        assert not d.is_test_path(f), f


def test_is_noise_path_drops_docs_lockfiles_tests_and_vendored():
    """Docs, lockfiles, test files, node_modules, and vendor paths across languages are classified as noise."""
    d = load_detection()
    for f in (
        "README.md",
        "docs/guide.rst",
        "site/intro.mdx",
        "package-lock.json",
        "frontend/yarn.lock",
        "go.sum",
        "uv.lock",
        "public/css/app.min.css.map",
        "bun.lock",
        "deno.lock",
        "app/tests/test_views.py",
        "app/views_test.go",
        "node_modules/left-pad/index.js",
        "vendor/github.com/pkg/errors.go",
        "Cargo.lock",
        "gradle.lockfile",
        "conan.lock",
        "src/parser_unittest.cc",
    ):
        assert d.is_noise_path(f), f


def test_is_noise_path_keeps_source_and_security_relevant_non_source():
    """Source of every language plus build scripts, SQL, shell, Dockerfile, Terraform, and YAML are not noise."""
    d = load_detection()
    for f in (
        "src/lib.rs",
        "src/main/java/app/Latest.java",
        "src/parser.cc",
        "include/parser.h",
        "web/app.ts",
        "CMakeLists.txt",
        "docker/build/finalize.sh",
        "out/site.go",
        "app/views.py",
        "src/main.go",
        "migrations/001_users.sql",
        "deploy/entrypoint.sh",
        "Dockerfile",
        "infra/main.tf",
        "config/settings.yaml",
    ):
        assert not d.is_noise_path(f), f


def test_translation_catalogs_are_noise_while_code_and_config_beside_them_are_kept():
    """Data files under locale, i18n, and l10n directories are noise, and Go code there and conf/app.ini are kept."""
    d = load_detection()
    for f in (
        "conf/locale/locale_de-DE.ini",
        "config/locales/fr.yml",
        "public/locales/zh-Hant/grafana.json",
        "apps/settings/l10n/de.json",
        "Server/Localization/Core/de.json",
        "src/main/resources/i18n/messages_de.properties",
    ):
        assert d.is_noise_path(f), f
    for f in ("internal/locale/locale.go", "conf/app.ini", "config/settings.yaml"):
        assert not d.is_noise_path(f), f


def _write(root, files):
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return sorted(files)


def test_gitattributes_linguist_vendored_rules_follow_git_pattern_semantics(tmp_path):
    """Anchored, basename, and ** patterns mark vendored paths, and a later or deeper rule can unset them."""
    files = _write(
        tmp_path,
        {
            ".gitattributes": (
                "# third-party code\n"
                "public/plugins/** linguist-vendored\n"
                "*.min.js linguist-vendored=true\n"
                "public/plugins/own/** -linguist-vendored\n"
                "libs/ linguist-vendored\n"
                "docs/** linguist-documentation\n"
            ),
            "web/.gitattributes": "assets/*.js linguist-vendored\nassets/app.js linguist-vendored=false\n",
        },
    )
    detection = detection_for(tmp_path, files)

    assert detection.is_dependency("public/plugins/pdfjs/viewer.mjs")
    assert detection.is_dependency("app/static/jquery.min.js")
    assert detection.is_dependency("web/assets/lib.js")
    assert not detection.is_dependency("public/plugins/own/main.js")
    assert not detection.is_dependency("web/assets/app.js")
    assert not detection.is_dependency("web/assets/nested/lib.js")
    assert not detection.is_dependency("libs/lib.js")
    assert not detection.is_dependency("public/app.js")
    assert detection.is_documentation("docs/guide.js")
    assert detection.is_noise_path("public/plugins/pdfjs/viewer.mjs")
    assert not load_detection().is_dependency("public/plugins/pdfjs/viewer.mjs")


def test_project_declarations_override_the_contract_defaults(tmp_path):
    """vendor/** -linguist-vendored keeps vendor code reviewable, and README.md -linguist-documentation is source."""
    files = _write(
        tmp_path,
        {".gitattributes": "vendor/** -linguist-vendored\nREADME.md -linguist-documentation\n"},
    )
    detection = detection_for(tmp_path, files)

    assert not detection.is_dependency("vendor/internal/auth.go")
    assert not detection.is_documentation("README.md")
    assert detection.is_documentation("docs/guide.md")
    assert load_detection().is_dependency("vendor/internal/auth.go")


def test_files_over_the_size_limit_are_classified_as_oversized(tmp_path):
    """A bindata.go over MAX_SOURCE_BYTES is the only oversized file, while app.py is not."""
    files = _write(
        tmp_path,
        {
            "app.py": "def handler(value):\n    return value\n",
            "bindata.go": "package bindata\n\nvar data = `" + "a" * MAX_SOURCE_BYTES + "`\n",
        },
    )

    assert detection_for(tmp_path, files).oversized_files == frozenset({"bindata.go"})
