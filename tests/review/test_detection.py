"""Detection config data drives source, noise, and test path classification."""

from cyberjury.review.detection import MAX_SOURCE_BYTES, detection_for, load_detection
from cyberjury.review.diff.model import strip_unreviewable_files
from cyberjury.review.result import SkippedFile
from cyberjury.review.selection import select_files
from cyberjury.review.syntax.facts import extract_syntax_facts


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


def test_vendored_files_leave_review_selection_and_syntax_facts(tmp_path):
    """A linguist-vendored public/plugins/lib.js is navigable but neither reviewed nor parsed, while app.py is both."""
    files = _write(
        tmp_path,
        {
            ".gitattributes": "public/plugins/** linguist-vendored\n",
            "app.py": "def handler(value):\n    return value\n",
            "public/plugins/lib.js": "function helper(value) { return value }\n",
        },
    )
    detection = detection_for(tmp_path, files)

    selection = select_files(tmp_path, files, detection)
    facts = extract_syntax_facts(tmp_path, files, selection.navigation_files, detection)

    assert selection.review_files == (".gitattributes", "app.py")
    assert selection.dependency_files == ("public/plugins/lib.js",)
    assert "public/plugins/lib.js" in selection.navigation_files
    assert set(facts.by_file) == {"app.py"}


def test_diff_review_skips_changes_to_vendored_files_as_noise(tmp_path):
    """A change to linguist-vendored public/plugins/lib.js is skipped as noise, and the app.py change stays."""
    files = _write(tmp_path, {".gitattributes": "public/plugins/** linguist-vendored\n"})
    diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n"
        "diff --git a/public/plugins/lib.js b/public/plugins/lib.js\n--- a/public/plugins/lib.js\n"
        "+++ b/public/plugins/lib.js\n@@ -1 +1 @@\n-var a = 1\n+var a = 2\n"
    )

    kept, skipped = strip_unreviewable_files(diff, detection_for(tmp_path, files))

    assert "app.py" in kept
    assert "lib.js" not in kept
    assert skipped == (SkippedFile(path="public/plugins/lib.js", reason="noise"),)


def test_files_over_the_size_limit_are_skipped_as_too_large(tmp_path):
    """A bindata.go over MAX_SOURCE_BYTES is skipped as too_large in selection, facts, and diff review."""
    limit = MAX_SOURCE_BYTES
    files = _write(
        tmp_path,
        {
            "app.py": "def handler(value):\n    return value\n",
            "bindata.go": "package bindata\n\nvar data = `" + "a" * limit + "`\n",
        },
    )
    detection = detection_for(tmp_path, files)
    diff = "diff --git a/bindata.go b/bindata.go\n--- a/bindata.go\n+++ b/bindata.go\n@@ -1 +1 @@\n-x\n+y\n"

    selection = select_files(tmp_path, files, detection)
    facts = extract_syntax_facts(tmp_path, files, selection.navigation_files, detection)
    kept, skipped = strip_unreviewable_files(diff, detection)

    assert selection.review_files == ("app.py",)
    assert selection.skipped_files == (SkippedFile(path="bindata.go", reason="too_large"),)
    assert "bindata.go" not in selection.navigation_files
    assert not facts.limitations
    assert kept == ""
    assert skipped == (SkippedFile(path="bindata.go", reason="too_large"),)
