"""Diff model tests cover patch paths, filtering, local grounding, and bounded batch packing."""

import pytest

from cyberjury.review.diff.model import (
    changed_line_ranges,
    changed_paths,
    chunk_path,
    deleted_paths,
    diff_local_context,
    diff_paths,
    pack_diff_chunks,
    split_diff_by_file,
    strip_unreviewable_files,
)

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def test_split_diff_by_file():
    chunks = split_diff_by_file(_FILE_A + _FILE_B)
    assert chunks == [_FILE_A, _FILE_B]


def test_split_diff_empty_and_unbounded():
    assert split_diff_by_file("") == []
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_pack_diff_chunks_empty_is_no_batches():
    assert pack_diff_chunks("") == []


def test_pack_diff_chunks_greedily_combines_files():
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A) + len(_FILE_B))
    assert batches == [_FILE_A + _FILE_B]
    batches = pack_diff_chunks(_FILE_A + _FILE_B, max_chars=len(_FILE_A))
    assert batches == [_FILE_A, _FILE_B]


def test_pack_diff_chunks_isolates_an_oversized_file():
    big = "diff --git a/big.py b/big.py\n@@ -0,0 +1 @@\n+" + "z" * 200 + "\n"
    batches = pack_diff_chunks(_FILE_A + big, max_chars=len(_FILE_A) + 5)
    assert batches == [_FILE_A, big]


def test_diff_model_excludes_test_files_before_review():
    """Diff unit construction applies the same test exclusion as repository units."""
    production = "diff --git a/app/views.py b/app/views.py\n+++ b/app/views.py\n+x = 1\n"
    test = "diff --git a/tests/test_views.py b/tests/test_views.py\n+++ b/tests/test_views.py\n+x = 1\n"

    kept, skipped = strip_unreviewable_files(production + test)

    assert kept == production
    assert skipped == ("tests/test_views.py",)


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"

_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_strip_unreviewable_files_drops_docs_and_lockfiles_keeps_source():
    kept, skipped = strip_unreviewable_files(_SRC + _DOC + _LOCK)
    assert kept == _SRC
    assert set(skipped) == {"README.md", "package-lock.json"}


def test_strip_unreviewable_files_keeps_a_chunk_whose_path_cannot_be_read():
    headerless = "@@ -0,0 +1 @@\n+x = 1\n"
    kept, skipped = strip_unreviewable_files(headerless)
    assert kept == headerless
    assert skipped == ()


def test_chunk_path_reads_the_deletion_and_git_header_fallbacks():
    deletion = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-# Title\n"
    assert chunk_path(deletion) == "README.md"
    header_only = "diff --git a/app/x.py b/app/x.py\nBinary files differ\n"
    assert chunk_path(header_only) == "app/x.py"
    quoted_header_only = 'diff --git "a/app icon.png" "b/app icon.png"\nBinary files differ\n'
    assert chunk_path(quoted_header_only) == "app icon.png"
    encoded_header_only = 'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\nBinary files differ\n'
    assert chunk_path(encoded_header_only) == "caf\u00e9.py"


def test_deleted_paths_identifies_source_files_absent_after_the_patch():
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-def sink(value): pass\n"
    assert deleted_paths(diff) == ("app.py",)


def test_pack_diff_chunks_preserves_source_order_within_bound():

    def chunk(path: str, line: str) -> str:
        return f"diff --git a/{path} b/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+{line}\n"

    first = chunk("first.ts", "const value = 1")
    caller = chunk("caller.ts", "mergeOptions(config, body)")
    filler = chunk("filler.ts", f"unrelatedWork(item) // {'x' * 200}")
    helper = chunk("helper.ts", "const mergeOptions = (target, source) => target")
    max_chars = len(first) + len(caller) + len(filler)

    batches = pack_diff_chunks(first + caller + filler + helper, max_chars=max_chars)
    first_paths = [chunk_path(part) for part in split_diff_by_file(batches[0])]

    assert len(batches[0]) <= max_chars
    assert first_paths == ["first.ts", "caller.ts", "filler.ts"]
    assert chunk_path(batches[1]) == "helper.ts"


def test_diff_model_uses_the_passed_profile_detection():
    """Diff unit construction uses the selected profile's test conventions."""
    from cyberjury.detection import load_detection
    from cyberjury.profiles.registry import resolve_profile

    evm = load_detection(resolve_profile("evm").paths.detection_file)
    diff = "diff --git a/Counter.t.sol b/Counter.t.sol\n+++ b/Counter.t.sol\n+contract CounterTest {}\n"
    kept, skipped = strip_unreviewable_files(diff, evm)
    assert kept == ""
    assert skipped == ("Counter.t.sol",)


def test_changed_paths_filters_noise_files():
    diff = (
        "diff --git a/app.py b/app.py\n+++ b/app.py\n+print(1)\n"
        "diff --git a/catalog.json b/catalog.json\n+++ b/catalog.json\n+{}\n"
        "diff --git a/README.md b/README.md\n+++ b/README.md\n+hi\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n+++ b/tests/test_app.py\n+def test_x(): pass\n"
    )
    assert changed_paths(diff) == ("app.py",)


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/app route.py b/app route.py\n--- a/app route.py\n+++ b/app route.py\n",
        'diff --git "a/app route.py" "b/app route.py"\n--- "a/app route.py"\n+++ "b/app route.py"\n',
    ],
)
def test_diff_paths_and_ranges_preserve_git_paths_with_spaces(header):
    diff = header + "@@ -0,0 +7,2 @@\n+def route():\n+    return sink()\n"

    assert diff_paths(diff) == ("app route.py",)
    assert changed_paths(diff) == ("app route.py",)
    assert changed_line_ranges(diff) == {"app route.py": ((7, 8),)}


@pytest.mark.parametrize(
    ("path_a", "definition", "path_b", "call"),
    [
        ("routes.ts", "handleRequest", "service.ts", "loadAccount"),
        ("Collateral.sol", "deposit", "Strategy.sol", "totalValue"),
    ],
)
def test_diff_local_grounding_links_changed_web_and_evm_symbols(path_a, definition, path_b, call):
    diff = (
        f"diff --git a/{path_a} b/{path_a}\n+++ b/{path_a}\n@@ -1 +1 @@\n"
        f"+function {definition}() {{ return controller.{call}(); }}\n"
        f"diff --git a/{path_b} b/{path_b}\n+++ b/{path_b}\n@@ -1 +1 @@\n"
        f"+function {call}() {{ return 1; }}\n"
    )

    context = diff_local_context(diff)

    assert f"{path_a} uses {path_b}:{call}" in context
