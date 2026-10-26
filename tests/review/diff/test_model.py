"""Diff model tests cover patch paths, filtering, changed ranges, and bounded batch packing."""

import pytest

from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.detection import MAX_SOURCE_BYTES, detection_for, load_detection
from cyberjury.review.diff.model import (
    DiffUnit,
    changed_line_ranges,
    chunk_path,
    diff_line_ranges,
    diff_paths,
    diff_unit_plan_record,
    pack_diff_chunks,
    split_diff_by_file,
    strip_unreviewable_files,
)
from cyberjury.review.result import SkippedFile
from tests.review.diff.support import FILE_A_DIFF, FILE_B_DIFF

_DETECTION = load_detection()


def test_split_diff_by_file():
    """A two-file patch splits into one chunk per diff --git header, preserving each chunk verbatim."""
    chunks = split_diff_by_file(FILE_A_DIFF + FILE_B_DIFF)
    assert chunks == [FILE_A_DIFF, FILE_B_DIFF]


def test_split_diff_empty_and_unbounded():
    """An empty string yields no chunks, and text without a diff --git header is returned as one chunk."""
    assert split_diff_by_file("") == []
    assert split_diff_by_file("just text\n") == ["just text\n"]


def test_pack_diff_chunks_empty_is_no_batches():
    """An empty diff packs into an empty batch list."""
    assert pack_diff_chunks("") == []


def test_pack_diff_chunks_greedily_combines_files():
    """Two files share one batch when the bound fits both, and split into two when it fits only one."""
    batches = pack_diff_chunks(FILE_A_DIFF + FILE_B_DIFF, max_chars=len(FILE_A_DIFF) + len(FILE_B_DIFF))
    assert batches == [FILE_A_DIFF + FILE_B_DIFF]
    batches = pack_diff_chunks(FILE_A_DIFF + FILE_B_DIFF, max_chars=len(FILE_A_DIFF))
    assert batches == [FILE_A_DIFF, FILE_B_DIFF]


def test_pack_diff_chunks_keeps_an_indivisible_oversized_line_observable():
    """A 200-character added line that exceeds the bound gets its own over-limit batch, kept intact."""
    big = "diff --git a/big.py b/big.py\n@@ -0,0 +1 @@\n+" + "z" * 200 + "\n"
    batches = pack_diff_chunks(FILE_A_DIFF + big, max_chars=len(FILE_A_DIFF) + 5)
    assert batches[0] == FILE_A_DIFF
    assert len(batches) == 2
    assert len(batches[1]) > len(FILE_A_DIFF) + 5
    assert "+" + "z" * 200 in batches[1]


def test_pack_diff_chunks_splits_one_large_hunk_without_dropping_changed_lines():
    """Twelve added lines under max_chars=180 span several batches within the bound, in original order."""
    added = [f"value_{index:02d} = {'x' * 20}" for index in range(12)]
    diff = f"diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,{len(added)} @@\n" + "".join(
        f"+{line}\n" for line in added
    )

    batches = pack_diff_chunks(diff, max_chars=180)

    assert len(batches) > 1
    assert all(len(batch) <= 180 for batch in batches)
    observed = [
        line[1:]
        for batch in batches
        for line in batch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    assert observed == added


def test_diff_unit_plan_record_exposes_patch_ownership():
    """A diff unit for a.py records kind diff, owned path a.py, and a patch sha256."""
    unit = DiffUnit(
        index=1,
        total=1,
        diff=FILE_A_DIFF,
        paths=("a.py",),
        definition_plan=DefinitionUnitPlan(seed_files=("a.py",)),
    )

    record = diff_unit_plan_record(unit)

    assert record.kind == "diff"
    assert record.owned_paths == ("a.py",)
    assert record.patch_sha256 is not None


def test_diff_model_excludes_test_files_before_review():
    """A tests/test_views.py change is skipped as noise while the app/views.py change is kept."""
    production = "diff --git a/app/views.py b/app/views.py\n+++ b/app/views.py\n@@ -0,0 +1 @@\n+x = 1\n"
    test = "diff --git a/tests/test_views.py b/tests/test_views.py\n+++ b/tests/test_views.py\n@@ -0,0 +1 @@\n+x = 1\n"

    kept, skipped = strip_unreviewable_files(production + test, _DETECTION)

    assert kept == production
    assert [(item.path, item.reason) for item in skipped] == [("tests/test_views.py", "noise")]


_SRC = "diff --git a/app.py b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"

_DOC = "diff --git a/README.md b/README.md\n@@ -0,0 +1 @@\n+# Title\n"

_LOCK = "diff --git a/package-lock.json b/package-lock.json\n@@ -0,0 +1 @@\n+{}\n"


def test_strip_unreviewable_files_drops_docs_and_lockfiles_keeps_source():
    """README.md and package-lock.json are skipped while the app.py source chunk is kept."""
    kept, skipped = strip_unreviewable_files(_SRC + _DOC + _LOCK, _DETECTION)
    assert kept == _SRC
    assert {item.path for item in skipped} == {"README.md", "package-lock.json"}


def test_strip_unreviewable_files_uses_the_profile_patch_boundary():
    """The profile skips .xlf and .scss changes but keeps .html templates and .sql files."""
    translation = "diff --git a/messages.xlf b/messages.xlf\n@@ -0,0 +1 @@\n+<trans-unit/>\n"
    style = "diff --git a/theme.scss b/theme.scss\n@@ -0,0 +1 @@\n+.secret { color: red; }\n"
    template = "diff --git a/view.html b/view.html\n@@ -0,0 +1 @@\n+{{ unsafe }}\n"
    query = "diff --git a/data.sql b/data.sql\n@@ -0,0 +1 @@\n+SELECT 1;\n"

    kept, skipped = strip_unreviewable_files(translation + style + template + query, _DETECTION)

    assert {item.path for item in skipped} == {"messages.xlf", "theme.scss"}
    assert "view.html" in kept
    assert "data.sql" in kept


def test_strip_unreviewable_files_skips_binary_changes():
    """A binary logo.png change is skipped as binary while the app.py source chunk is kept."""
    binary = "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"

    kept, skipped = strip_unreviewable_files(binary + _SRC, _DETECTION)

    assert [(item.path, item.reason) for item in skipped] == [("logo.png", "binary")]
    assert kept == _SRC


def test_strip_unreviewable_files_skips_submodule_pointer_changes():
    """A lib/forge-std submodule pointer change is skipped as submodule while the app.py source chunk is kept."""
    submodule = (
        "diff --git a/lib/forge-std b/lib/forge-std\nindex 1111111..2222222 160000\n"
        "--- a/lib/forge-std\n+++ b/lib/forge-std\n@@ -1 +1 @@\n"
        "-Subproject commit 1111111111111111111111111111111111111111\n"
        "+Subproject commit 2222222222222222222222222222222222222222\n"
    )

    kept, skipped = strip_unreviewable_files(submodule + _SRC, _DETECTION)

    assert [(item.path, item.reason) for item in skipped] == [("lib/forge-std", "submodule")]
    assert kept == _SRC


def test_strip_unreviewable_files_keeps_a_chunk_whose_path_cannot_be_read():
    """A hunk with no file header is kept and nothing is reported as skipped."""
    headerless = "@@ -0,0 +1 @@\n+x = 1\n"
    kept, skipped = strip_unreviewable_files(headerless, _DETECTION)
    assert kept == headerless
    assert skipped == ()


def test_chunk_path_reads_the_deletion_and_git_header_fallbacks():
    """Paths come from a/ for /dev/null deletions and from plain, quoted, and octal-escaped git headers."""
    deletion = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-# Title\n"
    assert chunk_path(deletion) == "README.md"
    header_only = "diff --git a/app/x.py b/app/x.py\nBinary files differ\n"
    assert chunk_path(header_only) == "app/x.py"
    quoted_header_only = 'diff --git "a/app icon.png" "b/app icon.png"\nBinary files differ\n'
    assert chunk_path(quoted_header_only) == "app icon.png"
    encoded_header_only = 'diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\nBinary files differ\n'
    assert chunk_path(encoded_header_only) == "caf\u00e9.py"


def test_pack_diff_chunks_preserves_source_order_within_bound():
    """The files first.ts, caller.ts, and filler.ts fill the first batch in order, and helper.ts starts the next."""

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


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/app route.py b/app route.py\n--- a/app route.py\n+++ b/app route.py\n",
        'diff --git "a/app route.py" "b/app route.py"\n--- "a/app route.py"\n+++ "b/app route.py"\n',
    ],
)
def test_diff_paths_and_ranges_preserve_git_paths_with_spaces(header):
    """Plain and quoted headers for app route.py both yield that path with changed range (7, 8)."""
    diff = header + "@@ -0,0 +7,2 @@\n+def route():\n+    return sink()\n"

    assert diff_paths(diff) == ("app route.py",)
    assert changed_line_ranges(diff, _DETECTION) == {"app route.py": ((7, 8),)}


def test_diff_line_ranges_separate_current_old_and_new_sides():
    """A one-line replacement in hunk -10,3 +10,3 yields current 10-12, old line 11, and new line 11."""
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " context_before\n"
        "-app.use(auth)\n"
        "+app.use(audit)\n"
        " context_after\n"
    )

    ranges = diff_line_ranges(diff, _DETECTION)

    assert ranges.current == {"app.py": ((10, 12),)}
    assert ranges.old == {"app.py": ((11, 11),)}
    assert ranges.new == {"app.py": ((11, 11),)}


def test_diff_line_ranges_keep_renamed_side_paths_distinct():
    """A rename from old.py to new.py records old-side ranges on old.py and new and current on new.py."""
    diff = "diff --git a/old.py b/new.py\n--- a/old.py\n+++ b/new.py\n@@ -4 +4 @@\n-allow()\n+deny()\n"

    ranges = diff_line_ranges(diff, _DETECTION)

    assert ranges.old == {"old.py": ((4, 4),)}
    assert ranges.new == {"new.py": ((4, 4),)}
    assert ranges.current == {"new.py": ((4, 4),)}


def test_diff_line_ranges_keep_reportable_non_source_files():
    """A policy.yaml change keeps line 1 in current, old, new, and changed_line_ranges."""
    diff = (
        "diff --git a/policy.yaml b/policy.yaml\n"
        "--- a/policy.yaml\n"
        "+++ b/policy.yaml\n"
        "@@ -1 +1 @@\n"
        "-require_approval: true\n"
        "+require_approval: false\n"
    )

    ranges = diff_line_ranges(diff, _DETECTION)

    assert ranges.current == {"policy.yaml": ((1, 1),)}
    assert ranges.old == {"policy.yaml": ((1, 1),)}
    assert ranges.new == {"policy.yaml": ((1, 1),)}
    assert changed_line_ranges(diff, _DETECTION) == {"policy.yaml": ((1, 1),)}


def test_strip_unreviewable_files_skips_changes_to_vendored_files_as_noise(tmp_path):
    """A change to linguist-vendored public/plugins/lib.js is skipped as noise, and the app.py change stays."""
    (tmp_path / ".gitattributes").write_text("public/plugins/** linguist-vendored\n", encoding="utf-8")
    diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a = 1\n+a = 2\n"
        "diff --git a/public/plugins/lib.js b/public/plugins/lib.js\n--- a/public/plugins/lib.js\n"
        "+++ b/public/plugins/lib.js\n@@ -1 +1 @@\n-var a = 1\n+var a = 2\n"
    )

    kept, skipped = strip_unreviewable_files(diff, detection_for(tmp_path, [".gitattributes"]))

    assert "app.py" in kept
    assert "lib.js" not in kept
    assert skipped == (SkippedFile(path="public/plugins/lib.js", reason="noise"),)


def test_strip_unreviewable_files_skips_oversized_files_as_too_large(tmp_path):
    """A change to a bindata.go over MAX_SOURCE_BYTES is skipped as too_large and nothing is kept."""
    (tmp_path / "bindata.go").write_text("package bindata\n\nvar data = `" + "a" * MAX_SOURCE_BYTES + "`\n")
    diff = "diff --git a/bindata.go b/bindata.go\n--- a/bindata.go\n+++ b/bindata.go\n@@ -1 +1 @@\n-x\n+y\n"

    kept, skipped = strip_unreviewable_files(diff, detection_for(tmp_path, ["bindata.go"]))

    assert kept == ""
    assert skipped == (SkippedFile(path="bindata.go", reason="too_large"),)
