"""Diff model tests cover patch paths, filtering, changed ranges, and bounded batch packing."""

import pytest

from cyberjury.review.definitions import DefinitionUnitPlan
from cyberjury.review.diff.model import (
    DiffUnit,
    changed_definition_fragments,
    changed_line_ranges,
    changed_paths,
    chunk_path,
    diff_line_ranges,
    diff_paths,
    diff_unit_plan_receipt,
    pack_diff_chunks,
    split_diff_by_file,
    strip_unreviewable_files,
)
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.relationships import RelationshipEvidenceBundle

_FILE_A = "diff --git a/a.py b/a.py\n@@ -0,0 +1 @@\n+x = 1\n"

_FILE_B = "diff --git a/b.py b/b.py\n@@ -0,0 +1 @@\n+y = 2\n"


def _facts_resolution() -> FactsResolutionReceipt:
    native = NativeAnalysisReceipt.create(
        producer="test",
        producer_version="1",
        source_count=0,
        definition_count=0,
        callsite_count=0,
        limitation_count=0,
        evidence={},
    )
    return FactsResolutionReceipt.create(
        native_analysis=native,
        relationship_evidence=RelationshipEvidenceBundle().to_data(),
        limitations=(),
    )


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


def test_pack_diff_chunks_keeps_an_indivisible_oversized_line_observable():
    big = "diff --git a/big.py b/big.py\n@@ -0,0 +1 @@\n+" + "z" * 200 + "\n"
    batches = pack_diff_chunks(_FILE_A + big, max_chars=len(_FILE_A) + 5)
    assert batches[0] == _FILE_A
    assert len(batches) == 2
    assert len(batches[1]) > len(_FILE_A) + 5
    assert "+" + "z" * 200 in batches[1]


def test_pack_diff_chunks_splits_one_large_hunk_without_dropping_changed_lines():
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


def test_diff_unit_plan_receipt_exposes_patch_ownership_and_over_target_units():
    unit = DiffUnit(
        index=1,
        total=1,
        diff=_FILE_A,
        paths=("a.py",),
        definition_plan=DefinitionUnitPlan(seed_files=("a.py",)),
    )

    receipt = diff_unit_plan_receipt([unit], _facts_resolution(), expected_owned_paths=("a.py",))

    assert receipt.expected_seed_ids == ("patch:a.py",)
    assert receipt.unowned_seed_ids == ()
    assert receipt.units[0].owned_paths == ("a.py",)
    assert receipt.units[0].patch_chars == len(_FILE_A)


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


def test_strip_unreviewable_files_uses_the_profile_patch_boundary():
    translation = "diff --git a/messages.xlf b/messages.xlf\n@@ -0,0 +1 @@\n+<trans-unit/>\n"
    style = "diff --git a/theme.scss b/theme.scss\n@@ -0,0 +1 @@\n+.secret { color: red; }\n"
    template = "diff --git a/view.html b/view.html\n@@ -0,0 +1 @@\n+{{ unsafe }}\n"
    query = "diff --git a/data.sql b/data.sql\n@@ -0,0 +1 @@\n+SELECT 1;\n"

    kept, skipped = strip_unreviewable_files(translation + style + template + query)

    assert set(skipped) == {"messages.xlf", "theme.scss"}
    assert "view.html" in kept
    assert "data.sql" in kept


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


def test_diff_line_ranges_separate_current_old_and_new_sides():
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

    ranges = diff_line_ranges(diff)

    assert ranges.current == {"app.py": ((10, 12),)}
    assert ranges.old == {"app.py": ((11, 11),)}
    assert ranges.new == {"app.py": ((11, 11),)}


def test_diff_line_ranges_keep_renamed_side_paths_distinct():
    diff = "diff --git a/old.py b/new.py\n--- a/old.py\n+++ b/new.py\n@@ -4 +4 @@\n-allow()\n+deny()\n"

    ranges = diff_line_ranges(diff)

    assert ranges.old == {"old.py": ((4, 4),)}
    assert ranges.new == {"new.py": ((4, 4),)}
    assert ranges.current == {"new.py": ((4, 4),)}


def test_diff_line_ranges_keep_reportable_non_source_files():
    diff = (
        "diff --git a/policy.yaml b/policy.yaml\n"
        "--- a/policy.yaml\n"
        "+++ b/policy.yaml\n"
        "@@ -1 +1 @@\n"
        "-require_approval: true\n"
        "+require_approval: false\n"
    )

    ranges = diff_line_ranges(diff)

    assert ranges.current == {"policy.yaml": ((1, 1),)}
    assert ranges.old == {"policy.yaml": ((1, 1),)}
    assert ranges.new == {"policy.yaml": ((1, 1),)}
    assert changed_line_ranges(diff) == {}


def test_changed_definition_mapping_keeps_deletion_and_enclosing_definitions(tmp_path):
    source = "class View(Base):\n    def handle(self):\n        require_admin(self)\n        return sensitive()\n"
    (tmp_path / "view.py").write_text(source)
    method_start = source.index("    def")
    graph = {
        "callgraph": {
            "view.py": {
                "View": [{"range": [0, len(source)], "calls": []}],
                "handle": [{"range": [method_start, len(source)], "calls": ["sensitive"]}],
            }
        }
    }
    diff = (
        "diff --git a/view.py b/view.py\n--- a/view.py\n+++ b/view.py\n"
        "@@ -2,3 +2,2 @@ class View(Base):\n"
        "     def handle(self):\n"
        "-        require_admin(self)\n"
        "         return sensitive()\n"
    )

    fragments = changed_definition_fragments(tmp_path, ("view.py",), changed_line_ranges(diff), graph)

    assert [fragment.name for fragment in fragments] == ["View", "handle"]


def test_adjacent_definition_end_does_not_claim_the_next_line(tmp_path):
    first = "def a():\n    return 1\n"
    second = "def b():\n    return 2\n"
    (tmp_path / "app.py").write_text(first + second)
    graph = {
        "callgraph": {
            "app.py": {
                "a": [{"range": [0, len(first)], "calls": []}],
                "b": [{"range": [len(first), len(first + second)], "calls": []}],
            }
        }
    }
    diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3 +3 @@\n-def b():\n+def b(x):\n"

    fragments = changed_definition_fragments(tmp_path, ("app.py",), changed_line_ranges(diff), graph)

    assert [fragment.name for fragment in fragments] == ["b"]
