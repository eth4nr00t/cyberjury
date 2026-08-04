from cyberjury.numbering import numbered_diff, numbered_source

_TWO_FILES = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -10,3 +10,4 @@ def f():
 kept
-gone
+added
 tail
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -1,1 +1,2 @@
 first
+second
"""


def _gutters(diff: str) -> dict[str, str]:
    return {line.split(" | ", 1)[1]: line.split(" | ", 1)[0].strip() for line in numbered_diff(diff).splitlines()}


def test_added_and_context_lines_carry_their_new_file_line_number():
    g = _gutters(_TWO_FILES)
    assert g[" kept"] == "10"
    assert g["+added"] == "11"
    assert g[" tail"] == "12"


def test_a_removed_line_has_no_number():
    assert _gutters(_TWO_FILES)["-gone"] == ""


def test_a_later_file_header_is_not_read_as_hunk_content():
    g = _gutters(_TWO_FILES)
    assert g["+++ b/b.py"] == ""
    assert g["diff --git a/b.py b/b.py"] == ""


def test_each_file_numbers_from_its_own_hunk_header():
    g = _gutters(_TWO_FILES)
    assert g["+second"] == "2"


def test_a_hunk_header_omitting_its_length_covers_one_line():
    g = _gutters("@@ -4 +4 @@\n-old\n+new\n")
    assert g["+new"] == "4"
    assert g["-old"] == ""


def test_a_no_newline_marker_does_not_consume_a_line_number():
    g = _gutters("@@ -1,2 +1,2 @@\n line1\n-line2\n\\ No newline at end of file\n+line2\n")
    assert g["\\ No newline at end of file"] == ""
    assert g["+line2"] == "2"


def test_a_new_file_numbers_from_one():
    body = "".join(f"+line{i}\n" for i in range(1, 4))
    g = _gutters(f"--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,3 @@\n{body}")
    assert g["+line1"] == "1"
    assert g["+line3"] == "3"
    assert g["+++ b/new.py"] == ""


def test_gutters_share_one_width_so_the_code_stays_aligned():
    widths = {len(line.split("|", 1)[0]) for line in numbered_diff(_TWO_FILES).splitlines()}
    assert len(widths) == 1


def test_numbered_source_labels_the_block_and_numbers_from_its_first_line():
    block = numbered_source("big.py", "line300\nline301\n", 300)
    assert block.startswith("# file: big.py lines 300-301\n")
    assert "300 | line300" in block
    assert "301 | line301" in block
