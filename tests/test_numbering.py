"""Source and diff gutters expose the line identities consumed by review prompts."""

from cyberjury.numbering import numbered_diff, numbered_source, split_lines

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


def _gutters(diff: str) -> dict[str, tuple[str, str]]:
    gutters = {}
    for line in numbered_diff(diff).splitlines():
        gutter, body = line.split(" | ", 1)
        old, new = gutter.split(":", 1)
        gutters[body] = (old.strip(), new.strip())
    return gutters


def test_added_and_context_lines_carry_both_side_line_numbers():
    """In hunk -10,3 +10,4, context kept is 10:10, added is :11, and context tail is 12:12."""
    g = _gutters(_TWO_FILES)
    assert g[" kept"] == ("10", "10")
    assert g["+added"] == ("", "11")
    assert g[" tail"] == ("12", "12")


def test_a_removed_line_carries_only_its_old_side_number():
    """The removed line gone in hunk -10,3 shows old number 11 and a blank new-side gutter."""
    assert _gutters(_TWO_FILES)["-gone"] == ("11", "")


def test_a_later_file_header_is_not_read_as_hunk_content():
    """The second file's diff --git and +++ b/b.py lines get blank gutters instead of hunk numbers."""
    g = _gutters(_TWO_FILES)
    assert g["+++ b/b.py"] == ("", "")
    assert g["diff --git a/b.py b/b.py"] == ("", "")


def test_each_file_numbers_from_its_own_hunk_header():
    """The second file restarts at its own @@ -1,1 +1,2 @@ header, numbering +second as new line 2."""
    g = _gutters(_TWO_FILES)
    assert g["+second"] == ("", "2")


def test_a_hunk_header_omitting_its_length_covers_one_line():
    """An @@ -4 +4 @@ header numbers the removed line old 4 and the added line new 4."""
    g = _gutters("@@ -4 +4 @@\n-old\n+new\n")
    assert g["+new"] == ("", "4")
    assert g["-old"] == ("4", "")


def test_a_no_newline_marker_does_not_consume_a_line_number():
    """A backslash No newline marker gets a blank gutter, so the following +line2 stays new line 2."""
    g = _gutters("@@ -1,2 +1,2 @@\n line1\n-line2\n\\ No newline at end of file\n+line2\n")
    assert g["\\ No newline at end of file"] == ("", "")
    assert g["+line2"] == ("", "2")


def test_a_new_file_numbers_from_one():
    """A /dev/null to new.py hunk @@ -0,0 +1,3 @@ numbers added lines 1-3 with a blank header gutter."""
    body = "".join(f"+line{i}\n" for i in range(1, 4))
    g = _gutters(f"--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,3 @@\n{body}")
    assert g["+line1"] == ("", "1")
    assert g["+line3"] == ("", "3")
    assert g["+++ b/new.py"] == ("", "")


def test_gutters_share_one_width_so_the_code_stays_aligned():
    """Every numbered line of the two-file diff has the same gutter width before the pipe."""
    widths = {len(line.split("|", 1)[0]) for line in numbered_diff(_TWO_FILES).splitlines()}
    assert len(widths) == 1


def test_numbered_source_labels_the_block_and_numbers_from_its_first_line():
    """Source starting at line 300 is headed big.py lines 300-301 and numbered 300 and 301."""
    block = numbered_source("big.py", "line300\nline301\n", 300)
    assert block.startswith("# file: big.py lines 300-301\n")
    assert "300 | line300" in block
    assert "301 | line301" in block


def test_form_feed_and_other_separators_stay_inside_their_numbered_line():
    """Form feed, escape, and file separator characters stay in their line, so the source spans lines 1-4."""
    source = "def page():\n    pass\n\x0c\nCOLOR = '\x1b[0m'\x1c\n"

    assert split_lines(source) == ["def page():", "    pass", "\x0c", "COLOR = '\x1b[0m'\x1c"]
    assert numbered_source("pager.py", source, 1).splitlines()[0] == "# file: pager.py lines 1-4"
