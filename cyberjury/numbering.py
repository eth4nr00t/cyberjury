"""Line numbering for the code a model reads, shared by both review paths.

A finding must cite a `file:line`, but code shown without numbers gives the model no way to
derive one, only to guess at a count. Numbering makes the line a value to copy. Both paths
number through one gutter, so a location is produced the same way whether the model read a
file slice or a diff.
"""

from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _gutter(number: int | None, width: int) -> str:
    label = str(number) if number is not None else ""
    return f"{label:>{width}} | "


def numbered_source(rel: str, text: str, first_line: int) -> str:
    """One labeled block whose every line carries its real line number in the file.

    A slice starting mid-file cannot even be counted from the top, and the header's range shows
    the block is a cut rather than the whole file."""
    lines = text.splitlines()
    last = first_line + max(len(lines), 1) - 1
    width = len(str(last))
    body = "\n".join(_gutter(first_line + i, width) + line for i, line in enumerate(lines))
    return f"# file: {rel} lines {first_line}-{last}\n{body}"


def _span(count: str | None) -> int:
    """A hunk header omits the length when it covers one line."""
    return 1 if count is None else int(count)


def _width(lines: list[str]) -> int:
    highest = 0
    for line in lines:
        m = _HUNK.match(line)
        if m:
            highest = max(highest, int(m.group(3)) + _span(m.group(4)))
    return len(str(highest)) if highest else 1


def numbered_diff(diff: str) -> str:
    """A unified diff whose added and context lines carry their new-file line number.

    A removed line keeps an empty gutter, since it has no new-file line to cite and numbering it
    from the old file would collide with the numbers around it. Each hunk header's own line counts
    bound the walk, so a header, an `index` line, or a `+++` path line is never mistaken for hunk
    content."""
    lines = diff.splitlines()
    width = _width(lines)
    out: list[str] = []
    line_no = 0
    new_remaining = old_remaining = 0
    for line in lines:
        m = _HUNK.match(line)
        if m:
            line_no = int(m.group(3))
            new_remaining, old_remaining = _span(m.group(4)), _span(m.group(2))
            out.append(_gutter(None, width) + line)
            continue
        number = None
        if new_remaining > 0 or old_remaining > 0:
            mark = line[:1]
            if mark == "+":
                number = line_no
                line_no += 1
                new_remaining -= 1
            elif mark in (" ", ""):
                number = line_no
                line_no += 1
                new_remaining -= 1
                old_remaining -= 1
            elif mark == "-":
                old_remaining -= 1
            elif mark != "\\":
                new_remaining = old_remaining = 0
        out.append(_gutter(number, width) + line)
    return "\n".join(out)
