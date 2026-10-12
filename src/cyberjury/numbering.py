"""Line numbering for source and patch evidence shown to a model.

A finding must cite a `file:line`, but code shown without numbers gives the model no way
to derive one, only to guess at a count. Source blocks use one current line gutter. Diff
blocks use old and new gutters so the report location and change anchor remain distinct.
"""

from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _gutter(number: int | None, width: int) -> str:
    label = str(number) if number is not None else ""
    return f"{label:>{width}} | "


def numbered_source(rel: str, text: str, first_line: int) -> str:
    """One labeled block whose every line carries its real line number in the file.

    A slice starting mid-file cannot even be counted from the top, and the header's range
    shows the block is a cut rather than the full file.
    """
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
            highest = max(
                highest,
                int(m.group(1)) + _span(m.group(2)),
                int(m.group(3)) + _span(m.group(4)),
            )
    return len(str(highest)) if highest else 1


def _diff_gutter(old: int | None, new: int | None, width: int) -> str:
    old_label = str(old) if old is not None else ""
    new_label = str(new) if new is not None else ""
    return f"{old_label:>{width}}:{new_label:>{width}} | "


def numbered_diff(diff: str) -> str:
    """A unified diff whose gutter carries old and new side line numbers."""
    lines = diff.splitlines()
    width = _width(lines)
    out: list[str] = []
    old_line = new_line = 0
    new_remaining = old_remaining = 0
    for line in lines:
        m = _HUNK.match(line)
        if m:
            old_line = int(m.group(1))
            new_line = int(m.group(3))
            new_remaining, old_remaining = _span(m.group(4)), _span(m.group(2))
            out.append(_diff_gutter(None, None, width) + line)
            continue
        old_number = new_number = None
        if new_remaining > 0 or old_remaining > 0:
            mark = line[:1]
            if mark == "+":
                new_number = new_line
                new_line += 1
                new_remaining -= 1
            elif mark in (" ", ""):
                old_number = old_line
                new_number = new_line
                old_line += 1
                new_line += 1
                new_remaining -= 1
                old_remaining -= 1
            elif mark == "-":
                old_number = old_line
                old_line += 1
                old_remaining -= 1
            elif mark != "\\":
                new_remaining = old_remaining = 0
        out.append(_diff_gutter(old_number, new_number, width) + line)
    return "\n".join(out)
