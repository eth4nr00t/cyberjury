"""Locate report evidence within benchmark source files."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_DECLARATION = r"(?:function|func|def|const|let|var|class|contract|library|interface|modifier|struct|enum)"


@lru_cache(maxsize=512)
def symbol_line_span(source_root: str, rel_file: str, symbol: str) -> tuple[int, int] | None:
    """Return the inclusive source line span for a symbol definition."""
    path = Path(source_root) / rel_file
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    escaped_symbol = re.escape(symbol.lower())
    declaration = next(
        (
            index
            for index, line in enumerate(lines)
            if re.search(rf"{_DECLARATION}\b.*\b{escaped_symbol}\b", line.lower())
            or re.search(rf"\b{escaped_symbol}\b\s*[=(:]", line.lower())
        ),
        None,
    )
    if declaration is None:
        return None
    depth = 0
    started = False
    for index in range(declaration, len(lines)):
        for character in lines[index]:
            if character == "{":
                depth += 1
                started = True
            elif character == "}":
                depth -= 1
                if started and depth == 0:
                    return (declaration + 1, index + 1)
    if started:
        return (declaration + 1, len(lines))
    base_indent = len(lines[declaration]) - len(lines[declaration].lstrip())
    for index in range(declaration + 1, len(lines)):
        if lines[index].strip() and len(lines[index]) - len(lines[index].lstrip()) <= base_indent:
            return (declaration + 1, index)
    return (declaration + 1, len(lines))
