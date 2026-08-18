"""Parsing: read a review's stored output into normalized reports.

A repository review writes confirmed findings as `findings/*.md` and as a
`findings.json`, and a diff run yields findings in memory. This module turns the stored
markdown and json forms into the shared Report, so one scorer reads a coded run and an
agent run alike. The cited files come from any source path in the body, matched against
the data-driven source extensions so the scorer names no language, the same boundary the
product keeps.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import available_profiles, get_profile
from evals.models import Report


@lru_cache(maxsize=1)
def _file_re() -> re.Pattern:
    exts = set(load_detection().source_extensions)
    for name in available_profiles():
        exts.update(load_detection(get_profile(name).paths.detection_file).source_extensions)
    exts = sorted((e.lstrip(".") for e in exts), key=len, reverse=True)
    alt = "|".join(re.escape(e) for e in exts)
    return re.compile(rf"(?<![\w./-])[\w./-]+\.(?:{alt})")


def _source_paths(text: str) -> tuple[str, ...]:
    out: dict[str, None] = {}
    for raw in _file_re().findall(text):
        first = raw.split("/", 1)[0]
        if re.match(r"^\d+(?:-|$)", first) or first.isdigit():
            continue
        out.setdefault(raw, None)
    return tuple(sorted(out))


def _cited_lines(text: str, files) -> tuple[int, ...]:
    """The source lines a report pins in a file it cites.

    so a symbol anchor can credit it by location. A `file.ext:NN` reference is read only
    when its file is one the report cites, so a bare number elsewhere in the prose is not
    mistaken for a line.
    """
    names = {Path(f).name for f in files}
    lines: set[int] = set()
    for m in re.finditer(r"([\w./-]+\.\w+):(\d+)", text):
        if Path(m.group(1)).name in names:
            lines.add(int(m.group(2)))
    return tuple(sorted(lines))


_DECL = r"(?:function|func|def|const|let|var|class|contract|library|interface|modifier|struct|enum)"


@lru_cache(maxsize=512)
def symbol_line_span(source_root: str, rel_file: str, symbol: str) -> tuple[int, int] | None:
    """The 1-indexed inclusive line span of a symbol's definition in the source.

    or None when the source is unavailable or the symbol is not found. Read from the source,
    the ground truth, never from a review, so it lets a symbol anchor credit a report that
    located the bug inside the right function by line even when the report never types the
    function's name. The end is found by brace matching for a braced language and by dedent
    for an indentation language, so it spans the stacks without a parser for each one. The
    span is additive, it only ever grants a credit alongside the name match and never
    removes one, so a missing span just falls back to matching the symbol by name.
    """
    p = Path(source_root) / rel_file
    if not p.is_file():
        return None
    raw = p.read_text(encoding="utf-8", errors="replace").splitlines()
    sym = re.escape(symbol.lower())
    decl = next(
        (
            i
            for i, ln in enumerate(raw)
            if re.search(rf"{_DECL}\b.*\b{sym}\b", ln.lower()) or re.search(rf"\b{sym}\b\s*[=(:]", ln.lower())
        ),
        None,
    )
    if decl is None:
        return None
    depth = 0
    started = False
    for idx in range(decl, len(raw)):
        for ch in raw[idx]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return (decl + 1, idx + 1)
    if started:
        return (decl + 1, len(raw))
    base = len(raw[decl]) - len(raw[decl].lstrip())
    for idx in range(decl + 1, len(raw)):
        if raw[idx].strip() and (len(raw[idx]) - len(raw[idx].lstrip())) <= base:
            return (decl + 1, idx)
    return (decl + 1, len(raw))


def parse_finding_md(text: str, name: str) -> Report:
    """Read one findings/<name>.md into a Report.

    Endpoint comes from the Source line, category from Type, the cited files from any source
    path in the body.
    """

    def field(key: str) -> str:
        m = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
        return m.group(1).strip().strip("`") if m else ""

    files = _source_paths(text)
    return Report.make(name, field("source"), field("type"), files, text=text, lines=_cited_lines(text, files))


def reports_from_findings_dir(d: str | Path) -> list[Report]:
    """Load reports from a finalized findings directory."""
    d = Path(d)
    if not d.is_dir():
        raise ValueError(f"no findings directory at {d}, finalize a review first")
    return [parse_finding_md(p.read_text(encoding="utf-8"), p.stem) for p in sorted(d.glob("*.md"))]


def reports_from_json(path: str | Path) -> list[Report]:
    """Load reports from the machine-readable findings JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data["findings"] if isinstance(data, dict) else data
    out = []
    for i, r in enumerate(rows):
        files = [str(r["file"])] if r.get("file") else []
        text = " ".join(
            str(r.get(k, ""))
            for k in (
                "title",
                "note",
                "analysis",
                "attack_path",
                "description",
                "exploit_scenario",
                "recommendation",
                "evidence",
                "impact",
                "exploit",
            )
        )
        lines = set(_cited_lines(text, files))
        if isinstance(r.get("line"), int):
            lines.add(r["line"])
        out.append(
            Report.make(
                str(r.get("id") or f"r{i}"),
                str(r.get("entry") or r.get("source") or ""),
                str(r.get("category") or r.get("type") or ""),
                files,
                text=text,
                lines=lines,
            )
        )
    return out
