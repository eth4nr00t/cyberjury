"""Normalized findings consumed by the score engine."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cyberjury.detection import load_detection
from cyberjury.profiles.registry import available_profiles, get_profile
from evals.score.match import category_of, normalize_endpoint


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it."""

    name: str
    endpoint: str = ""
    category: str = ""
    files: tuple[str, ...] = ()
    text: str = ""
    lines: tuple[int, ...] = ()

    @classmethod
    def make(
        cls,
        name: str,
        endpoint: str,
        category: str,
        files: Sequence[str],
        text: str = "",
        lines: Sequence[int] = (),
    ) -> Report:
        """Build a normalized report."""
        return cls(
            name=name,
            endpoint=normalize_endpoint(endpoint),
            category=category_of(category),
            files=tuple(files),
            text=text.lower(),
            lines=tuple(sorted({int(line) for line in lines})),
        )


@lru_cache(maxsize=1)
def _file_re() -> re.Pattern:
    extensions = set(load_detection().source_extensions)
    for name in available_profiles():
        detection_file = get_profile(name).paths.detection_file
        extensions.update(load_detection(detection_file).source_extensions)
    extension_pattern = "|".join(
        re.escape(extension.lstrip(".")) for extension in sorted(extensions, key=len, reverse=True)
    )
    return re.compile(rf"(?<![\w./-])[\w./-]+\.(?:{extension_pattern})")


def _source_paths(text: str) -> tuple[str, ...]:
    paths: dict[str, None] = {}
    for raw_path in _file_re().findall(text):
        first = raw_path.split("/", 1)[0]
        if re.match(r"^\d+(?:-|$)", first) or first.isdigit():
            continue
        paths.setdefault(raw_path, None)
    return tuple(sorted(paths))


def _cited_lines(text: str, files: Sequence[str]) -> tuple[int, ...]:
    names = {Path(file).name for file in files}
    lines: set[int] = set()
    for match in re.finditer(r"([\w./-]+\.\w+):(\d+)", text):
        if Path(match.group(1)).name in names:
            lines.add(int(match.group(2)))
    return tuple(sorted(lines))


def parse_finding_md(text: str, name: str) -> Report:
    """Read one findings Markdown document into a report."""

    def field(key: str) -> str:
        match = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
        return match.group(1).strip().strip("`") if match else ""

    files = _source_paths(text)
    return Report.make(name, field("source"), field("type"), files, text=text, lines=_cited_lines(text, files))


def reports_from_findings_dir(directory: str | Path) -> list[Report]:
    """Load reports from a finalized findings directory."""
    findings_dir = Path(directory)
    if not findings_dir.is_dir():
        raise ValueError(f"no findings directory at {findings_dir}, finalize a review first")
    return [parse_finding_md(path.read_text(encoding="utf-8"), path.stem) for path in sorted(findings_dir.glob("*.md"))]


def reports_from_json(path: str | Path) -> list[Report]:
    """Load reports from machine readable findings JSON."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data["findings"] if isinstance(data, dict) else data
    reports = []
    for index, row in enumerate(rows):
        files = [str(row["file"])] if row.get("file") else []
        text = " ".join(
            str(row.get(key, ""))
            for key in (
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
        if isinstance(row.get("line"), int):
            lines.add(row["line"])
        reports.append(
            Report.make(
                str(row.get("id") or f"r{index}"),
                str(row.get("entry") or row.get("source") or ""),
                str(row.get("category") or row.get("type") or ""),
                files,
                text=text,
                lines=lines,
            )
        )
    return reports
