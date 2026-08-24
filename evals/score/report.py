"""Normalized findings consumed by the score engine."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from evals.score.match import category_of, normalize_endpoint


@dataclass(frozen=True, order=True)
class ReportLocation:
    """Bind one cited source line to the file that owns it."""

    file: str
    line: int | None = None


@dataclass(frozen=True, order=True)
class ReportChangeAnchor:
    """Bind a report to the exact patch line that caused its behavior."""

    file: str
    line: int
    side: Literal["old", "new"]


@dataclass(frozen=True, kw_only=True)
class Report:
    """One reported issue, however a path produced it."""

    name: str
    endpoint: str = ""
    category: str = ""
    locations: tuple[ReportLocation, ...] = ()
    text: str = ""
    change_anchor: ReportChangeAnchor | None = None

    @property
    def files(self) -> tuple[str, ...]:
        """Expose every cited file once in report order."""
        return tuple(dict.fromkeys(location.file for location in self.locations))

    @property
    def lines(self) -> tuple[int, ...]:
        """Expose cited lines for compatibility with single file consumers."""
        return tuple(sorted({location.line for location in self.locations if location.line is not None}))

    def lines_for(self, file: str, *, exact: bool) -> tuple[int, ...]:
        """Return only line citations attached to the requested source file."""
        expected = Path(file).as_posix().removeprefix("./")
        if not exact:
            matching_files = {
                location.file for location in self.locations if Path(location.file).name == Path(file).name
            }
            if len(matching_files) != 1:
                return ()
        return tuple(
            sorted(
                {
                    location.line
                    for location in self.locations
                    if location.line is not None
                    and (
                        Path(location.file).as_posix().removeprefix("./") == expected
                        if exact
                        else Path(location.file).name == Path(file).name
                    )
                }
            )
        )

    @classmethod
    def make(
        cls,
        name: str,
        endpoint: str,
        category: str,
        files: Sequence[str],
        text: str = "",
        lines: Sequence[int] = (),
        locations: Sequence[ReportLocation] = (),
        change_anchor: ReportChangeAnchor | None = None,
    ) -> Report:
        """Build a normalized report."""
        normalized_locations = tuple(locations)
        if normalized_locations and (files or lines):
            raise ValueError("report locations cannot be combined with separate files or lines")
        if not normalized_locations:
            normalized_files = tuple(files)
            normalized_lines = tuple(sorted({int(line) for line in lines}))
            if normalized_lines and len(normalized_files) != 1:
                raise ValueError("report lines require exactly one source file")
            normalized_locations = tuple(
                ReportLocation(file, line) for file in normalized_files for line in (normalized_lines or (None,))
            )
        return cls(
            name=name,
            endpoint=normalize_endpoint(endpoint),
            category=category_of(category),
            locations=normalized_locations,
            text=text.lower(),
            change_anchor=change_anchor,
        )


def _file_res() -> tuple[re.Pattern, re.Pattern]:
    extension = r"[A-Za-z][A-Za-z0-9]{0,15}"
    quoted = re.compile(rf"`(?P<path>[\w./-][\w ./-]*\.{extension})`")
    plain = re.compile(rf"(?<![\w./-])(?P<path>[\w./-]+\.{extension})(?=:\d+)")
    return quoted, plain


def _source_paths(text: str) -> tuple[str, ...]:
    paths: dict[str, None] = {}
    quoted, plain = _file_res()
    for match in quoted.finditer(text):
        paths.setdefault(match.group("path"), None)
    unquoted_text = quoted.sub(" ", text)
    for known_path in paths:
        if " " in known_path:
            unquoted_text = unquoted_text.replace(known_path, " ")
    for raw_path in plain.findall(unquoted_text):
        first = raw_path.split("/", 1)[0]
        if re.match(r"^\d+(?:-|$)", first) or first.isdigit():
            continue
        paths.setdefault(raw_path, None)
    return tuple(sorted(paths))


def _matching_file(cited_path: str, files: Sequence[str]) -> str | None:
    exact = [file for file in files if Path(file).as_posix() == Path(cited_path).as_posix()]
    if exact:
        return exact[0]
    names = [file for file in files if Path(file).name == Path(cited_path).name]
    return names[0] if len(names) == 1 else None


def _cited_locations(text: str, files: Sequence[str]) -> tuple[ReportLocation, ...]:
    locations: set[ReportLocation] = set()
    citations = re.finditer(
        r"`(?P<quoted>[^`\r\n]+)`:(?P<quoted_line>\d+)|(?P<plain>[\w./-]+\.\w+):(?P<plain_line>\d+)",
        text,
    )
    for match in citations:
        cited_path = match.group("quoted") or match.group("plain")
        cited_line = match.group("quoted_line") or match.group("plain_line")
        file = _matching_file(cited_path, files)
        if file is not None:
            locations.add(ReportLocation(file, int(cited_line)))
    for file in files:
        if " " not in file:
            continue
        for match in re.finditer(rf"(?<![\w./-]){re.escape(file)}:(\d+)", text):
            locations.add(ReportLocation(file, int(match.group(1))))
    cited_files = {location.file for location in locations}
    locations.update(ReportLocation(file) for file in files if file not in cited_files)
    return tuple(sorted(locations))


def parse_finding_md(text: str, name: str) -> Report:
    """Read one findings Markdown document into a report."""

    def field(key: str) -> str:
        match = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
        return match.group(1).strip().strip("`") if match else ""

    files = _source_paths(text)
    return Report.make(
        name,
        field("source"),
        field("type"),
        (),
        text=text,
        locations=_cited_locations(text, files),
    )


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
        change_anchor = _report_change_anchor(row.get("change_anchor"), path=path, index=index)
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
        locations = set(_cited_locations(text, files))
        line = row.get("line")
        if line is not None:
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                raise ValueError(f"{path} findings[{index}].line must be null or a positive integer")
            if not files:
                raise ValueError(f"{path} findings[{index}].line requires a source file")
            locations.discard(ReportLocation(files[0]))
            locations.add(ReportLocation(files[0], line))
        reports.append(
            Report.make(
                str(row.get("id") or f"r{index}"),
                str(row.get("entry") or row.get("source") or ""),
                str(row.get("category") or row.get("type") or ""),
                (),
                text=text,
                locations=locations,
                change_anchor=change_anchor,
            )
        )
    return reports


def _report_change_anchor(value: object, *, path: str | Path, index: int) -> ReportChangeAnchor | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"file", "line", "side"}:
        raise ValueError(f"{path} findings[{index}].change_anchor is malformed")
    file = value["file"]
    line = value["line"]
    side = value["side"]
    if (
        not isinstance(file, str)
        or not file.strip()
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
        or side not in ("old", "new")
    ):
        raise ValueError(f"{path} findings[{index}].change_anchor is malformed")
    return ReportChangeAnchor(file=file.strip(), line=line, side=side)
