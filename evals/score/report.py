"""Normalized findings consumed by the score engine."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


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
    locations: tuple[ReportLocation, ...] = ()
    change_anchor: ReportChangeAnchor | None = None

    def lines_for(self, file: str) -> tuple[int, ...]:
        """Return only line citations attached to the requested source file."""
        expected = Path(file).as_posix().removeprefix("./")
        return tuple(
            sorted(
                {
                    location.line
                    for location in self.locations
                    if location.line is not None and Path(location.file).as_posix().removeprefix("./") == expected
                }
            )
        )


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
                "summary",
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
            Report(
                name=str(row.get("id") or f"r{index}"),
                locations=tuple(sorted(locations)),
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
