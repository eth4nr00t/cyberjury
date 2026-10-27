"""Readable production source selection without a language or framework allowlist."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.detection import Detection
from cyberjury.review.result import SkippedFile


@dataclass(frozen=True, kw_only=True)
class FileSelection:
    """The snapshot files one review covers, navigates, and skips."""

    review_files: tuple[str, ...]
    navigation_files: tuple[str, ...]
    skipped_files: tuple[SkippedFile, ...]
    documentation_files: tuple[str, ...] = ()
    dependency_files: tuple[str, ...] = ()


def decodes_as_utf8(data: bytes) -> bool:
    """Report whether file content is UTF-8 text."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def select_files(root: str | Path, files: Sequence[str], detection: Detection) -> FileSelection:
    """Keep every readable non-noise text file for review and record the ones that cannot be read."""
    base = Path(root)
    sources: list[str] = []
    documentation: list[str] = []
    dependencies: list[str] = []
    review: list[str] = []
    skipped: list[SkippedFile] = []
    for relative in files:
        if detection.is_ignored(relative):
            continue
        dependency = detection.is_dependency(relative)
        doc = not dependency and detection.is_documentation(relative)
        noise = detection.is_noise_path(relative)
        if noise and not (dependency or doc):
            continue
        if relative in detection.oversized_files:
            if not noise:
                skipped.append(SkippedFile(path=relative, reason="too_large"))
            continue
        data = (base / relative).read_bytes()
        decodable = decodes_as_utf8(data)
        if noise:
            if decodable and b"\0" not in data:
                (dependencies if dependency else documentation).append(relative)
            continue
        if b"\0" in data:
            skipped.append(SkippedFile(path=relative, reason="binary"))
        elif not decodable:
            skipped.append(SkippedFile(path=relative, reason="not_utf8"))
        elif not data:
            sources.append(relative)
            skipped.append(SkippedFile(path=relative, reason="empty_file"))
        else:
            sources.append(relative)
            review.append(relative)
    return FileSelection(
        review_files=tuple(review),
        navigation_files=tuple(dict.fromkeys((*sources, *documentation, *dependencies))),
        skipped_files=tuple(skipped),
        documentation_files=tuple(documentation),
        dependency_files=tuple(dependencies),
    )
