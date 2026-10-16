"""Select readable production source without a language or framework allowlist."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cyberjury.detection import Detection
from cyberjury.review.result import SkippedFile


@dataclass(frozen=True, kw_only=True)
class FileSelection:
    """The snapshot files one review covers, navigates, and skips."""

    review_files: tuple[str, ...]
    navigation_files: tuple[str, ...]
    skipped_files: tuple[SkippedFile, ...]


def select_files(root: str | Path, files: Sequence[str], detection: Detection) -> FileSelection:
    """Keep every readable non-noise text file for review and record the ones that cannot be read.

    Navigation also publishes readable documentation, and keeps empty source files that no
    review unit covers.
    """
    base = Path(root)
    sources: list[str] = []
    documentation: list[str] = []
    review: list[str] = []
    skipped: list[SkippedFile] = []
    for relative in files:
        if detection.is_skipped_dir(PurePosixPath(relative).parts[:-1]):
            continue
        noise = detection.is_noise_path(relative)
        doc = PurePosixPath(relative).suffix.lower() in detection.doc_extensions
        if noise and not doc:
            continue
        data = (base / relative).read_bytes()
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            decodable = False
        else:
            decodable = True
        if doc and decodable:
            documentation.append(relative)
        if noise:
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
        navigation_files=tuple(dict.fromkeys((*sources, *documentation))),
        skipped_files=tuple(skipped),
    )
