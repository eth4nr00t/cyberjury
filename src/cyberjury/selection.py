"""Select readable production source without a language or framework allowlist."""

from __future__ import annotations

from pathlib import Path

from cyberjury.detection import Detection
from cyberjury.review.paths import repository_files


def source_files(root: str | Path, detection: Detection) -> tuple[str, ...]:
    """Keep every readable non-noise file in the repository review worklist."""
    base = Path(root)
    selected: list[str] = []
    for relative in repository_files(base, detection):
        if detection.is_noise_path(relative):
            continue
        path = base / relative
        try:
            with path.open("rb") as stream:
                prefix = stream.read(8192)
            if any(byte < 32 and byte not in (9, 10, 13) for byte in prefix):
                continue
            path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        selected.append(relative)
    return tuple(selected)
