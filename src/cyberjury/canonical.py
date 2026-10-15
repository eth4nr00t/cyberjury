"""Canonical encodings and validators shared by persisted receipts."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath


def canonical_json(value: object) -> str:
    """Serialize JSON deterministically and reject non-finite numbers."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_sha256(value: object) -> str:
    """Hash the canonical JSON encoding of one value."""
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def text_sha256(value: str) -> str:
    """Hash one exact text value."""
    return hashlib.sha256(value.encode()).hexdigest()


def normalized_repository_path(path: object, label: str) -> str:
    """Return a nonempty relative POSIX repository path or reject it with the labeled error."""
    if not isinstance(path, str):
        raise ValueError(f"{label} must be a normalized repository path")
    normalized = PurePosixPath(path)
    if (
        not path
        or path == "."
        or path.startswith("/")
        or "\\" in path
        or normalized.as_posix() != path
        or ".." in normalized.parts
    ):
        raise ValueError(f"{label} must be a normalized repository path")
    return path
