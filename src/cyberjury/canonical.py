"""Content hashes shared by persisted receipts."""

from __future__ import annotations

import hashlib
import json

_ENCODER = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def canonical_sha256(value: object) -> str:
    """Hash the deterministic JSON encoding of one value as it streams, rejecting non-finite numbers."""
    digest = hashlib.sha256()
    for chunk in _ENCODER.iterencode(value):
        digest.update(chunk.encode())
    return digest.hexdigest()


def text_sha256(value: str) -> str:
    """Hash one exact text value."""
    return hashlib.sha256(value.encode()).hexdigest()
