"""Content hashes shared by persisted receipts."""

from __future__ import annotations

import hashlib
import json


def canonical_sha256(value: object) -> str:
    """Hash the deterministic JSON encoding of one value, rejecting non-finite numbers."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest()


def text_sha256(value: str) -> str:
    """Hash one exact text value."""
    return hashlib.sha256(value.encode()).hexdigest()
