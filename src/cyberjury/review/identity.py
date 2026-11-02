"""Stable candidate identities built from reportable source anchors."""

from __future__ import annotations

import hashlib
import re

from cyberjury.review.paths import normalized_location_path


def canonical_category(category: str) -> str:
    """Normalize a model supplied class without treating qualifiers as new classes."""
    raw = category.strip()
    broad_class = re.sub(r"(?:[\s_-]*\([^()]*\))+$", "", raw).strip() or raw
    return broad_class.lower().replace(" ", "-").replace("_", "-")


def _anchor_text(anchor: tuple[str, int, str] | None) -> str:
    return "\x1e".join(map(str, anchor)) if anchor is not None else ""


def candidate_identity(
    *,
    target: str,
    file: str,
    line: int,
    category: str,
    entrypoint: str,
    anchor: tuple[str, int, str] | None,
    title: str,
    source_operation_id: str,
) -> str:
    """Identify one candidate from its location, class, entrypoint, anchors, and normalized title."""
    normalized_title = " ".join(title.lower().split())
    material = "\x1f".join(
        (
            "candidate-v1",
            target,
            normalized_location_path(file),
            str(line),
            category,
            normalized_title,
            " ".join(entrypoint.lower().split()),
            _anchor_text(anchor),
            source_operation_id,
        )
    )
    return f"candidate-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
