"""Build stable candidate identities from reportable source anchors."""

from __future__ import annotations

import hashlib
import re


def canonical_category(category: str) -> str:
    """Normalize a model supplied class without treating qualifiers as new classes."""
    raw = category.strip()
    broad_class = re.sub(r"(?:[\s_-]*\([^()]*\))+$", "", raw).strip() or raw
    return broad_class.lower().replace(" ", "-").replace("_", "-")


def _attack_path_identity(*, target: str, path_anchor: str) -> str:
    normalized = " ".join(path_anchor.lower().split())
    material = "\x1f".join(("attack-path-v1", target, normalized))
    return f"path-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def candidate_identity(
    *,
    target: str,
    file: str,
    line: int | None,
    category: str,
    path_anchor: str,
    anchor: tuple[str, int, str] | None = None,
    root_cause: str = "",
    source_operation_id: str = "",
) -> str:
    """Identify one candidate from its location, class, anchors, and normalized root cause.

    `root_cause` is model supplied prose. Callers keep it so distinct findings that share
    every structured anchor still receive distinct ids.
    """
    normalized_file = file.strip().replace("\\", "/")
    normalized_category = category.strip().lower().replace("_", "-")
    normalized_cause = " ".join(root_cause.lower().split())
    attack_path_id = _attack_path_identity(target=target, path_anchor=path_anchor)
    location = str(line) if line is not None else ""
    anchor_text = "\x1e".join(map(str, anchor)) if anchor is not None else ""
    material = "\x1f".join(
        (
            "candidate-v1",
            target,
            normalized_file,
            location,
            normalized_category,
            normalized_cause,
            attack_path_id,
            anchor_text,
            source_operation_id,
        )
    )
    return f"candidate-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
