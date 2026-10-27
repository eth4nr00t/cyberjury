"""Build stable candidate identities from reportable source anchors."""

from __future__ import annotations

import hashlib
import re


def canonical_category(category: str) -> str:
    """Normalize a model supplied class without treating qualifiers as new classes."""
    raw = category.strip()
    broad_class = re.sub(r"(?:[\s_-]*\([^()]*\))+$", "", raw).strip() or raw
    return broad_class.lower().replace(" ", "-").replace("_", "-")


def _normalized_file(file: str) -> str:
    return file.strip().replace("\\", "/")


def _normalized_category(category: str) -> str:
    return category.strip().lower().replace("_", "-")


def _anchor_text(anchor: tuple[str, int, str] | None) -> str:
    return "\x1e".join(map(str, anchor)) if anchor is not None else ""


def _attack_path_identity(*, target: str, path_anchor: str) -> str:
    normalized = " ".join(path_anchor.lower().split())
    material = "\x1f".join(("attack-path-v1", target, normalized))
    return f"path-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def candidate_identity(
    *,
    target: str,
    file: str,
    line: int,
    category: str,
    path_anchor: str,
    anchor: tuple[str, int, str] | None,
    root_cause: str,
    source_operation_id: str,
) -> str:
    """Identify one candidate from its location, class, anchors, and normalized root cause."""
    normalized_cause = " ".join(root_cause.lower().split())
    attack_path_id = _attack_path_identity(target=target, path_anchor=path_anchor)
    material = "\x1f".join(
        (
            "candidate-v1",
            target,
            _normalized_file(file),
            str(line),
            _normalized_category(category),
            normalized_cause,
            attack_path_id,
            _anchor_text(anchor),
            source_operation_id,
        )
    )
    return f"candidate-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def location_fingerprint(*, file: str, line: int, category: str, anchor: tuple[str, int, str] | None) -> str:
    """Identify one problem across runs by its location, class, and change anchor, independent of its wording."""
    material = "\x1f".join(
        ("fingerprint-v1", _normalized_file(file), str(line), _normalized_category(category), _anchor_text(anchor))
    )
    return f"fingerprint-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
