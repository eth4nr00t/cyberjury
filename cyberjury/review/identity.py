"""Build stable candidate identities from reportable source anchors."""

from __future__ import annotations

import hashlib


def attack_path_identity(*, target: str, path_anchor: str) -> str:
    """Identify one entry path independently from its security violations."""
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
) -> str:
    """Identify one candidate without model controlled descriptive prose."""
    normalized_file = file.strip().replace("\\", "/")
    normalized_category = category.strip().lower().replace("_", "-")
    attack_path_id = attack_path_identity(target=target, path_anchor=path_anchor)
    location = str(line) if line is not None else ""
    anchor_text = "\x1e".join(map(str, anchor)) if anchor is not None else ""
    material = "\x1f".join(
        (
            "candidate-v1",
            target,
            normalized_file,
            location,
            normalized_category,
            attack_path_id,
            anchor_text,
        )
    )
    return f"candidate-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"
