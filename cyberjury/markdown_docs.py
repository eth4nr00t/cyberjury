"""Shared markdown-doc plumbing: frontmatter parsing and directory loading.

Both the vulnerability classes under `knowledge/vulnerabilities` and the guides under
`knowledge/guides/languages`, `knowledge/guides/frameworks`, and `knowledge/guides/protocols` are markdown files with a
YAML frontmatter and a body. This holds only that shared mechanics. Each caller
builds its own typed record and applies its own selection, since vulnerability
classes select by trigger text and guides select by detection signals.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import yaml


def md_field(text: str, key: str) -> str | None:
    """Value of a `- key: value` line in a markdown body, or None when absent. `key`
    is embedded as a regex, so a caller may pass an alternation. The seeded-doc readers
    in the repository engine and the gate share this pattern so they cannot drift apart."""
    m = re.search(rf"(?im)^\s*-?\s*{key}\s*:\s*(.+?)\s*$", text)
    return m.group(1).strip() if m else None


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Return the frontmatter dict and the body. A doc with no `---` frontmatter yields an empty dict and the text."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) == 3:
            meta = yaml.safe_load(parts[1]) or {}
            return (meta if isinstance(meta, dict) else {}), parts[2].strip()
    return {}, text


def iter_md_docs(directory: str | Path) -> Iterator[tuple[Path, dict, str]]:
    """Yield the path, meta, and body for each `*.md` under `directory`, recursively,
    skipping an `index.md`. This lets a guide axis group files into subdirectories,
    for example frameworks by language, and lets a directory carry a plain index
    that is not loaded as a class. Yields nothing if the directory does not exist.
    Sorted by path for determinism."""
    root = Path(directory)
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*.md")):
        if path.name == "index.md":
            continue
        meta, body = parse_frontmatter(path.read_text(encoding="utf-8"))
        yield path, meta, body
