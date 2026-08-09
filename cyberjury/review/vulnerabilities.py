"""Shared vulnerability knowledge loading, selection, and category normalization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyberjury.markdown_docs import iter_md_docs
from cyberjury.resources import VULNERABILITIES_DIR

_IMPACT_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


@dataclass(frozen=True, kw_only=True)
class Vulnerability:
    """One vulnerability class loaded from domain knowledge."""

    id: str
    title: str
    impact: str
    tags: tuple[str, ...]
    aliases: tuple[str, ...]
    selection_hints: tuple[str, ...]
    body: str


def load_vulnerabilities(directory: str | Path = VULNERABILITIES_DIR) -> list[Vulnerability]:
    """Load vulnerabilities."""
    items = [
        Vulnerability(
            id=path.stem,
            title=str(meta.get("title", path.stem)),
            impact=str(meta.get("impact", "MEDIUM")).upper(),
            tags=tuple(meta.get("tags", [])),
            aliases=tuple(str(a) for a in meta.get("aliases", [])),
            selection_hints=tuple(str(t) for t in meta.get("selection_hints", [])),
            body=body,
        )
        for path, meta, body in iter_md_docs(directory)
    ]
    return sorted(items, key=lambda v: v.id)


def select_vulnerabilities(diff: str, items: list[Vulnerability], *, limit: int = 6) -> list[Vulnerability]:
    """The classes whose selection hints appear in the diff, most-severe first, capped."""
    low = diff.lower()
    matched = [v for v in items if any(t.lower() in low for t in v.selection_hints)]
    matched.sort(key=lambda v: (_IMPACT_RANK.get(v.impact, 1), v.id), reverse=True)
    return matched[:limit]


def allowed_categories(directory: str | Path = VULNERABILITIES_DIR) -> list[str]:
    """The closed set of finding categories: every vulnerability id.

    A finding's category must be one of these or 'other', so findings tie back to a class.
    """
    return [v.id for v in load_vulnerabilities(directory)]


def _slug(category: str) -> str:
    return category.strip().lower().replace("_", "-").replace(" ", "-")


def normalize_category(category: str, allowed: set[str]) -> str:
    """Map a model-emitted category onto the closed vulnerability-id set.

    lowercase and hyphenate, so `sql_injection` becomes `sql-injection`, keep it if it is a
    known id, else `other`. Empty stays empty.
    """
    if not category:
        return ""
    slug = _slug(category)
    return slug if slug in allowed else "other"


def category_aliases(directory: str | Path = VULNERABILITIES_DIR) -> dict[str, str]:
    """A `{variant: canonical-id}` map from each class's declared `aliases`.

    so the label variants a model emits for one class, `oracle` and `oracle-manipulation`
    for `oracle-price-manipulation`, fold onto the id. The canonical id is its own identity
    and is not listed as an alias.
    """
    out: dict[str, str] = {}
    for v in load_vulnerabilities(directory):
        for alias in v.aliases:
            out[_slug(alias)] = v.id
    return out


def canonical_category(category: str, aliases: dict[str, str]) -> str:
    """Fold a model-emitted category onto its canonical id through `aliases`.

    Unlike `normalize_category` an unknown class stays itself rather than becoming `other`,
    so two distinct unknown classes at one location are never merged. Empty stays empty.
    """
    if not category:
        return ""
    slug = _slug(category)
    return aliases.get(slug, slug)


def vulnerability_knowledge(
    text: str,
    *,
    directory: str | Path = VULNERABILITIES_DIR,
    limit: int | None = 6,
) -> str:
    """Render the selected vulnerability bodies for a review target.

    `limit=None` keeps every class, preserving Repository Review's current prompt behavior
    until the narrower selector has been backtested.
    """
    items = load_vulnerabilities(directory)
    selected = items if limit is None else select_vulnerabilities(text, items, limit=limit)
    return "\n\n---\n\n".join(v.body for v in selected)


def vulnerabilities_for_diff(diff: str, *, directory: str | Path = VULNERABILITIES_DIR, limit: int = 6) -> str:
    """The vulnerability class bodies relevant to one diff prompt."""
    return vulnerability_knowledge(diff, directory=directory, limit=limit)
