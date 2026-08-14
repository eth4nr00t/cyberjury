"""Shared vulnerability knowledge loading, selection, and category normalization."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cyberjury.markdown_docs import iter_md_docs
from cyberjury.resources import VULNERABILITIES_DIR
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

_IMPACT_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


@dataclass(frozen=True, kw_only=True)
class Vulnerability:
    """One vulnerability class loaded from profile knowledge."""

    id: str
    title: str
    impact: str
    tags: tuple[str, ...]
    aliases: tuple[str, ...]
    selection_hints: tuple[str, ...]
    body: str


@dataclass(frozen=True, kw_only=True)
class KnowledgePack:
    """One bounded set of vulnerability classes for a model judgment."""

    items: tuple[Vulnerability, ...]

    @property
    def categories(self) -> tuple[str, ...]:
        """Preserve selected relevance order in prompts and failure records."""
        return tuple(item.id for item in self.items)

    @property
    def body(self) -> str:
        """Keep assigned class guidance complete inside one judgment."""
        return render_vulnerabilities(list(self.items))

    @property
    def label(self) -> str:
        """Describe this pack in failure and progress records."""
        return ", ".join(self.categories) if self.categories else "general review"


@dataclass(frozen=True, kw_only=True)
class KnowledgePlan:
    """Every selected class partitioned into complete judgment work."""

    selected: tuple[Vulnerability, ...]
    packs: tuple[KnowledgePack, ...]


@dataclass(frozen=True, kw_only=True)
class VulnerabilityCatalog:
    """One profile knowledge catalog used by every review target."""

    items: tuple[Vulnerability, ...]
    ids: frozenset[str]
    aliases: dict[str, str]

    @classmethod
    def load(cls, directory: str | Path = VULNERABILITIES_DIR) -> VulnerabilityCatalog:
        """Build the selection and category contract from one content directory."""
        items = tuple(load_vulnerabilities(directory))
        aliases = {_slug(alias): vulnerability.id for vulnerability in items for alias in vulnerability.aliases}
        return cls(
            items=items,
            ids=frozenset(vulnerability.id for vulnerability in items),
            aliases=aliases,
        )

    def select(self, evidence: str, context: str = "") -> list[Vulnerability]:
        """Select every class evidenced by source and grounded context."""
        return select_vulnerabilities(f"{evidence}\n{context}", list(self.items))

    def render(self, selected: list[Vulnerability]) -> str:
        """Render selected classes in their relevance order."""
        return render_vulnerabilities(selected)

    def knowledge_for(self, evidence: str, context: str = "") -> str:
        """Return the relevant class bodies for one judgment unit."""
        return self.render(self.select(evidence, context))

    def plan(
        self,
        evidence: str,
        context: str = "",
        *,
        max_chars: int = DEFAULT_REVIEW_SETTINGS.knowledge.target_chars_per_judgment,
        max_classes: int = DEFAULT_REVIEW_SETTINGS.knowledge.max_classes_per_judgment,
    ) -> KnowledgePlan:
        """Plan bounded judgments while retaining every selected class."""
        if max_chars < 1 or max_classes < 1:
            raise ValueError("knowledge pack limits must be positive")
        selected = tuple(self.select(evidence, context))
        groups: list[list[Vulnerability]] = []
        current: list[Vulnerability] = []
        current_size = 0
        separator_size = len("\n\n---\n\n")
        for item in selected:
            added = len(item.body) + (separator_size if current else 0)
            if current and (current_size + added > max_chars or len(current) >= max_classes):
                groups.append(current)
                current = []
                current_size = 0
                added = len(item.body)
            current.append(item)
            current_size += added
        if current:
            groups.append(current)
        if not groups:
            groups.append([])
        packs = tuple(KnowledgePack(items=tuple(group)) for group in groups)
        return KnowledgePlan(selected=selected, packs=packs)

    def canonicalize(self, category: str) -> str:
        """Fold aliases onto canonical ids without collapsing unknown classes."""
        if not category:
            return ""
        slug = _slug(category)
        return self.aliases.get(slug, slug)

    def close_category(self, category: str) -> str:
        """Map one category onto the closed report id set."""
        canonical = self.canonicalize(category)
        return canonical if not canonical or canonical in self.ids else "other"


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


def select_vulnerabilities(
    text: str,
    items: list[Vulnerability],
) -> list[Vulnerability]:
    """Keep every hint match so relevance ordering cannot reduce review coverage."""
    low = text.lower()
    matches = {v.id: tuple(hint for hint in v.selection_hints if hint.lower() in low) for v in items}
    matched = [v for v in items if matches[v.id]]
    matched.sort(
        key=lambda v: (
            -_IMPACT_RANK.get(v.impact, 1),
            -max(len(hint) for hint in matches[v.id]),
            -len(matches[v.id]),
            v.id,
        )
    )
    return matched


def allowed_categories(directory: str | Path = VULNERABILITIES_DIR) -> list[str]:
    """The closed set of finding categories: every vulnerability id.

    A finding's category must be one of these or 'other', so findings tie back to a class.
    """
    return [v.id for v in load_vulnerabilities(directory)]


def _slug(category: str) -> str:
    return category.strip().lower().replace("_", "-").replace(" ", "-")


def normalize_category(category: str, allowed: set[str]) -> str:
    """Map a model category onto the closed vulnerability id set.

    Lowercase and hyphenate the value, so `sql_injection` becomes `sql-injection`. Keep it if it is a
    known id, else `other`. Empty stays empty.
    """
    if not category:
        return ""
    slug = _slug(category)
    return slug if slug in allowed else "other"


def category_aliases(directory: str | Path = VULNERABILITIES_DIR) -> dict[str, str]:
    """A `{variant: canonical-id}` map from each class's declared `aliases`.

    Label variants a model emits for one class, such as `oracle` and `oracle-manipulation`,
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


def render_vulnerabilities(vulnerabilities: list[Vulnerability]) -> str:
    """Preserve relevance order because prompt position guides reviewer attention."""
    return "\n\n---\n\n".join(vulnerability.body for vulnerability in vulnerabilities)


def vulnerabilities_for_review(
    evidence: str,
    *,
    context: str = "",
    directory: str | Path = VULNERABILITIES_DIR,
    catalog: VulnerabilityCatalog | list[Vulnerability] | None = None,
) -> str:
    """Match source and grounded facts together so cross-function evidence selects knowledge."""
    if isinstance(catalog, VulnerabilityCatalog):
        return catalog.knowledge_for(evidence, context)
    items = load_vulnerabilities(directory) if catalog is None else catalog
    selected = select_vulnerabilities(f"{evidence}\n{context}", items)
    return render_vulnerabilities(selected)


def vulnerabilities_for_diff(
    diff: str,
    *,
    context: str = "",
    directory: str | Path = VULNERABILITIES_DIR,
) -> str:
    """Keep diff and repository judgments on the same selection contract."""
    return vulnerabilities_for_review(
        diff,
        context=context,
        directory=directory,
    )
