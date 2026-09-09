"""Deterministic security decision material for one review unit."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

KNOWLEDGE_ASSIGNMENT_SCHEMA = "cyberjury.knowledge-assignment/v1"
SECURITY_CATALOG_SCHEMA = 1

_ID = re.compile(r"^[a-z][a-z0-9-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value.strip()


def _identifier(value: object, label: str) -> str:
    identifier = _text(value, label)
    if not _ID.fullmatch(identifier):
        raise ValueError(f"{label} must be a lowercase hyphenated id")
    return identifier


def _slug(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _string_tuple(value: object, label: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be a string list")
    if required and not value:
        raise ValueError(f"{label} must not be empty")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} must not contain duplicates")
    return tuple(value)


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityCategory:
    """One public finding category and its taxonomy identity."""

    id: str
    title: str
    aliases: tuple[str, ...]
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject category metadata that cannot support stable output."""
        object.__setattr__(self, "id", _identifier(self.id, "security category id"))
        object.__setattr__(self, "title", _text(self.title, "security category title"))
        for label, values in (("aliases", self.aliases), ("tags", self.tags)):
            if not isinstance(values, tuple) or not all(isinstance(value, str) and value for value in values):
                raise ValueError(f"security category {label} must be a string tuple")
            if len(values) != len(set(values)):
                raise ValueError(f"security category {label} must not contain duplicates")
        if not self.tags:
            raise ValueError("security category tags must not be empty")

    @classmethod
    def from_entry(cls, category_id: object, value: object) -> SecurityCategory:
        """Load one map entry without accepting silent schema expansion."""
        fields = {"title", "aliases", "tags"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("security category must contain the exact supported fields")
        return cls(
            id=_identifier(category_id, "security category id"),
            title=_text(value["title"], "security category title"),
            aliases=_string_tuple(value["aliases"], "security category aliases"),
            tags=_string_tuple(value["tags"], "security category tags", required=True),
        )

    def to_dict(self) -> dict[str, object]:
        """Return the strict catalog form without repeating the map key."""
        return {"title": self.title, "aliases": list(self.aliases), "tags": list(self.tags)}


@dataclass(frozen=True, slots=True, kw_only=True)
class DecisionRule:
    """One compact security predicate with its evidence and reporting boundary."""

    id: str
    category_id: str
    title: str
    security_property: str
    required_evidence: str
    refuting_evidence: str
    report_boundary: str

    def __post_init__(self) -> None:
        """Reject a rule that cannot support both confirmation and refutation."""
        object.__setattr__(self, "id", _identifier(self.id, "decision rule id"))
        object.__setattr__(self, "category_id", _identifier(self.category_id, "decision rule category id"))
        for field in (
            "title",
            "security_property",
            "required_evidence",
            "refuting_evidence",
            "report_boundary",
        ):
            label = field.replace("_", " ")
            object.__setattr__(self, field, _text(getattr(self, field), f"decision rule {label}"))

    def to_dict(self) -> dict[str, str]:
        """Return the strict data form used by profile content."""
        return {
            "id": self.id,
            "category_id": self.category_id,
            "title": self.title,
            "security_property": self.security_property,
            "required_evidence": self.required_evidence,
            "refuting_evidence": self.refuting_evidence,
            "report_boundary": self.report_boundary,
        }

    @classmethod
    def from_dict(cls, value: object) -> DecisionRule:
        """Load one rule without accepting silent schema expansion."""
        fields = {
            "id",
            "category_id",
            "title",
            "security_property",
            "required_evidence",
            "refuting_evidence",
            "report_boundary",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("decision rule must contain the exact supported fields")
        return cls(**value)

    def render(self) -> str:
        """Render the complete decision contract without examples or background prose."""
        return (
            f"## {self.id}: {self.title}\n"
            f"Finding category: {self.category_id}\n"
            f"Security property: {self.security_property}\n"
            f"Required evidence: {self.required_evidence}\n"
            f"Refuting evidence: {self.refuting_evidence}\n"
            f"Report boundary: {self.report_boundary}"
        )

    def render_index(self) -> str:
        """Render the minimum behavior identity and security property used for discovery."""
        return f"- {self.id} [{self.category_id}]: {self.security_property}"


@dataclass(frozen=True, slots=True, kw_only=True)
class BriefDocument:
    """The security reasoning kernel included in a review brief."""

    id: str
    body: str

    def __post_init__(self) -> None:
        """Keep kernel identity and content suitable for stable rendering."""
        object.__setattr__(self, "id", _identifier(self.id, "brief document id"))
        object.__setattr__(self, "body", _text(self.body, "brief document body"))


@dataclass(frozen=True, slots=True)
class GeneralBrief:
    """One empty knowledge task for a reviewer without a profile brief."""

    body: str = ""
    label: str = "general review"


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewBrief:
    """The complete immutable security knowledge presented to one judgment."""

    kernel: BriefDocument
    categories: tuple[SecurityCategory, ...]
    rules: tuple[DecisionRule, ...]

    def __post_init__(self) -> None:
        """Require one kernel and unambiguous ordered content identities."""
        if not isinstance(self.kernel, BriefDocument):
            raise ValueError("review brief requires one kernel document")
        if (
            not isinstance(self.categories, tuple)
            or not self.categories
            or not all(isinstance(category, SecurityCategory) for category in self.categories)
        ):
            raise ValueError("review brief categories must be a nonempty security category tuple")
        if tuple(category.id for category in self.categories) != tuple(
            sorted(category.id for category in self.categories)
        ):
            raise ValueError("review brief categories must use stable id order")
        if len({category.id for category in self.categories}) != len(self.categories):
            raise ValueError("review brief category ids must be unique")
        if (
            not isinstance(self.rules, tuple)
            or not self.rules
            or not all(isinstance(rule, DecisionRule) for rule in self.rules)
        ):
            raise ValueError("review brief rules must be a nonempty decision rule tuple")
        if tuple(rule.id for rule in self.rules) != tuple(sorted(rule.id for rule in self.rules)):
            raise ValueError("review brief rules must use stable id order")
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("review brief rule ids must be unique")
        rule_categories = {rule.category_id for rule in self.rules}
        if rule_categories != set(self.category_ids):
            missing = set(self.category_ids).difference(rule_categories)
            unknown = rule_categories.difference(self.category_ids)
            details = []
            if missing:
                details.append(f"missing rule categories: {', '.join(sorted(missing))}")
            if unknown:
                details.append(f"unknown rule categories: {', '.join(sorted(unknown))}")
            raise ValueError(f"review brief category coverage is invalid. {'. '.join(details)}")
        aliases: dict[str, str] = {}
        for category in self.categories:
            for alias in category.aliases:
                normalized = _slug(alias)
                if normalized in self.category_ids:
                    raise ValueError(f"security category alias {alias!r} collides with a category id")
                existing = aliases.get(normalized)
                if existing is not None and existing != category.id:
                    raise ValueError(f"security category alias {alias!r} has multiple owners")
                aliases[normalized] = category.id

    @property
    def rule_ids(self) -> tuple[str, ...]:
        """Expose the complete category coverage in rendered order."""
        return tuple(rule.id for rule in self.rules)

    @property
    def category_ids(self) -> frozenset[str]:
        """Return every public report category in the canonical catalog."""
        return frozenset(category.id for category in self.categories)

    @property
    def category_aliases(self) -> dict[str, str]:
        """Return normalized output aliases owned by their canonical category."""
        return {_slug(alias): category.id for category in self.categories for alias in category.aliases}

    @property
    def category_titles(self) -> dict[str, str]:
        """Return human readable category titles by canonical id."""
        return {category.id: category.title for category in self.categories}

    def canonicalize_category(self, category: str) -> str:
        """Fold one model category onto the canonical catalog without hiding unknown values."""
        if not category:
            return ""
        normalized = _slug(category)
        return self.category_aliases.get(normalized, normalized)

    def close_category(self, category: str) -> str:
        """Map one model category onto the closed public report set."""
        canonical = self.canonicalize_category(category)
        return canonical if not canonical or canonical in self.category_ids else "other"

    @property
    def rule_categories(self) -> dict[str, str]:
        """Map each behavior identity to its report category."""
        return {rule.id: rule.category_id for rule in self.rules}

    def expand_rule_requests(self, requests: tuple[str, ...]) -> tuple[str, ...]:
        """Expand rule or category requests into stable behavior ids."""
        known = {*self.rule_ids, *self.category_ids}
        unknown = set(requests).difference(known)
        if unknown:
            raise ValueError(f"decision rule request contains unknown ids: {', '.join(sorted(unknown))}")
        requested = set(requests)
        return tuple(rule.id for rule in self.rules if rule.id in requested or rule.category_id in requested)

    @property
    def body(self) -> str:
        """Expose the rendered discovery brief to target prompt adapters."""
        return self.render()

    @property
    def label(self) -> str:
        """Name the single deterministic review brief judgment."""
        return "security rule index"

    @property
    def content_sha256(self) -> str:
        """Identify the exact discovery brief sent to a model."""
        return _sha256(self.render())

    def render(self) -> str:
        """Render the stable discovery input without detailed rule expansion."""
        rules = "\n".join(rule.render_index() for rule in self.rules)
        blocks = [f"# Security Reasoning Kernel\n{self.kernel.body}"]
        blocks.append(f"# Security Rule Index\n{rules}")
        return "\n\n".join(blocks)

    def render_followup(self) -> str:
        """Render complete category coverage without repeating unrelated rule details."""
        categories = "\n".join(f"- {category.id}: {category.title}" for category in self.categories)
        return (
            f"# Security Reasoning Kernel\n{self.kernel.body}\n\n"
            f"# Security Category Index\n{categories}\n\n"
            "Request a category id when new evidence requires behavior rules outside the rules already delivered."
        )

    def prompt_body(self, revision: int) -> str:
        """Use full behavior discovery once, then retain compact category coverage."""
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValueError("review brief prompt revision must be a nonnegative integer")
        return self.render() if revision == 0 else self.render_followup()

    def render_rule_details(self, rule_ids: tuple[str, ...]) -> str:
        """Render exact requested decision contracts in catalog order."""
        if not isinstance(rule_ids, tuple) or not rule_ids or not all(isinstance(value, str) for value in rule_ids):
            raise ValueError("detailed decision rule ids must be a nonempty string tuple")
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("detailed decision rule ids must be unique")
        requested = set(rule_ids)
        unknown = requested.difference(self.rule_ids)
        if unknown:
            raise ValueError(f"detailed decision rule ids are unknown: {', '.join(sorted(unknown))}")
        return "\n\n".join(rule.render() for rule in self.rules if rule.id in requested)

    def validate_rule_binding(self, rule_id: str, category_id: str) -> str:
        """Return a valid behavior id bound to the finding category."""
        normalized_rule = rule_id.strip() if isinstance(rule_id, str) else ""
        normalized_category = category_id.strip() if isinstance(category_id, str) else ""
        if normalized_category not in {*self.category_ids, "other"}:
            raise ValueError(f"finding category is unknown: {normalized_category}")
        if normalized_category == "other":
            if normalized_rule:
                raise ValueError("an other finding cannot claim a profile decision rule")
            return ""
        if not normalized_rule:
            raise ValueError("a profile finding requires a decision_rule_id")
        rule = next((item for item in self.rules if item.id == normalized_rule), None)
        if rule is None:
            raise ValueError(f"decision_rule_id is unknown: {normalized_rule}")
        if rule.category_id != normalized_category:
            raise ValueError(
                f"decision_rule_id {normalized_rule} belongs to {rule.category_id}, not {normalized_category}"
            )
        return normalized_rule

    def details_for_binding(self, rule_id: str, category_id: str) -> str:
        """Render the exact decision contract used to verify one finding."""
        validated = self.validate_rule_binding(rule_id, category_id)
        return self.render_rule_details((validated,)) if validated else ""

    def details_for_bindings(self, bindings: tuple[tuple[str, str], ...]) -> str:
        """Render each valid candidate rule once in stable catalog order."""
        rule_ids = tuple(
            dict.fromkeys(
                validated
                for rule_id, category_id in bindings
                if (validated := self.validate_rule_binding(rule_id, category_id))
            )
        )
        return self.render_rule_details(rule_ids) if rule_ids else ""


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeAssignmentReceipt:
    """The immutable review brief assigned to every grounded unit."""

    profile_binding_sha256: str
    grounding_receipt_sha256: str
    unit_ids: tuple[str, ...]
    kernel_id: str
    category_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    rendered_chars: int
    content_sha256: str
    security_catalog_sha256: str
    receipt_sha256: str

    def __post_init__(self) -> None:
        """Reject a receipt that cannot prove one exact downstream input."""
        for field in (
            "profile_binding_sha256",
            "grounding_receipt_sha256",
            "content_sha256",
            "security_catalog_sha256",
            "receipt_sha256",
        ):
            if not isinstance(getattr(self, field), str) or not _SHA256.fullmatch(getattr(self, field)):
                raise ValueError(f"review brief {field} must be a SHA-256 digest")
        if not isinstance(self.unit_ids, tuple) or not all(isinstance(value, str) and value for value in self.unit_ids):
            raise ValueError("knowledge assignment unit_ids must be a string tuple")
        if len(self.unit_ids) != len(set(self.unit_ids)):
            raise ValueError("knowledge assignment unit_ids must be unique")
        _identifier(self.kernel_id, "review brief kernel id")
        for label, values in (("category ids", self.category_ids), ("rule ids", self.rule_ids)):
            if not isinstance(values, tuple) or not all(
                isinstance(value, str) and _ID.fullmatch(value) for value in values
            ):
                raise ValueError(f"review brief {label} must be an id tuple")
            if len(values) != len(set(values)):
                raise ValueError(f"review brief {label} must be unique")
        if isinstance(self.rendered_chars, bool) or not isinstance(self.rendered_chars, int) or self.rendered_chars < 1:
            raise ValueError("review brief rendered_chars must be a positive integer")
        if self.receipt_sha256 != _sha256(_canonical_json(self.semantic_dict())):
            raise ValueError("review brief receipt hash does not match its content")

    @classmethod
    def create(
        cls,
        brief: ReviewBrief,
        *,
        profile_binding_sha256: str,
        grounding_receipt_sha256: str,
        unit_ids: tuple[str, ...],
    ) -> KnowledgeAssignmentReceipt:
        """Bind one rendered brief to its profile and complete grounded worklist."""
        rendered = brief.render()
        semantic: dict[str, object] = {
            "profile_binding_sha256": profile_binding_sha256,
            "grounding_receipt_sha256": grounding_receipt_sha256,
            "unit_ids": unit_ids,
            "kernel_id": brief.kernel.id,
            "category_ids": tuple(sorted(brief.category_ids)),
            "rule_ids": brief.rule_ids,
            "rendered_chars": len(rendered),
            "content_sha256": brief.content_sha256,
            "security_catalog_sha256": _sha256(
                _canonical_json(
                    {
                        "schema": SECURITY_CATALOG_SCHEMA,
                        "categories": {category.id: category.to_dict() for category in brief.categories},
                        "rules": [rule.to_dict() for rule in brief.rules],
                    }
                )
            ),
        }
        return cls(**semantic, receipt_sha256=_sha256(_canonical_json(semantic)))

    def semantic_dict(self) -> dict[str, object]:
        """Return the response-affecting receipt fields."""
        return {
            "profile_binding_sha256": self.profile_binding_sha256,
            "grounding_receipt_sha256": self.grounding_receipt_sha256,
            "unit_ids": self.unit_ids,
            "kernel_id": self.kernel_id,
            "category_ids": self.category_ids,
            "rule_ids": self.rule_ids,
            "rendered_chars": self.rendered_chars,
            "content_sha256": self.content_sha256,
            "security_catalog_sha256": self.security_catalog_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        """Return the strict persistent form."""
        return {
            "schema": KNOWLEDGE_ASSIGNMENT_SCHEMA,
            **self.semantic_dict(),
            "unit_ids": list(self.unit_ids),
            "category_ids": list(self.category_ids),
            "rule_ids": list(self.rule_ids),
            "receipt_sha256": self.receipt_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> KnowledgeAssignmentReceipt:
        """Load and verify one persisted receipt."""
        fields = {
            "schema",
            "profile_binding_sha256",
            "grounding_receipt_sha256",
            "unit_ids",
            "kernel_id",
            "category_ids",
            "rule_ids",
            "rendered_chars",
            "content_sha256",
            "security_catalog_sha256",
            "receipt_sha256",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("review brief receipt must contain the exact supported fields")
        if value["schema"] != KNOWLEDGE_ASSIGNMENT_SCHEMA:
            raise ValueError("knowledge assignment schema is unsupported")
        data = {key: item for key, item in value.items() if key != "schema"}
        for field in ("unit_ids", "category_ids", "rule_ids"):
            if not isinstance(data[field], list):
                raise ValueError(f"review brief receipt {field} must be a list")
            data[field] = tuple(data[field])
        return cls(**data)


def load_security_catalog(path: str | Path) -> tuple[tuple[SecurityCategory, ...], tuple[DecisionRule, ...]]:
    """Load one canonical category and behavior catalog in stable id order."""
    source = Path(path)
    try:
        value = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"security catalog file {source} could not be loaded: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "categories", "rules"}:
        raise ValueError(f"security catalog file {source} must contain schema, categories, and rules")
    if value["schema"] != SECURITY_CATALOG_SCHEMA:
        raise ValueError(f"security catalog file {source} has an unsupported schema")
    raw_categories = value["categories"]
    if not isinstance(raw_categories, dict) or not raw_categories:
        raise ValueError(f"security catalog file {source} must contain a nonempty category map")
    categories = tuple(
        sorted(
            (SecurityCategory.from_entry(category_id, data) for category_id, data in raw_categories.items()),
            key=lambda category: category.id,
        )
    )
    if not isinstance(value["rules"], list) or not value["rules"]:
        raise ValueError(f"security catalog file {source} must contain a nonempty rule list")
    rules = tuple(sorted((DecisionRule.from_dict(item) for item in value["rules"]), key=lambda rule: rule.id))
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError(f"security catalog file {source} has duplicate rule ids")
    return categories, rules


def load_review_brief(
    *,
    kernel_id: str,
    kernel_file: str | Path,
    catalog_file: str | Path,
) -> ReviewBrief:
    """Load the complete deterministic profile knowledge used by one judgment."""
    source = Path(kernel_file)
    try:
        kernel = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"security kernel file {source} could not be loaded: {exc}") from exc
    categories, rules = load_security_catalog(catalog_file)
    return ReviewBrief(
        kernel=BriefDocument(id=kernel_id, body=kernel),
        categories=categories,
        rules=rules,
    )
