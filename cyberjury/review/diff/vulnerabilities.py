"""Compatibility exports for shared vulnerability knowledge helpers."""

from cyberjury.review.vulnerabilities import (
    Vulnerability,
    allowed_categories,
    canonical_category,
    category_aliases,
    load_vulnerabilities,
    normalize_category,
    select_vulnerabilities,
    vulnerabilities_for_diff,
    vulnerability_knowledge,
)

__all__ = [
    "Vulnerability",
    "allowed_categories",
    "canonical_category",
    "category_aliases",
    "load_vulnerabilities",
    "normalize_category",
    "select_vulnerabilities",
    "vulnerabilities_for_diff",
    "vulnerability_knowledge",
]
