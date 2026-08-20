"""Expose the Web facts backend while keeping Tree-sitter grammars lazy."""

from cyberjury.profiles.web.facts.backend import TreeSitterFacts

__all__ = ["TreeSitterFacts"]
