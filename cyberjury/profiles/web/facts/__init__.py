"""Expose the Web facts backend while keeping tree-sitter grammars lazy."""

from cyberjury.profiles.web.facts.backend import TreeSitterCallGraph

__all__ = ["TreeSitterCallGraph"]
