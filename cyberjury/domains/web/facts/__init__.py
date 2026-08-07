"""The web domain's facts backend: a function-level call graph from tree-sitter.

Kept in its own package so the grammars are imported only when a run enables facts, the
way the evm domain isolates Slither.
"""

from cyberjury.domains.web.facts.callgraph import TreeSitterCallGraph

__all__ = ["TreeSitterCallGraph"]
