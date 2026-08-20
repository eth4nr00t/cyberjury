"""Coordinate EVM source analysis into the shared Facts contract."""

from __future__ import annotations

from pathlib import Path

from cyberjury.profiles.evm.facts.analyzer import INSTALL_HINT, analyze, available
from cyberjury.profiles.evm.facts.graph import build_graph, facts_from_graph
from cyberjury.profiles.evm.facts.resolver import (
    analyzer_target,
    load_profile_detection,
    resolve_compile_root,
    resolve_project,
)
from cyberjury.review.facts import Facts, FactsBackend
from cyberjury.review.failures import BackendUnavailable


class SlitherFacts(FactsBackend):
    """Extract EVM facts through the profile analyzer and graph pipeline."""

    install_hint = INSTALL_HINT

    def available(self) -> bool:
        """Report whether the configured analyzer can run."""
        return available()

    def extract(self, root: str | Path) -> Facts:
        """Analyze and resolve the review scope or fail loud."""
        if not self.available():
            raise BackendUnavailable(self.install_hint)
        review_root = Path(root).resolve()
        compile_root = resolve_compile_root(review_root)
        analyzed = analyze(analyzer_target(review_root, compile_root))
        resolved = resolve_project(analyzed, review_root, load_profile_detection())
        graph = build_graph(resolved)
        if compile_root != review_root and not graph.contracts:
            raise BackendUnavailable(
                f"the compile at {compile_root} succeeded but produced no contract under the review "
                f"scope {review_root}, so check that the project compiles the reviewed directory"
            )
        return facts_from_graph(graph)


__all__ = ["SlitherFacts"]
