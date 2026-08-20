"""Coordinate web source analysis into the shared Facts contract."""

from __future__ import annotations

from pathlib import Path

from cyberjury.profiles.web.facts.analyzer import (
    LangSpec,
    SourceParseError,
    analyze_repository,
    available,
    grammar_for,
    load_specs,
)
from cyberjury.profiles.web.facts.graph import build_graph, facts_from_graph
from cyberjury.profiles.web.facts.resolver import (
    ancestor_directories,
    load_profile_detection,
    resolve_repository,
    reviewable_sources,
    scope_prefixes,
)
from cyberjury.review.facts import Facts, FactsBackend
from cyberjury.review.failures import BackendUnavailable


class TreeSitterFacts(FactsBackend):
    """Extract repository relationships from declarative Tree-sitter queries."""

    def __init__(self, specs: dict[str, LangSpec] | None = None) -> None:
        """Load the shipped analyzer contracts unless tests provide explicit ones."""
        self._specs = specs if specs is not None else load_specs()
        packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in self._specs.values()})
        self.install_hint = f"install {', '.join(packages)} to enable it"

    def available(self) -> bool:
        """Report whether the configured analyzer can run."""
        return available(self._specs)

    def extract(self, root: str | Path) -> Facts:
        """Analyze and resolve every reviewable source file or fail loud."""
        if not self.available():
            raise BackendUnavailable(self.install_hint)
        base = Path(root).resolve()
        sources = reviewable_sources(base, load_profile_detection(), self._specs)
        missing_grammars = sorted({spec.name for _path, _rel, spec in sources if grammar_for(spec) is None})
        if missing_grammars:
            raise BackendUnavailable(f"missing tree-sitter grammar for: {', '.join(missing_grammars)}")
        try:
            analyzed = analyze_repository(sources)
        except SourceParseError as exc:
            raise BackendUnavailable(f"facts extraction skipped reviewable source, {exc}") from exc
        known = {rel for _path, rel, _spec in sources}
        directories = {directory for rel in known for directory in ancestor_directories(rel)}
        resolved = resolve_repository(
            analyzed,
            known=known,
            directories=directories,
            specs=tuple(self._specs.values()),
            prefixes=scope_prefixes(base),
        )
        return facts_from_graph(build_graph(analyzed, resolved))


__all__ = ["TreeSitterFacts"]
