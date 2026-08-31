"""Coordinate web source analysis into the shared Facts contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cyberjury.profiles.web.facts.analyzer import (
    AnalyzerConfigurationError,
    LangSpec,
    SourceReadError,
    analyze_repository,
    available,
    grammar_for,
    load_specs,
)
from cyberjury.profiles.web.facts.graph import build_graph, facts_from_graph
from cyberjury.profiles.web.facts.resolver import (
    collect_navigation_evidence,
    load_profile_detection,
    reviewable_sources,
)
from cyberjury.review.facts import FactLimitation, Facts, FactsBackend
from cyberjury.review.failures import BackendUnavailable


class TreeSitterFacts(FactsBackend):
    """Extract deterministic repository syntax evidence from declarative Tree-sitter queries."""

    def __init__(self, specs: dict[str, LangSpec] | None = None) -> None:
        """Load the shipped analyzer contracts unless tests provide explicit ones."""
        self._specs = specs if specs is not None else load_specs()
        self._cache_identity: str | None = None
        packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in self._specs.values()})
        self.install_hint = f"install {', '.join(packages)} to enable it"

    def available(self) -> bool:
        """Report whether the configured analyzer can run."""
        return available(self._specs)

    def cache_identity(self) -> str:
        """Bind cache entries to effective queries, grammars, and package versions."""
        if self._cache_identity is not None:
            return self._cache_identity
        packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in self._specs.values()})
        versions = {}
        for package in packages:
            try:
                versions[package] = version(package)
            except PackageNotFoundError:
                versions[package] = "missing"
        payload = {
            "backend": super().cache_identity(),
            "specs": {name: asdict(spec) for name, spec in sorted(self._specs.items())},
            "versions": versions,
        }
        self._cache_identity = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return self._cache_identity

    def extract(self, root: str | Path) -> Facts:
        """Extract complete source evidence and disclose source level limitations."""
        if not self.available():
            raise BackendUnavailable(self.install_hint)
        base = Path(root).resolve()
        detection = load_profile_detection()
        sources = reviewable_sources(base, detection, self._specs)
        missing_grammars = sorted({spec.name for _path, _rel, spec in sources if grammar_for(spec) is None})
        if missing_grammars:
            raise BackendUnavailable(f"missing tree-sitter grammar for: {', '.join(missing_grammars)}")
        try:
            analyzed = analyze_repository(sources)
        except (AnalyzerConfigurationError, SourceReadError) as exc:
            raise BackendUnavailable(str(exc)) from exc
        navigation = collect_navigation_evidence(base, analyzed, detection)
        facts = facts_from_graph(build_graph(analyzed, navigation))
        limitations = tuple(
            FactLimitation(
                source=item.source,
                analyzer=item.analyzer,
                reason=item.reason,
                line=item.line,
                column=item.column,
            )
            for item in analyzed.limitations
        )
        limitations = tuple(dict.fromkeys((*limitations, *navigation.limitations)))
        return Facts(summary=facts.summary, data=facts.data, limitations=limitations)


__all__ = ["TreeSitterFacts"]
