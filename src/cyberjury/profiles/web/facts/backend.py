"""Coordinate web source analysis into the shared Facts contract."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, replace
from functools import cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cyberjury.canonical import canonical_sha256
from cyberjury.profiles.web.facts.analyzer import (
    AnalyzerConfigurationError,
    LangSpec,
    SourceReadError,
    analyze_repository,
    load_specs,
    validate_specs,
)
from cyberjury.profiles.web.facts.graph import facts_from_repository
from cyberjury.profiles.web.facts.resolver import collect_navigation_evidence, reviewable_sources
from cyberjury.review.facts import (
    FactLimitation,
    Facts,
    FactsBackend,
    FactsResolutionReceipt,
    NativeAnalysisReceipt,
)
from cyberjury.review.failures import BackendUnavailable
from cyberjury.review.relationships import RelationshipEvidenceBundle


@cache
def _installed_versions(packages: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    versions: list[tuple[str, str]] = []
    for package in packages:
        try:
            value = version(package)
        except PackageNotFoundError:
            value = "missing"
        versions.append((package, value))
    return tuple(versions)


class TreeSitterFacts(FactsBackend):
    """Extract deterministic repository syntax evidence from declarative Tree-sitter queries."""

    def __init__(
        self,
        specs: dict[str, LangSpec] | None = None,
        *,
        detection_file: Path | None = None,
        queries_file: Path | None = None,
    ) -> None:
        """Load the shipped analyzer contracts unless tests provide explicit ones."""
        profile_root = Path(__file__).resolve().parents[1]
        self._detection_file = detection_file or profile_root / "detection.yaml"
        self._queries_file = queries_file or Path(__file__).resolve().parent / "queries.yaml"
        self._explicit_specs = specs is not None
        self._specs = specs if specs is not None else load_specs(self._queries_file)
        self._cache_identity: str | None = None

    def bind_content(self, content):
        """Bind detection and query data to one materialized profile snapshot."""
        specs = self._specs if self._explicit_specs else None
        return TreeSitterFacts(
            specs,
            detection_file=content.detection_file,
            queries_file=content.root / "facts" / "queries.yaml",
        )

    def validate_content(self, content) -> None:
        """Require valid analyzer queries whose languages equal the detection parser inputs."""
        from cyberjury.detection import load_detection

        specs = load_specs(content.root / "facts" / "queries.yaml")
        validate_specs(specs)
        parsed = {extension for spec in specs.values() for extension in spec.extensions}
        if parsed != load_detection(content.detection_file).source_extensions:
            raise ValueError("detection source_extensions must equal the analyzer query extensions")

    def cache_identity(self) -> str:
        """Bind cache entries to effective queries, grammars, and package versions."""
        if self._cache_identity is not None:
            return self._cache_identity
        packages = sorted({"tree-sitter"} | {spec.module.replace("_", "-") for spec in self._specs.values()})
        payload = {
            "backend": super().cache_identity(),
            "detection_sha256": hashlib.sha256(self._detection_file.read_bytes()).hexdigest(),
            "specs": {name: asdict(spec) for name, spec in sorted(self._specs.items())},
            "versions": dict(_installed_versions(tuple(packages))),
        }
        self._cache_identity = canonical_sha256(payload)
        return self._cache_identity

    def extract(self, root: str | Path) -> Facts:
        """Extract complete source evidence and disclose source level limitations."""
        base = Path(root).resolve()
        from cyberjury.detection import load_detection

        detection = load_detection(self._detection_file)
        sources = reviewable_sources(base, detection, self._specs)
        try:
            analyzed = analyze_repository(sources)
        except (AnalyzerConfigurationError, SourceReadError) as exc:
            raise BackendUnavailable(str(exc)) from exc
        navigation = collect_navigation_evidence(base, analyzed, detection)
        facts = facts_from_repository(replace(analyzed, sources={**analyzed.sources, **navigation.navigation_sources}))
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
        receipt = NativeAnalysisReceipt.create(
            producer="tree-sitter",
            producer_version=analyzed.producer_version,
            source_count=len(set(analyzed.sources).union(item.source for item in analyzed.limitations)),
            definition_count=len(analyzed.definitions),
            callsite_count=sum(len(definition.callsites) for definition in analyzed.definitions),
            limitation_count=len(analyzed.limitations),
            evidence=asdict(analyzed),
        )
        result = Facts(
            summary=facts.summary,
            data=facts.data,
            limitations=limitations,
            native_analysis=receipt,
        )
        return replace(
            result,
            facts_resolution=FactsResolutionReceipt.create(
                native_analysis=receipt,
                relationship_evidence=result.data.get(
                    "relationship_evidence",
                    RelationshipEvidenceBundle().to_data(),
                ),
                limitations=result.limitations,
            ),
        )


__all__ = ["TreeSitterFacts"]
