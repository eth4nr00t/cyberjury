"""Persist deterministic facts and model relationships between review stages."""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.facts import Facts, fact_unit_specs
from cyberjury.review.relations import (
    RelationshipResolution,
    RelationshipResolver,
    relationship_evidence_fingerprint,
    relationship_result_from_data,
    structural_result_from_data,
    validate_relationship_results,
    validate_structural_results,
)
from cyberjury.review.relationships import RelationshipEvidenceBundle

FACTS_ARTIFACTS = (
    "_facts.md",
    "_facts_by_file.json",
    "_facts_units.json",
    "_facts_graph.json",
    "_relationship_evidence.json",
    "_facts_limitations.json",
)
CACHE_ERROR = "_facts_cache_error.txt"
RELATIONSHIP_ARTIFACT = "_relationships.json"


def facts_cache_key(
    target: Path,
    files: tuple[str, ...],
    profile_name: str,
    *,
    profile_fingerprint: str = "",
    backend_identity: str = "",
    schema: str = "8",
) -> str:
    """Return a content key for facts extracted from one profile and source scope."""
    digest = hashlib.sha256()
    digest.update(f"{schema}\x00{profile_name}\x00{profile_fingerprint}\x00{backend_identity}".encode())
    for rel in sorted(files):
        try:
            data = (target / rel).read_bytes()
        except OSError as exc:
            raise OSError(f"cannot compute facts cache key because source {rel!r} could not be read: {exc}") from exc
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


@dataclass(frozen=True, kw_only=True)
class SourceSnapshot:
    """Content identity shared by facts extraction and later source materialization."""

    root: Path
    files: tuple[str, ...]
    profile_name: str
    profile_fingerprint: str
    backend_identity: str
    key: str

    @classmethod
    def capture(
        cls,
        root: Path,
        files: tuple[str, ...],
        profile_name: str,
        *,
        profile_fingerprint: str,
        backend_identity: str,
    ) -> SourceSnapshot:
        """Capture one stable content key and the inputs needed to revalidate it."""
        return cls(
            root=root,
            files=files,
            profile_name=profile_name,
            profile_fingerprint=profile_fingerprint,
            backend_identity=backend_identity,
            key=facts_cache_key(
                root,
                files,
                profile_name,
                profile_fingerprint=profile_fingerprint,
                backend_identity=backend_identity,
            ),
        )

    def matches(self) -> bool:
        """Return whether the live source still has this identity."""
        return self.key == facts_cache_key(
            self.root,
            self.files,
            self.profile_name,
            profile_fingerprint=self.profile_fingerprint,
            backend_identity=self.backend_identity,
        )


@dataclass(frozen=True, kw_only=True)
class RelationshipStore:
    """Persist model established relationships under evidence and resolver identity."""

    workspace: Path

    def resolve(
        self,
        root: str | Path,
        bundle: RelationshipEvidenceBundle,
        resolver: RelationshipResolver,
    ) -> RelationshipResolution:
        """Restore matching results or resolve and atomically replace the artifact."""
        restored = self.load(bundle, resolver.cache_identity())
        if restored is not None:
            return restored
        resolution = resolver.resolve(root, bundle)
        validate_relationship_results(bundle, resolution.call_results)
        validate_structural_results(bundle, resolution.structural_results)
        self._write(bundle, resolver.cache_identity(), resolution)
        return resolution

    def load(
        self,
        bundle: RelationshipEvidenceBundle,
        resolver_identity: str,
    ) -> RelationshipResolution | None:
        """Load matching results and reject stale resume state."""
        path = self.workspace / RELATIONSHIP_ARTIFACT
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"relationship artifact {path} is corrupt: {exc}") from exc
        fields = {
            "schema",
            "evidence_fingerprint",
            "resolver_identity",
            "call_results",
            "structural_results",
            "metrics",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("schema") != 4:
            raise ValueError(f"relationship artifact {path} has an unsupported schema")
        expected_evidence = relationship_evidence_fingerprint(bundle)
        if value.get("evidence_fingerprint") != expected_evidence:
            raise ValueError("relationship evidence changed since the prior run. Re-run with --fresh")
        if value.get("resolver_identity") != resolver_identity:
            raise ValueError("relationship resolver changed since the prior run. Re-run with --fresh")
        raw_results = value.get("call_results")
        if not isinstance(raw_results, list):
            raise ValueError(f"relationship artifact {path} call_results must be a list")
        call_results = tuple(relationship_result_from_data(item) for item in raw_results)
        validate_relationship_results(bundle, call_results)
        raw_structural_results = value.get("structural_results")
        if not isinstance(raw_structural_results, list):
            raise ValueError(f"relationship artifact {path} structural_results must be a list")
        structural_results = tuple(structural_result_from_data(item) for item in raw_structural_results)
        validate_structural_results(bundle, structural_results)
        metrics = value.get("metrics")
        metric_fields = {"calls", "initial_packet_characters", "input_tokens", "output_tokens", "elapsed_seconds"}
        if not isinstance(metrics, dict) or set(metrics) != metric_fields:
            raise ValueError(f"relationship artifact {path} metrics are malformed")
        integer_fields = ("calls", "initial_packet_characters", "input_tokens", "output_tokens")
        if any(
            isinstance(metrics[field], bool) or not isinstance(metrics[field], int) or metrics[field] < 0
            for field in integer_fields
        ):
            raise ValueError(f"relationship artifact {path} metrics contain invalid counters")
        elapsed = metrics["elapsed_seconds"]
        if isinstance(elapsed, bool) or not isinstance(elapsed, int | float) or elapsed < 0:
            raise ValueError(f"relationship artifact {path} elapsed_seconds is invalid")
        return RelationshipResolution(
            call_results=call_results,
            structural_results=structural_results,
            calls=metrics["calls"],
            initial_packet_characters=metrics["initial_packet_characters"],
            input_tokens=metrics["input_tokens"],
            output_tokens=metrics["output_tokens"],
            elapsed_seconds=float(elapsed),
            restored=True,
        )

    def clear(self) -> None:
        """Remove prior model results during fresh workspace setup."""
        with contextlib.suppress(FileNotFoundError):
            (self.workspace / RELATIONSHIP_ARTIFACT).unlink()

    def _write(
        self,
        bundle: RelationshipEvidenceBundle,
        resolver_identity: str,
        resolution: RelationshipResolution,
    ) -> None:
        value = {
            "schema": 4,
            "evidence_fingerprint": relationship_evidence_fingerprint(bundle),
            "resolver_identity": resolver_identity,
            "call_results": [result.to_data() for result in resolution.call_results],
            "structural_results": [result.to_data() for result in resolution.structural_results],
            "metrics": {
                "calls": resolution.calls,
                "initial_packet_characters": resolution.initial_packet_characters,
                "input_tokens": resolution.input_tokens,
                "output_tokens": resolution.output_tokens,
                "elapsed_seconds": resolution.elapsed_seconds,
            },
        }
        path = self.workspace / RELATIONSHIP_ARTIFACT
        temporary = self.workspace / f"{RELATIONSHIP_ARTIFACT}.tmp"
        temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        temporary.replace(path)


@dataclass(frozen=True, kw_only=True)
class FactsStore:
    """Persist and restore facts artifacts without owning a review workflow."""

    workspace: Path
    cache_root: Path

    def complete(self) -> bool:
        """Whether the workspace has every artifact declared by its manifest."""
        artifacts = self._read_manifest(self.workspace / "_facts_manifest.json")
        return artifacts is not None and all((self.workspace / name).is_file() for name in artifacts)

    def clear(self) -> None:
        """Remove facts artifacts before a fresh extraction or cache restore."""
        for name in (*FACTS_ARTIFACTS, "_facts_manifest.json", CACHE_ERROR):
            with contextlib.suppress(FileNotFoundError):
                (self.workspace / name).unlink()

    def restore(self, key: str) -> bool:
        """Restore a complete cached facts result into the workspace."""
        artifacts = self._read_manifest(self.cache_root / f"{key}.manifest.json")
        if artifacts is None:
            return False
        cache_paths = self._cache_paths(key)
        if not all(cache_paths[name].is_file() for name in artifacts):
            return False
        for name in artifacts:
            (self.workspace / name).write_text(cache_paths[name].read_text(encoding="utf-8"), encoding="utf-8")
        self._write_manifest(self.workspace / "_facts_manifest.json", artifacts)
        with contextlib.suppress(FileNotFoundError):
            (self.workspace / CACHE_ERROR).unlink()
        return True

    def persist(self, facts: Facts, key: str, *, is_test_path: Callable[[str], bool]) -> None:
        """Write facts and supported structured fields to the workspace and cache."""
        if facts.empty:
            return
        data = facts.data if isinstance(facts.data, dict) else {}
        units = [
            unit
            for unit in fact_unit_specs(facts)
            if not any(is_test_path(fragment.file) for fragment in unit.get("fragments", ()))
        ]
        artifacts = ["_facts.md"]
        cache = facts.complete
        self._write_text("_facts.md", facts.summary)
        by_file = data.get("by_file")
        if by_file:
            self._write_json("_facts_by_file.json", by_file)
            artifacts.append("_facts_by_file.json")
        if units:
            self._write_json("_facts_units.json", units)
            artifacts.append("_facts_units.json")
        graph = data.get("graph")
        if graph:
            self._write_json("_facts_graph.json", graph)
            artifacts.append("_facts_graph.json")
        relationships = data.get("relationship_evidence")
        if isinstance(relationships, dict) and any(relationships.values()):
            self._write_json("_relationship_evidence.json", relationships)
            artifacts.append("_relationship_evidence.json")
        if facts.limitations:
            self._write_json("_facts_limitations.json", [limitation.to_data() for limitation in facts.limitations])
            artifacts.append("_facts_limitations.json")
        self._write_manifest(self.workspace / "_facts_manifest.json", artifacts)
        if cache:
            self._populate_cache(key, artifacts)

    def populate_cache_from_workspace(self, key: str) -> None:
        """Retry optional cache population from one committed complete workspace."""
        artifacts = self._read_manifest(self.workspace / "_facts_manifest.json")
        if artifacts is None or "_facts_limitations.json" in artifacts:
            return
        self._populate_cache(key, artifacts)

    def _populate_cache(self, key: str, artifacts: list[str]) -> None:
        try:
            self.cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            cache_paths = self._cache_paths(key)
            for name in artifacts:
                cache_paths[name].write_text((self.workspace / name).read_text(encoding="utf-8"), encoding="utf-8")
            self._write_manifest(self.cache_root / f"{key}.manifest.json", artifacts)
        except OSError as exc:
            self.remove_cache(key)
            (self.workspace / CACHE_ERROR).write_text(f"facts cache population failed: {exc}\n", encoding="utf-8")
            return
        with contextlib.suppress(FileNotFoundError):
            (self.workspace / CACHE_ERROR).unlink()

    def remove_cache(self, key: str) -> None:
        """Remove one incomplete or invalid cache entry without touching workspace facts."""
        for path in (*self._cache_paths(key).values(), self.cache_root / f"{key}.manifest.json"):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()

    def _cache_paths(self, key: str) -> dict[str, Path]:
        return {
            "_facts.md": self.cache_root / f"{key}.md",
            "_facts_by_file.json": self.cache_root / f"{key}.json",
            "_facts_units.json": self.cache_root / f"{key}.units.json",
            "_facts_graph.json": self.cache_root / f"{key}.graph.json",
            "_relationship_evidence.json": self.cache_root / f"{key}.relationships.json",
            "_facts_limitations.json": self.cache_root / f"{key}.limitations.json",
        }

    def _write_text(self, name: str, value: str) -> None:
        (self.workspace / name).write_text(value, encoding="utf-8")

    def _write_json(self, name: str, value: object) -> None:
        self._write_text(name, json.dumps(value))

    @staticmethod
    def _read_manifest(path: Path) -> list[str] | None:
        if not path.is_file():
            return None
        try:
            artifacts = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(artifacts, list) or "_facts.md" not in artifacts:
            return None
        known = set(FACTS_ARTIFACTS)
        if not all(isinstance(name, str) and name in known for name in artifacts):
            return None
        return list(dict.fromkeys(artifacts))

    @staticmethod
    def _write_manifest(path: Path, artifacts: list[str]) -> None:
        path.write_text(json.dumps(sorted(artifacts)), encoding="utf-8")
