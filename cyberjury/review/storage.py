"""Persist deterministic facts between review stages."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.facts import Facts, NativeAnalysisReceipt, fact_unit_specs
from cyberjury.sources.snapshot import SourceSnapshot

FACTS_ARTIFACTS = (
    "_facts.md",
    "_facts_by_file.json",
    "_facts_units.json",
    "_facts_graph.json",
    "_relationship_evidence.json",
    "_facts_limitations.json",
    "_native_analysis.json",
)
CACHE_ERROR = "_facts_cache_error.txt"


def facts_cache_key(
    target: Path,
    files: tuple[str, ...],
    profile_name: str,
    *,
    profile_content_snapshot_id: str = "",
    backend_identity: str = "",
    schema: str = "8",
) -> str:
    """Return a content key for facts extracted from one profile and source scope."""
    snapshot = SourceSnapshot.capture(target, files)
    return facts_cache_key_from_snapshot(
        snapshot.snapshot_id,
        profile_name,
        profile_content_snapshot_id=profile_content_snapshot_id,
        backend_identity=backend_identity,
        schema=schema,
    )


def facts_cache_key_from_snapshot(
    snapshot_id: str,
    profile_name: str,
    *,
    profile_content_snapshot_id: str,
    backend_identity: str,
    schema: str = "8",
) -> str:
    """Bind a source-only snapshot to profile and analyzer cache identity."""
    if not re.fullmatch(r"[0-9a-f]{64}", snapshot_id):
        raise ValueError("facts cache source snapshot id is invalid")
    if profile_content_snapshot_id and not re.fullmatch(r"[0-9a-f]{64}", profile_content_snapshot_id):
        raise ValueError("facts cache profile content snapshot id is invalid")
    digest = hashlib.sha256()
    digest.update(f"{schema}\x00{profile_name}\x00{profile_content_snapshot_id}\x00{backend_identity}".encode())
    digest.update(bytes.fromhex(snapshot_id))
    return digest.hexdigest()


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
        if facts.empty and facts.native_analysis is None:
            return
        data = facts.data if isinstance(facts.data, dict) else {}
        units = [
            unit
            for unit in fact_unit_specs(facts)
            if not any(is_test_path(fragment.file) for fragment in unit.get("fragments", ()))
        ]
        artifacts: list[str] = []
        cache = facts.complete
        if not facts.empty:
            self._write_text("_facts.md", facts.summary)
            artifacts.append("_facts.md")
        if facts.native_analysis is not None:
            self._write_json("_native_analysis.json", facts.native_analysis.to_dict())
            artifacts.append("_native_analysis.json")
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

    def native_analysis(self) -> NativeAnalysisReceipt | None:
        """Read and validate the persisted native analysis receipt when present."""
        path = self.workspace / "_native_analysis.json"
        if not path.is_file():
            return None
        try:
            return NativeAnalysisReceipt.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise ValueError(f"native analysis artifact at {path} is invalid: {exc}") from exc

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
            "_native_analysis.json": self.cache_root / f"{key}.analysis.json",
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
        if not isinstance(artifacts, list) or not {"_facts.md", "_native_analysis.json"}.intersection(artifacts):
            return None
        known = set(FACTS_ARTIFACTS)
        if not all(isinstance(name, str) and name in known for name in artifacts):
            return None
        return list(dict.fromkeys(artifacts))

    @staticmethod
    def _write_manifest(path: Path, artifacts: list[str]) -> None:
        path.write_text(json.dumps(sorted(artifacts)), encoding="utf-8")
