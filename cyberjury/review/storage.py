"""Persist deterministic facts between repository review stages."""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberjury.review.facts import Facts, fact_unit_specs

FACTS_ARTIFACTS = (
    "_facts.md",
    "_facts_by_file.json",
    "_facts_units.json",
    "_facts_graph.json",
    "_facts_limitations.json",
)


def facts_cache_key(target: Path, files: tuple[str, ...], profile_name: str, *, schema: str = "3") -> str:
    """Return a content key for facts extracted from one profile and source scope."""
    digest = hashlib.sha256()
    digest.update(f"{schema}\x00{profile_name}".encode())
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
        for name in (*FACTS_ARTIFACTS, "_facts_manifest.json"):
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
        if cache:
            self.cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write_text("_facts.md", facts.summary, key, ".md", cache=cache)
        by_file = data.get("by_file")
        if by_file:
            self._write_json("_facts_by_file.json", by_file, key, ".json", cache=cache)
            artifacts.append("_facts_by_file.json")
        if units:
            self._write_json("_facts_units.json", units, key, ".units.json", cache=cache)
            artifacts.append("_facts_units.json")
        graph = data.get("graph")
        if graph:
            self._write_json("_facts_graph.json", graph, key, ".graph.json", cache=cache)
            artifacts.append("_facts_graph.json")
        if facts.limitations:
            self._write_json(
                "_facts_limitations.json",
                [limitation.to_data() for limitation in facts.limitations],
                key,
                ".limitations.json",
                cache=cache,
            )
            artifacts.append("_facts_limitations.json")
        self._write_manifest(self.workspace / "_facts_manifest.json", artifacts)
        if cache:
            self._write_manifest(self.cache_root / f"{key}.manifest.json", artifacts)

    def _cache_paths(self, key: str) -> dict[str, Path]:
        return {
            "_facts.md": self.cache_root / f"{key}.md",
            "_facts_by_file.json": self.cache_root / f"{key}.json",
            "_facts_units.json": self.cache_root / f"{key}.units.json",
            "_facts_graph.json": self.cache_root / f"{key}.graph.json",
            "_facts_limitations.json": self.cache_root / f"{key}.limitations.json",
        }

    def _write_text(self, name: str, value: str, key: str, suffix: str, *, cache: bool) -> None:
        text = self.workspace / name
        text.write_text(value, encoding="utf-8")
        if cache:
            cached = self.cache_root / f"{key}{suffix}"
            cached.write_text(value, encoding="utf-8")

    def _write_json(self, name: str, value: object, key: str, suffix: str, *, cache: bool) -> None:
        self._write_text(name, json.dumps(value), key, suffix, cache=cache)

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
