"""Shared facts contracts and extraction semantics for review workflows."""

from __future__ import annotations

import contextlib
import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


class BackendUnavailable(RuntimeError):
    """A required facts or source backend cannot run."""


@dataclass(frozen=True, kw_only=True)
class Facts:
    """Deterministic facts that ground one or more review contexts.

    ``summary`` is prompt-ready text. ``data`` is a structured payload with shared keys
    such as ``by_file``, ``graph``, and optional focused unit specifications. Domain
    backends may add fields, but extraction, persistence, and consumption remain review-owned.
    """

    summary: str = ""
    data: dict = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        """Report whether the backend produced no usable facts."""
        return not self.summary and not self.data


class FactsBackend(ABC):
    """Extract deterministic facts from a source tree for grounded review."""

    install_hint: str = "install the backend's toolchain to enable it"

    @abstractmethod
    def available(self) -> bool:
        """Whether the backing tool is installed and can support grounded review."""

    @abstractmethod
    def extract(self, root: str | Path) -> Facts:
        """Extract facts from ``root`` or raise ``BackendUnavailable``."""


def extract_facts(
    backend: FactsBackend | None,
    root: str | Path,
    *,
    purpose: str = "review",
) -> Facts:
    """Run one facts backend with shared loud-failure behavior.

    A missing backend means that the caller did not bind grounding. A bound backend that
    cannot run or returns an invalid value is an error, never an empty clean review.
    """
    if backend is None:
        return Facts()
    if not backend.available():
        raise BackendUnavailable(
            f"the facts backend cannot run for {purpose}, so this review has no grounding. {backend.install_hint}"
        )
    try:
        facts = backend.extract(root)
    except BackendUnavailable:
        raise
    except Exception as exc:
        raise BackendUnavailable(
            f"facts extraction failed for {purpose}, so this review has no grounding: {exc}"
        ) from exc
    if not isinstance(facts, Facts):
        raise BackendUnavailable(f"facts backend returned an invalid result for {purpose}")
    return facts


def fact_unit_specs(facts: Facts) -> list[dict]:
    """Return backend-provided focused unit specifications in one shared shape."""
    data = facts.data if isinstance(facts.data, dict) else {}
    specs = data.get("unit_specs", [])
    if not isinstance(specs, list):
        raise BackendUnavailable("facts backend returned invalid focused unit specifications")
    if not all(isinstance(spec, dict) for spec in specs):
        raise BackendUnavailable("facts backend returned a malformed focused unit specification")
    return specs


def pack_unit_specs(
    records: dict,
    *,
    focus_flags: tuple[str, ...],
    max_source_chars: int,
) -> list[dict]:
    """Pack flagged function records into bounded, generic unit specifications."""
    raw: list[tuple[frozenset, dict]] = []
    for owner, record in records.items():
        file = record.get("file") or ""
        functions = record.get("functions") or {}
        if not file:
            continue
        callers: dict[str, list[str]] = {}
        for function, info in functions.items():
            for callee in info.get("calls") or ():
                callers.setdefault(callee, []).append(function)
        for function, info in functions.items():
            if not any(info.get(flag) for flag in focus_flags):
                continue
            function_range = _fact_range(info)
            if function_range is None:
                continue
            ordered = [function]
            ordered += [callee for callee in info.get("calls") or () if callee in functions and callee not in ordered]
            ordered += [caller for caller in callers.get(function, ()) if caller in functions and caller not in ordered]
            picked: list[str] = []
            total = 0
            for name in ordered:
                span = _fact_range(functions[name])
                if span is None:
                    continue
                size = span[1] - span[0]
                if picked and total + size > max_source_chars:
                    continue
                picked.append(name)
                total += size
            fragments = sorted(
                ([file, *_fact_range(functions[name])] for name in picked),
                key=lambda fragment: fragment[1],
            )
            spec = {"name": f"{file}#{owner}.{_fact_short(function)}", "files": [file], "fragments": fragments}
            raw.append((frozenset(picked), spec))
    raw.sort(key=lambda item: len(item[0]), reverse=True)
    kept: list[dict] = []
    kept_sets: list[frozenset] = []
    for names, spec in raw:
        if any(names <= prior for prior in kept_sets):
            continue
        kept_sets.append(names)
        kept.append(spec)
    return kept


def _fact_range(info: dict) -> list[int] | None:
    value = info.get("range")
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return [int(value[0]), int(value[1])]
    return None


def _fact_short(name: str) -> str:
    return name.split("(", 1)[0]


FACTS_ARTIFACTS = ("_facts.md", "_facts_by_file.json", "_facts_units.json", "_facts_graph.json")


def facts_cache_key(target: Path, files: tuple[str, ...], profile_name: str, *, schema: str = "2") -> str:
    """Return a content key for facts extracted from one profile and source scope."""
    digest = hashlib.sha256()
    digest.update(f"{schema}\x00{profile_name}".encode())
    for rel in sorted(files):
        try:
            data = (target / rel).read_bytes()
        except OSError:
            continue
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
        cached_manifest = self.cache_root / f"{key}.manifest.json"
        artifacts = self._read_manifest(cached_manifest)
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
            if not any(
                isinstance(fragment, (list, tuple)) and fragment and is_test_path(str(fragment[0]))
                for fragment in unit.get("fragments", ())
            )
        ]
        artifacts = ["_facts.md"]
        self.cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write_text("_facts.md", facts.summary, key, ".md")
        by_file = data.get("by_file")
        if by_file:
            self._write_json("_facts_by_file.json", by_file, key, ".json")
            artifacts.append("_facts_by_file.json")
        if units:
            self._write_json("_facts_units.json", units, key, ".units.json")
            artifacts.append("_facts_units.json")
        graph = data.get("graph")
        if graph:
            self._write_json("_facts_graph.json", graph, key, ".graph.json")
            artifacts.append("_facts_graph.json")
        self._write_manifest(self.workspace / "_facts_manifest.json", artifacts)
        self._write_manifest(self.cache_root / f"{key}.manifest.json", artifacts)

    def _cache_paths(self, key: str) -> dict[str, Path]:
        return {
            "_facts.md": self.cache_root / f"{key}.md",
            "_facts_by_file.json": self.cache_root / f"{key}.json",
            "_facts_units.json": self.cache_root / f"{key}.units.json",
            "_facts_graph.json": self.cache_root / f"{key}.graph.json",
        }

    def _write_text(self, name: str, value: str, key: str, suffix: str) -> None:
        text = self.workspace / name
        cached = self.cache_root / f"{key}{suffix}"
        text.write_text(value, encoding="utf-8")
        cached.write_text(value, encoding="utf-8")

    def _write_json(self, name: str, value: object, key: str, suffix: str) -> None:
        payload = json.dumps(value)
        self._write_text(name, payload, key, suffix)

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
