"""Coordinate EVM source analysis into the shared Facts contract."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import replace
from functools import cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cyberjury.profiles.evm.facts.analyzer import INSTALL_HINT, analysis_evidence, analyze, available
from cyberjury.profiles.evm.facts.graph import build_graph, facts_from_graph, load_unit_policy
from cyberjury.profiles.evm.facts.resolver import load_profile_detection, resolve_project
from cyberjury.review.facts import Facts, FactsBackend, FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.failures import BackendUnavailable


@cache
def _installed_toolchain() -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    versions: list[tuple[str, str]] = []
    for package in ("slither-analyzer", "crytic-compile", "web3"):
        try:
            value = version(package)
        except PackageNotFoundError:
            value = "missing"
        versions.append((package, value))
    tools: list[tuple[str, str]] = []
    for name in ("solc", "forge"):
        executable = shutil.which(name)
        if executable is None:
            tools.append((name, "missing"))
            continue
        try:
            result = subprocess.run(
                [executable, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            tools.append((name, (result.stdout or result.stderr).strip()))
        except (OSError, subprocess.SubprocessError):
            tools.append((name, "unavailable"))
    return tuple(versions), tuple(tools)


class SlitherFacts(FactsBackend):
    """Extract EVM facts through the profile analyzer and graph pipeline."""

    install_hint = INSTALL_HINT
    writes_analysis_artifacts = True

    def __init__(self, *, detection_file: Path | None = None) -> None:
        """Cache stable tool identity across scaffold fingerprint checks."""
        self._detection_file = detection_file or Path(__file__).resolve().parents[1] / "detection.yaml"
        self._cache_identity: str | None = None

    def bind_content(self, content):
        """Bind Solidity analyzer policy to one materialized profile snapshot."""
        return SlitherFacts(detection_file=content.detection_file)

    def validate_content(self, content) -> None:
        """Require the materialized profile to contain valid EVM unit policy."""
        load_unit_policy(content.detection_file)

    def analysis_output_dirs(self) -> frozenset[str]:
        """Omit profile-declared compiler output directories from protected inputs."""
        return load_profile_detection(self._detection_file).analysis_output_dirs

    def available(self) -> bool:
        """Report whether the configured analyzer can run."""
        return available()

    def cache_identity(self) -> str:
        """Bind cache entries to the installed Solidity analysis toolchain."""
        if self._cache_identity is not None:
            return self._cache_identity
        versions, tools = _installed_toolchain()
        payload = {
            "backend": super().cache_identity(),
            "detection_sha256": hashlib.sha256(self._detection_file.read_bytes()).hexdigest(),
            "versions": dict(versions),
            "tools": dict(tools),
        }
        self._cache_identity = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return self._cache_identity

    def extract(self, root: str | Path) -> Facts:
        """Analyze and resolve the review scope or fail loud."""
        if not self.available():
            raise BackendUnavailable(self.install_hint)
        review_root = Path(root).resolve()
        detection = load_profile_detection(self._detection_file)
        compile_root = resolve_compile_root(review_root, detection=detection)
        analyzed = analyze(analyzer_target(review_root, compile_root, detection=detection))
        evidence_root = compile_root if compile_root.is_dir() else compile_root.parent
        source_identities = {
            contract.source.used or contract.source.short or Path(contract.source.absolute).name or contract.identity
            for contract in analyzed.contracts
        }
        receipt = NativeAnalysisReceipt.create(
            producer="slither",
            producer_version=analyzed.producer_version,
            source_count=len(source_identities),
            definition_count=sum(1 + len(contract.functions) for contract in analyzed.contracts),
            callsite_count=sum(
                len(function.callsites) for contract in analyzed.contracts for function in contract.functions
            ),
            limitation_count=0,
            evidence=analysis_evidence(analyzed, source_root=evidence_root),
        )
        resolved = resolve_project(analyzed, review_root, detection)
        graph = build_graph(resolved)
        if compile_root != review_root and not graph.contracts:
            raise BackendUnavailable(
                f"the compile at {compile_root} succeeded but produced no contract under the review "
                f"scope {review_root}, so check that the project compiles the reviewed directory"
            )
        facts = replace(
            facts_from_graph(graph, unit_policy=load_unit_policy(self._detection_file)),
            native_analysis=receipt,
        )
        return replace(
            facts,
            facts_resolution=FactsResolutionReceipt.create(
                native_analysis=receipt,
                relationship_evidence=facts.data["relationship_evidence"],
                limitations=facts.limitations,
            ),
        )


def resolve_compile_root(review_root: Path, *, detection=None) -> Path:
    """Use the nearest repository bounded framework root for scoped analysis."""
    detection = detection or load_profile_detection()
    markers = detection.compile_roots
    if not markers:
        return review_root
    ancestors = [review_root, *review_root.parents]
    repository = next((directory for directory in ancestors if (directory / ".git").exists()), None)
    if repository is None:
        return review_root
    for directory in ancestors:
        if any((directory / marker).is_file() for marker in markers):
            return directory
        if directory == repository:
            break
    return review_root


def analyzer_target(review_root: Path, compile_root: Path, *, detection=None) -> Path:
    """Choose the narrowest analyzer input that retains project compile context."""
    if compile_root != review_root or review_root.is_file() or _has_compile_config(review_root, detection=detection):
        return compile_root
    solidity_files = sorted(path for path in review_root.rglob("*.sol") if path.is_file())
    return solidity_files[0] if len(solidity_files) == 1 else compile_root


def _has_compile_config(root: Path, *, detection=None) -> bool:
    detection = detection or load_profile_detection()
    return any((root / marker).is_file() for marker in detection.compile_roots)


__all__ = ["SlitherFacts", "analyzer_target", "resolve_compile_root"]
