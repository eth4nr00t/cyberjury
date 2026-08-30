"""Coordinate EVM source analysis into the shared Facts contract."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from cyberjury.profiles.evm.facts.analyzer import INSTALL_HINT, analyze, available
from cyberjury.profiles.evm.facts.graph import build_graph, facts_from_graph, load_unit_policy
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

    def __init__(self) -> None:
        """Cache stable tool identity across scaffold fingerprint checks."""
        self._cache_identity: str | None = None

    def available(self) -> bool:
        """Report whether the configured analyzer can run."""
        return available()

    def cache_identity(self) -> str:
        """Bind cache entries to the installed Solidity analysis toolchain."""
        if self._cache_identity is not None:
            return self._cache_identity
        versions = {}
        for package in ("slither-analyzer", "crytic-compile", "web3"):
            try:
                versions[package] = version(package)
            except PackageNotFoundError:
                versions[package] = "missing"
        tools = {}
        for name in ("solc", "forge"):
            executable = shutil.which(name)
            if executable is None:
                tools[name] = "missing"
                continue
            try:
                result = subprocess.run(
                    [executable, "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                tools[name] = (result.stdout or result.stderr).strip()
            except (OSError, subprocess.SubprocessError):
                tools[name] = "unavailable"
        payload = {"backend": super().cache_identity(), "versions": versions, "tools": tools}
        self._cache_identity = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return self._cache_identity

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
        return facts_from_graph(graph, unit_policy=load_unit_policy())


__all__ = ["SlitherFacts"]
