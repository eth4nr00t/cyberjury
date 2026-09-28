"""Bind Solidity package sources to the selected npm artifact."""

from __future__ import annotations

from pathlib import Path

from cyberjury.profiles.base import content_paths
from cyberjury.review.dependencies import DependencyCatalog, DependencySource, DependencySourceError
from cyberjury.sources.npm import npm_members, npm_selection
from cyberjury.sources.packages import build_package_catalog


def _read_source(source: DependencySource, repository: Path) -> str:
    """Keep the package manager rule shared with other profiles."""
    if source.ecosystem != "evm" or Path(source.selection_file).name != "package-lock.json":
        raise DependencySourceError("Solidity dependency has no supported lock selection")

    def check(selection: bytes, archive: bytes) -> None:
        npm_selection(source, selection, archive)

    return source.read(repository, check_selection=check)


def catalog_from_archives(repository: Path, directory: Path) -> DependencyCatalog | None:
    """Index only locked Solidity source members from offline npm archives."""
    from cyberjury.detection import load_detection

    def archive_members(archive: Path) -> tuple[str, str, str, tuple[str, ...]]:
        package, version, entries = npm_members(archive)
        return "evm", package, version, tuple(name for name in entries if name.endswith(".sol"))

    def selection_names(_ecosystem: str) -> frozenset[str]:
        return frozenset({"package-lock.json"})

    return build_package_catalog(
        repository,
        directory,
        detection=load_detection(content_paths(Path(__file__).parent).detection_file),
        lock_names=frozenset({"package-lock.json"}),
        suffixes=(".tgz", ".tar.gz"),
        archive_members=archive_members,
        selection_names=selection_names,
        read_source=_read_source,
    )
