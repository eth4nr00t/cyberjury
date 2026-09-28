"""Build bounded, profile selected offline package source catalogs."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury.review.dependencies import DependencyCatalog, DependencySource, DependencySourceError

if TYPE_CHECKING:
    from cyberjury.detection import Detection

type ArchiveMembers = Callable[[Path], tuple[str, str, str, tuple[str, ...]]]
type SelectionNames = Callable[[str], frozenset[str]]


def build_package_catalog(
    repository: str | Path,
    directory: str | Path,
    *,
    detection: Detection,
    lock_names: frozenset[str],
    suffixes: tuple[str, ...],
    archive_members: ArchiveMembers,
    selection_names: SelectionNames,
    read_source: Callable[[DependencySource, Path], str],
) -> DependencyCatalog | None:
    """Capture only artifacts proven selected by the target's supported locks."""
    from cyberjury.review.paths import repository_files

    base = Path(repository).resolve()
    archives = Path(directory).resolve()
    if not archives.is_dir():
        raise DependencySourceError("dependency archive directory is unavailable")
    locks = tuple(file for file in repository_files(base, detection) if Path(file).name in lock_names)
    artifacts = tuple(sorted(path for path in archives.iterdir() if path.is_file()))
    if len(artifacts) > 128:
        raise DependencySourceError("dependency archive directory exceeds the archive limit")
    supported_artifacts = tuple(path for path in artifacts if path.name.endswith(suffixes))
    sources: list[DependencySource] = []
    for archive in supported_artifacts:
        if archive.is_symlink() or not archive.resolve().is_relative_to(archives):
            raise DependencySourceError("dependency archive cannot escape its selected source directory")
        if archive.stat().st_size > 100_000_000:
            raise DependencySourceError("dependency archive exceeds the size limit")
        ecosystem, package, version, members = archive_members(archive)
        if not members:
            raise DependencySourceError(f"dependency archive {archive.name} has no readable source members")
        if len(members) > 4_000:
            raise DependencySourceError("dependency archive has too many source members")
        raw_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        matched = False
        rejection = "no matching project lock"
        for lock in locks:
            if Path(lock).name not in selection_names(ecosystem):
                continue
            selection_hash = hashlib.sha256((base / lock).read_bytes()).hexdigest()
            selected = DependencySource(
                ecosystem=ecosystem,
                package=package,
                version=version,
                archive=archive,
                archive_sha256=raw_hash,
                member=members[0],
                selection_file=lock,
                selection_sha256=selection_hash,
            )
            try:
                read_source(selected, base)
            except DependencySourceError as exc:
                rejection = str(exc)
                continue
            matched = True
            sources.extend(
                DependencySource(
                    ecosystem=ecosystem,
                    package=package,
                    version=version,
                    archive=archive,
                    archive_sha256=raw_hash,
                    member=member,
                    selection_file=lock,
                    selection_sha256=selection_hash,
                )
                for member in members
            )
        if not matched:
            raise DependencySourceError(f"dependency archive {archive.name} has no verified selection: {rejection}")
    if len(sources) > 10_000:
        raise DependencySourceError("dependency catalog exceeds the source member limit")
    if supported_artifacts and not sources:
        raise DependencySourceError("no supplied dependency archive matches a supported project selection file")
    return DependencyCatalog(repository=base, sources=tuple(sources), reader=read_source) if sources else None
