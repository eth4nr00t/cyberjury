"""Keep third party source identities separate from reviewed repository paths."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from cyberjury.workspace import read_json_object, write_json_atomic

if TYPE_CHECKING:
    from cyberjury.profiles.base import ReviewProfile
    from cyberjury.review.context import SourceEvidence

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARTIFACT_BYTES = 100_000_000
_MAX_MEMBER_BYTES = 2_000_000


class DependencySourceError(RuntimeError):
    """The selected artifact or source cannot support an exact receipt."""


def _member_name(name: str) -> str:
    if not isinstance(name, str):
        raise DependencySourceError("dependency source member has an unsafe path")
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {".", ".."} for part in path.parts)
        or "\\" in name
        or ":" in name
    ):
        raise DependencySourceError("dependency source member has an unsafe path")
    return name


@dataclass(frozen=True, kw_only=True)
class DependencySource:
    """One bounded member whose selection still needs ecosystem validation."""

    ecosystem: str
    package: str
    version: str
    archive: Path
    archive_sha256: str
    member: str
    selection_file: str
    selection_sha256: str

    def __post_init__(self) -> None:
        """Reject identities that cannot be used as exact external receipts."""
        if not isinstance(self.archive, Path) or not self.archive.is_absolute():
            raise DependencySourceError("dependency archive path must be absolute")
        if not all(
            isinstance(value, str) and value and "\x00" not in value
            for value in (self.ecosystem, self.package, self.version)
        ):
            raise DependencySourceError("dependency identity is incomplete")
        _member_name(self.member)
        _member_name(self.selection_file)
        if (
            not isinstance(self.archive_sha256, str)
            or not isinstance(self.selection_sha256, str)
            or not _SHA256.fullmatch(self.archive_sha256)
            or not _SHA256.fullmatch(self.selection_sha256)
        ):
            raise DependencySourceError("dependency source hashes must be SHA-256 digests")

    @property
    def identity(self) -> str:
        """Identify an artifact member without treating it as repository source."""
        return (
            f"{self.ecosystem}:{self.package}@{self.version}:{self.archive_sha256}:"
            f"{self.selection_file}:{self.selection_sha256}:{self.member}"
        )

    @property
    def id(self) -> str:
        """Keep dependency receipts outside repository navigation identifiers."""
        return f"dep-{hashlib.sha256(self.identity.encode()).hexdigest()[:20]}"

    @property
    def selection_id(self) -> str:
        """Identify one target selected artifact independently of its source members."""
        package_identity = f"{self.ecosystem}:{self.package}@{self.version}:{self.archive_sha256}"
        selection = f"{package_identity}:{self.selection_file}:{self.selection_sha256}"
        digest = hashlib.sha256(selection.encode()).hexdigest()
        return f"pkg-{digest[:20]}"

    def to_dict(self) -> dict[str, str]:
        """Record the minimum inputs required to replay a selected artifact."""
        return {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "archive": str(self.archive),
            "archive_sha256": self.archive_sha256,
            "member": self.member,
            "selection_file": self.selection_file,
            "selection_sha256": self.selection_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> DependencySource:
        """Reject corrupted external source identities during workspace resume."""
        fields = set(cls.__dataclass_fields__)
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or not all(isinstance(item, str) for item in value.values())
        ):
            raise DependencySourceError("dependency source identity has an invalid shape")
        return cls(**{**value, "archive": Path(value["archive"])})

    def read(self, repository: str | Path, *, check_selection: Callable[[bytes, bytes], None]) -> str:
        """Revalidate selection semantics and exact artifact before reading."""
        base = Path(repository).resolve()
        selected = (base / self.selection_file).resolve()
        if not selected.is_relative_to(base) or not selected.is_file():
            raise DependencySourceError("dependency selection is unavailable inside the reviewed repository")
        selection = selected.read_bytes()
        if hashlib.sha256(selection).hexdigest() != self.selection_sha256:
            raise DependencySourceError("dependency selection changed after capture")
        try:
            archive = self.archive.resolve(strict=True)
            if not archive.is_file() or archive.stat().st_size > _MAX_ARTIFACT_BYTES:
                raise DependencySourceError("dependency archive is unavailable or too large")
            with archive.open("rb") as stream:
                raw = stream.read(_MAX_ARTIFACT_BYTES + 1)
            if len(raw) > _MAX_ARTIFACT_BYTES:
                raise DependencySourceError("dependency archive exceeds the size limit")
            if hashlib.sha256(raw).hexdigest() != self.archive_sha256:
                raise DependencySourceError("dependency archive changed after capture")
            check_selection(selection, raw)
            return self._read_member(raw)
        except (OSError, ValueError) as exc:
            raise DependencySourceError(f"dependency source is unreadable: {exc}") from exc

    def _read_member(self, raw: bytes) -> str:
        """Read one member only from bytes whose artifact identity was checked."""
        try:
            if zipfile.is_zipfile(io.BytesIO(raw)):
                with zipfile.ZipFile(io.BytesIO(raw)) as opened:
                    info = opened.getinfo(self.member)
                    if (
                        info.is_dir()
                        or info.file_size > _MAX_MEMBER_BYTES
                        or (info.external_attr >> 16) & 0o170000 == 0o120000
                    ):
                        raise DependencySourceError("dependency source member is not a bounded regular file")
                    with opened.open(info) as stream:
                        data = stream.read(_MAX_MEMBER_BYTES + 1)
            else:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as opened:
                    info = opened.getmember(self.member)
                    if not info.isfile() or info.size > _MAX_MEMBER_BYTES:
                        raise DependencySourceError("dependency source member is not a bounded regular file")
                    stream = opened.extractfile(info)
                    if stream is None:
                        raise DependencySourceError("dependency source member is unreadable")
                    with stream:
                        data = stream.read(_MAX_MEMBER_BYTES + 1)
        except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            raise DependencySourceError(f"dependency source is unreadable: {exc}") from exc
        if len(data) > _MAX_MEMBER_BYTES:
            raise DependencySourceError("dependency source member exceeds the size limit")
        try:
            return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeDecodeError as exc:
            raise DependencySourceError("dependency source member is not UTF-8") from exc


@dataclass(frozen=True, kw_only=True)
class DependencyMatch:
    """One discoverable external source range, not a repository location."""

    source: DependencySource
    start: int
    end: int
    line: int
    preview: str

    @property
    def id(self) -> str:
        """Bind the returned range to the exact artifact member identity."""
        value = f"{self.source.identity}:{self.start}:{self.end}"
        return f"dep-{hashlib.sha256(value.encode()).hexdigest()[:20]}"

    def receipt(self, content: str) -> DependencyReceipt:
        """Bind one exact delivered window to its immutable artifact identity."""
        if self.end > len(content):
            raise DependencySourceError("dependency receipt exceeds the verified source")
        return DependencyReceipt(
            source=self.source,
            start=self.start,
            end=self.end,
            id=self.id,
            content_sha256=hashlib.sha256(content[self.start : self.end].encode()).hexdigest(),
        )


@dataclass(frozen=True, kw_only=True)
class DependencyReceipt:
    """A replayable dependency source window, never a repository span."""

    source: DependencySource
    start: int
    end: int
    id: str
    content_sha256: str

    def __post_init__(self) -> None:
        """Require a source bound range and content digest."""
        if (
            not isinstance(self.source, DependencySource)
            or not isinstance(self.id, str)
            or not isinstance(self.content_sha256, str)
            or isinstance(self.start, bool)
            or not isinstance(self.start, int)
            or isinstance(self.end, bool)
            or not isinstance(self.end, int)
            or self.start < 0
            or self.end <= self.start
            or not _SHA256.fullmatch(self.content_sha256)
        ):
            raise DependencySourceError("dependency receipt has an invalid source range or digest")
        expected = f"dep-{hashlib.sha256(f'{self.source.identity}:{self.start}:{self.end}'.encode()).hexdigest()[:20]}"
        if self.id != expected:
            raise DependencySourceError("dependency receipt id does not match its source range")

    def read(self, catalog: DependencyCatalog) -> str:
        """Check catalog membership and reread the same source bytes."""
        return self.read_with_line(catalog)[0]

    def read_with_line(self, catalog: DependencyCatalog) -> tuple[str, int]:
        """Replay the receipt once and return its first source line."""
        if self.source not in catalog.sources:
            raise DependencySourceError("dependency receipt is not part of the selected source catalog")
        content = catalog.read(self.source)
        if self.end > len(content):
            raise DependencySourceError("dependency receipt exceeds its source file")
        selected = content[self.start : self.end]
        if hashlib.sha256(selected.encode()).hexdigest() != self.content_sha256:
            raise DependencySourceError("dependency source changed after its exact receipt was delivered")
        return selected, content[: self.start].count("\n") + 1

    def to_dict(self) -> dict[str, object]:
        """Persist source coordinates without persisting third party source text."""
        return {
            "source": self.source.to_dict(),
            "start": self.start,
            "end": self.end,
            "id": self.id,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> DependencyReceipt:
        """Reconstruct an exact range only after validating all receipt fields."""
        fields = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != fields:
            raise DependencySourceError("dependency source receipt has an invalid shape")
        return cls(**{**value, "source": DependencySource.from_dict(value["source"])})


@dataclass(frozen=True, kw_only=True)
class DependencyCatalog:
    """Search profile verified package files only when a role requests them."""

    repository: Path
    sources: tuple[DependencySource, ...]
    reader: Callable[[DependencySource, Path], str]

    def __post_init__(self) -> None:
        """Reject ambiguous external source identities."""
        if not isinstance(self.repository, Path) or not self.repository.is_absolute():
            raise DependencySourceError("dependency catalog repository must be an absolute path")
        if not isinstance(self.sources, tuple) or any(
            not isinstance(source, DependencySource) for source in self.sources
        ):
            raise DependencySourceError("dependency catalog sources must be a source tuple")
        if not callable(self.reader):
            raise DependencySourceError("dependency catalog reader must be callable")
        if len({source.identity for source in self.sources}) != len(self.sources):
            raise DependencySourceError("dependency catalog repeats a source member")

    @property
    def selections(self) -> tuple[DependencySource, ...]:
        """Publish one representative per independently selected package artifact."""
        return tuple({source.selection_id: source for source in self.sources}.values())

    def read(self, source: DependencySource) -> str:
        """Revalidate selection and archive content at every exact read."""
        return self.reader(source, self.repository)

    def validate(self) -> None:
        """Recheck each selected artifact once before a review is reported complete."""
        checked: set[str] = set()
        for source in self.sources:
            key = source.selection_id
            if key in checked:
                continue
            checked.add(key)
            self.read(source)

    @property
    def revision(self) -> str:
        """Bind source members and selection hashes to one attempt identity."""
        entries = [(item.identity, item.selection_file, item.selection_sha256) for item in self.sources]
        value = {"policy": "cyberjury.dependency-selection/v1", "entries": entries}
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def search(self, package: str, query: str) -> tuple[DependencyMatch, ...]:
        """Publish literal text matches without claiming a call binding."""
        if not package or not query:
            raise DependencySourceError("dependency search requires a package and literal query")
        matches: dict[str, DependencyMatch] = {}
        verified_archives: dict[tuple[Path, str], bytes] = {}
        total_archive_bytes = 0
        total_source_chars = 0
        for source in self.sources:
            if source.package.casefold() != package.casefold():
                continue
            key = (source.archive, source.selection_id)
            raw = verified_archives.get(key)
            if raw is None:
                self.read(source)
                raw = source.archive.read_bytes()
                if hashlib.sha256(raw).hexdigest() != source.archive_sha256:
                    raise DependencySourceError("dependency archive changed during source search")
                total_archive_bytes += len(raw)
                if total_archive_bytes > 128_000_000:
                    raise DependencySourceError("dependency search exceeds the archive memory budget")
                verified_archives[key] = raw
            text = source._read_member(raw)
            total_source_chars += len(text)
            if total_source_chars > 40_000_000:
                raise DependencySourceError("dependency search exceeds the source text budget")
            lines = text.splitlines(keepends=True)
            offsets = [0]
            for line in lines:
                offsets.append(offsets[-1] + len(line))
            for line_no, line in enumerate(lines, start=1):
                if query not in line:
                    continue
                first = max(0, line_no - 4)
                last = min(len(lines), line_no + 12)
                match = DependencyMatch(
                    source=source,
                    start=offsets[first],
                    end=offsets[last],
                    line=line_no,
                    preview=line.strip()[:240],
                )
                matches[match.id] = match
        return tuple(matches.values())


def dependency_catalog_for(profile: ReviewProfile, repository: str | Path) -> DependencyCatalog | None:
    """Bind an explicitly supplied offline archive directory through the selected profile."""
    directory = os.environ.get("CYBERJURY_DEPENDENCY_ARCHIVES", "").strip()
    if not directory:
        return None
    if profile.dependency_catalog is None:
        raise DependencySourceError(f"profile {profile.name} has no external dependency source provider")
    return profile.dependency_catalog(Path(repository).resolve(), Path(directory).resolve())


def load_dependency_receipts(workspace: Path, catalog: DependencyCatalog | None) -> tuple[SourceEvidence, ...]:
    """Revalidate replayable external windows on workspace resume."""
    from cyberjury.review.context import SourceEvidence

    path = workspace / "_dependency_evidence.json"
    if not path.is_file():
        return ()
    try:
        data = read_json_object(path)
    except (OSError, ValueError) as exc:
        raise DependencySourceError("repository dependency evidence is unreadable") from exc
    if (
        catalog is None
        or not isinstance(data, dict)
        or set(data) != {"schema", "revision", "receipts"}
        or data["schema"] != "cyberjury.dependency-evidence/v1"
        or data["revision"] != catalog.revision
        or not isinstance(data["receipts"], list)
    ):
        raise DependencySourceError("repository dependency evidence does not match the selected source revision")
    results = []
    for raw in data["receipts"]:
        receipt = DependencyReceipt.from_dict(raw)
        receipt.read(catalog)
        results.append(
            SourceEvidence(
                id=receipt.id,
                identity=f"{receipt.source.identity}:{receipt.start}:{receipt.end}",
                text=f"Dependency source receipt {receipt.id}",
                dependency_receipt=receipt,
            )
        )
    if len({item.id for item in results}) != len(results):
        raise DependencySourceError("repository dependency evidence contains duplicate receipts")
    return tuple(results)


def verify_dependency_catalog(workspace: Path, catalog: DependencyCatalog | None) -> None:
    """Reject finalize or resume against an unbound external source selection."""
    path = workspace / "_dependency_sources.json"
    if catalog is None and not path.exists():
        return
    if not path.is_file() or catalog is None:
        raise DependencySourceError("repository dependency selection changed since the workspace was created")
    try:
        stored = read_json_object(path)
    except (OSError, ValueError) as exc:
        raise DependencySourceError("repository dependency selection record is unreadable") from exc
    if stored != {"schema": "cyberjury.dependency-selection/v1", "revision": catalog.revision}:
        raise DependencySourceError("repository dependency selection changed since the workspace was created")


def save_dependency_receipts(
    workspace: Path,
    catalog: DependencyCatalog | None,
    evidence: tuple[SourceEvidence, ...],
) -> None:
    """Checkpoint exact external coordinates without persisting source text."""
    selected = tuple(item for item in evidence if item.dependency_receipt is not None)
    if not selected:
        return
    if catalog is None:
        raise DependencySourceError("cannot persist external evidence without its catalog")
    by_id = {item.id: item for item in load_dependency_receipts(workspace, catalog)}
    for item in selected:
        if item.dependency_receipt is None:
            continue
        prior = by_id.get(item.id)
        if prior is not None and prior.dependency_receipt != item.dependency_receipt:
            raise DependencySourceError("dependency source receipt changed across review passes")
        item.dependency_receipt.read(catalog)
        by_id[item.id] = item
    write_json_atomic(
        workspace / "_dependency_evidence.json",
        {
            "schema": "cyberjury.dependency-evidence/v1",
            "revision": catalog.revision,
            "receipts": [item.dependency_receipt.to_dict() for item in by_id.values() if item.dependency_receipt],
        },
    )
