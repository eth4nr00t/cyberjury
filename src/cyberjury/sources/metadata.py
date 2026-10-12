"""SourceMeta: optional provenance for a fetched source tree.

It records where a local source tree came from, such as a chain and a contract address,
so a review can show that context. It never feeds finding decisions, invariants 2 and 3,
it only annotates the report.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cyberjury.sources.snapshot import SourceSnapshot

SOURCE_META_SCHEMA = "cyberjury.source-metadata/v1"
SOURCE_ACQUISITION_SCHEMA = "cyberjury.source-acquisition/v1"
SOURCE_METADATA_FILE = "cyberjury-source.json"
SOURCE_RAW_FILE = "explorer-raw.json"
SOURCE_ACQUISITION_FILE = "cyberjury-source-manifest.json"
SOURCE_CONTROL_FILES = frozenset({SOURCE_METADATA_FILE, SOURCE_RAW_FILE, SOURCE_ACQUISITION_FILE})


class SourceError(Exception):
    """A source fetch or parse failed, so no partial source tree is returned."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _strict_json(text: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key {key!r}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


@dataclass(frozen=True, kw_only=True)
class SourceMeta:
    """Block explorer provenance rendered into reports."""

    source: str = ""
    chain: str = ""
    chain_id: int | None = None
    address: str = ""
    source_url: str = ""
    contract_name: str = ""
    compiler_version: str = ""
    optimization_used: bool | None = None
    runs: int | None = None
    constructor_arguments: str = ""
    evm_version: str = ""
    license_type: str = ""
    proxy: bool | None = None
    implementation_address: str = ""
    fetched_at: str = ""

    def __post_init__(self) -> None:
        """Keep the in-memory provenance shape JSON strict before persistence."""
        strings = (
            self.source,
            self.chain,
            self.address,
            self.source_url,
            self.contract_name,
            self.compiler_version,
            self.constructor_arguments,
            self.evm_version,
            self.license_type,
            self.implementation_address,
            self.fetched_at,
        )
        if not all(isinstance(value, str) for value in strings):
            raise ValueError("source metadata text fields must be strings")
        for value in (self.chain_id, self.runs):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError("source metadata numeric fields must be integers or null")
        for value in (self.optimization_used, self.proxy):
            if value is not None and not isinstance(value, bool):
                raise ValueError("source metadata boolean fields must be booleans or null")

    def to_dict(self) -> dict[str, Any]:
        """Return the stable wire form consumed by reports and persisted state."""
        return {"schema": SOURCE_META_SCHEMA, **asdict(self)}

    def to_json(self) -> str:
        """Render source provenance as stable JSON for automation."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)

    def is_empty(self) -> bool:
        """No provenance was recorded, so a report shows no Target section."""
        return all(value in ("", None) for value in asdict(self).values())

    def display_rows(self) -> list[tuple[str, str]]:
        """The present provenance fields as label and value pairs for a report, in a stable order.

        skipping the empty ones so a report prints only what it has.
        """
        rows = [
            ("Chain", self.chain),
            ("Chain ID", str(self.chain_id) if self.chain_id is not None else ""),
            ("Address", self.address),
            ("Source", self.source_url),
            ("Contract", self.contract_name),
            ("Compiler", self.compiler_version),
        ]
        return [(label, value) for label, value in rows if value]


@dataclass(frozen=True, kw_only=True)
class SourceAcquisition:
    """Verified publication receipt separated from review source identity."""

    metadata: SourceMeta
    published_response_sha256: str
    source_snapshot: SourceSnapshot
    acquisition_sha256: str

    @classmethod
    def create(
        cls,
        *,
        metadata: SourceMeta,
        published_response_sha256: str,
        source_snapshot: SourceSnapshot,
    ) -> SourceAcquisition:
        """Create a receipt from its canonical semantic content."""
        semantic = {
            "metadata": metadata.to_dict(),
            "published_response_sha256": published_response_sha256,
            "source_snapshot": source_snapshot.to_dict(),
        }
        return cls(
            metadata=metadata,
            published_response_sha256=published_response_sha256,
            source_snapshot=source_snapshot,
            acquisition_sha256=_sha256(semantic),
        )

    def semantic_dict(self) -> dict[str, object]:
        """Return acquisition facts without their receipt hash."""
        return {
            "metadata": self.metadata.to_dict(),
            "published_response_sha256": self.published_response_sha256,
            "source_snapshot": self.source_snapshot.to_dict(),
        }

    def __post_init__(self) -> None:
        """Require every acquisition receipt to match its exact semantic content."""
        if not re.fullmatch(r"[0-9a-f]{64}", self.published_response_sha256):
            raise ValueError("published response sha256 is invalid")
        if self.acquisition_sha256 != _sha256(self.semantic_dict()):
            raise ValueError("source acquisition sha256 does not match its content")

    def to_dict(self) -> dict[str, object]:
        """Return the strict acquisition manifest wire form."""
        return {
            "schema": SOURCE_ACQUISITION_SCHEMA,
            **self.semantic_dict(),
            "acquisition_sha256": self.acquisition_sha256,
        }


def _to_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("1", "true"):
            return True
        if token in ("0", "false"):
            return False
    return None


def _to_str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def read_source_meta_file(path: Path) -> SourceMeta | None:
    """Read a cyberjury-source.json into a SourceMeta.

    Absent returns None, so a normal review with no provenance is unaffected. Present but
    malformed fails loud, invariant 4. Empty provenance reads as None, so a report adds no
    Target.
    """
    if not path.exists():
        return None
    try:
        data = _strict_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SourceError(f"{path.name} is malformed: {error}") from error
    meta = source_meta_from_persisted_dict(data)
    return None if meta.is_empty() else meta


def source_meta_from_dict(data: object) -> SourceMeta:
    """Read a cyberjury-source.json back into a SourceMeta.

    Fail loud when the file is not a JSON object, invariant 4. A missing field stays
    empty, never guessed.
    """
    if not isinstance(data, dict):
        raise SourceError("source metadata is not a JSON object")
    return SourceMeta(
        source=_to_str(data.get("source")),
        chain=_to_str(data.get("chain")),
        chain_id=_to_int(data.get("chain_id")),
        address=_to_str(data.get("address")),
        source_url=_to_str(data.get("source_url")),
        contract_name=_to_str(data.get("contract_name")),
        compiler_version=_to_str(data.get("compiler_version")),
        optimization_used=_to_bool(data.get("optimization_used")),
        runs=_to_int(data.get("runs")),
        constructor_arguments=_to_str(data.get("constructor_arguments")),
        evm_version=_to_str(data.get("evm_version")),
        license_type=_to_str(data.get("license_type")),
        proxy=_to_bool(data.get("proxy")),
        implementation_address=_to_str(data.get("implementation_address")),
        fetched_at=_to_str(data.get("fetched_at")),
    )


def source_meta_from_persisted_dict(data: object) -> SourceMeta:
    """Parse the exact versioned metadata written by verified acquisition."""
    if not isinstance(data, dict):
        raise SourceError("source metadata is not a JSON object")
    fields = {"schema", *asdict(SourceMeta())}
    if set(data) != fields or data.get("schema") != SOURCE_META_SCHEMA:
        raise SourceError("source metadata has an unsupported or nonexact schema")
    meta = source_meta_from_dict(data)
    if meta.to_dict() != data:
        raise SourceError("source metadata fields have invalid persisted types")
    if not meta.source or not meta.chain or meta.chain_id is None or not meta.address or not meta.source_url:
        raise SourceError("source metadata is missing acquisition provenance")
    if meta.proxy is None or meta.optimization_used is None:
        raise SourceError("source metadata has invalid boolean fields")
    return meta


def _acquired_source_files(root: Path) -> tuple[str, ...]:
    files: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if len(relative.parts) == 1 and relative.name in SOURCE_CONTROL_FILES:
            continue
        if path.is_symlink() and path.resolve(strict=True).is_dir():
            raise SourceError(f"verified source contains a directory symlink: {relative.as_posix()}")
        if path.is_file():
            files.append(relative.as_posix())
    return tuple(sorted(files))


def read_source_acquisition(root: Path) -> SourceAcquisition | None:
    """Validate a complete verified source publication when control files are present."""
    from cyberjury.sources.snapshot import SourceSnapshot, SourceSnapshotError

    present = {name for name in SOURCE_CONTROL_FILES if (root / name).exists()}
    if not present:
        return None
    if present != set(SOURCE_CONTROL_FILES):
        raise SourceError("verified source acquisition control files are incomplete")
    try:
        acquisition = _strict_json((root / SOURCE_ACQUISITION_FILE).read_text(encoding="utf-8"))
        raw = (root / SOURCE_RAW_FILE).read_bytes()
        metadata_data = _strict_json((root / SOURCE_METADATA_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError, SourceSnapshotError) as exc:
        raise SourceError(f"verified source acquisition is unreadable: {exc}") from exc
    fields = {
        "schema",
        "metadata",
        "published_response_sha256",
        "source_snapshot",
        "acquisition_sha256",
    }
    if (
        not isinstance(acquisition, dict)
        or set(acquisition) != fields
        or acquisition.get("schema") != SOURCE_ACQUISITION_SCHEMA
    ):
        raise SourceError("verified source acquisition manifest has an invalid schema")
    meta = source_meta_from_persisted_dict(acquisition["metadata"])
    if metadata_data != meta.to_dict():
        raise SourceError("verified source metadata does not match its acquisition manifest")
    raw_hash = hashlib.sha256(raw).hexdigest()
    if acquisition["published_response_sha256"] != raw_hash:
        raise SourceError("verified source published response hash does not match")
    try:
        snapshot = SourceSnapshot.from_dict(
            acquisition["source_snapshot"],
            root=root,
            scope_provider=lambda: _acquired_source_files(root),
        )
    except (OSError, ValueError) as exc:
        raise SourceError(f"verified source snapshot is invalid: {exc}") from exc
    if not snapshot.matches():
        raise SourceError("verified source files no longer match the acquisition manifest")
    try:
        return SourceAcquisition(
            metadata=meta,
            published_response_sha256=acquisition["published_response_sha256"],
            source_snapshot=snapshot,
            acquisition_sha256=acquisition["acquisition_sha256"],
        )
    except ValueError as exc:
        raise SourceError(f"verified source acquisition receipt is invalid: {exc}") from exc
