"""SourceMeta: optional provenance for a fetched source tree.

It records where a local source tree came from, such as a chain and a contract address,
so a review can show that context. It never feeds finding decisions, invariants 2 and 3,
it only annotates the report.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class SourceError(Exception):
    """A source fetch or parse failed, so no partial source tree is returned."""


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

    def to_dict(self) -> dict[str, Any]:
        """Return the stable wire form consumed by reports and persisted state."""
        return asdict(self)

    def to_json(self) -> str:
        """Render source provenance as stable JSON for automation."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

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
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SourceError(f"{path.name} is malformed: {error}") from error
    meta = source_meta_from_dict(data)
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
