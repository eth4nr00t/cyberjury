"""Fetch a verified source tree for a contract address and write it to disk.

The one place that combines the network, the pure parser, and the filesystem for the
`fetch source` command. It never runs a review, that is a separate explicit step, so a
fetch that fails leaves no half-written tree passed off as complete.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from cyberjury.sources.explorer import chain_for, fetch_getsourcecode
from cyberjury.sources.metadata import SourceError, SourceMeta
from cyberjury.sources.reconstruct import parse_getsourcecode

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_METADATA_FILE = "cyberjury-source.json"
_RAW_FILE = "explorer-raw.json"


@dataclass(frozen=True)
class FetchResult:
    """Fetched source tree root plus its block explorer provenance."""

    out_dir: Path
    meta: SourceMeta
    file_count: int
    metadata_path: Path


def _write_tree(out_dir: Path, files: dict[str, str]) -> None:
    """Write each reconstructed file under out_dir, refusing any path that would escape it.

    The parser already checked, this is defense in depth at the last step before a write.
    """
    base = out_dir.resolve()
    for rel, content in files.items():
        dest = (out_dir / rel).resolve()
        if dest != base and base not in dest.parents:
            raise SourceError(f"unsafe source path: {rel!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def fetch_source(
    *,
    chain_key: str,
    address: str,
    api_key: str,
    out: str,
    fetched_at: str,
    overwrite: bool = False,
    opener=None,
) -> FetchResult:
    """Fetch verified source for an address and write the tree plus metadata.

    or fail loud on a bad address, a missing key, an unverified contract, or a non-empty
    output directory, invariant 4.
    """
    address = address.strip()
    if not _ADDRESS.match(address):
        raise SourceError(f"not a contract address: {address!r}")
    if not api_key.strip():
        raise SourceError("no Etherscan API key, set CYBERJURY_ETHERSCAN_API_KEY or pass --api-key")
    chain = chain_for(chain_key)
    out_dir = Path(out)
    if out_dir.exists() and any(out_dir.iterdir()) and not overwrite:
        raise SourceError(f"output directory {out_dir} is not empty, pass --overwrite to replace it")

    payload = fetch_getsourcecode(chain, address, api_key.strip(), opener=opener)
    source_url = chain.address_url.format(address=address)
    meta, files = parse_getsourcecode(
        payload,
        source=chain.source,
        chain=chain.key,
        chain_id=chain.chain_id,
        address=address,
        source_url=source_url,
        fetched_at=fetched_at,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    _write_tree(out_dir, files)
    (out_dir / _RAW_FILE).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    metadata_path = out_dir / _METADATA_FILE
    metadata_path.write_text(meta.to_json(), encoding="utf-8")
    return FetchResult(out_dir=out_dir, meta=meta, file_count=len(files), metadata_path=metadata_path)
