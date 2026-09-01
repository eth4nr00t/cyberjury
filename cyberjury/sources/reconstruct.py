"""Turn a block explorer getsourcecode response into a source tree and its SourceMeta.

Pure, no network and no filesystem, so tests drive it with fixtures. An explorer returns
the SourceCode field in one of three shapes: plain Solidity text, a single JSON object,
or a standard JSON input wrapped in an extra pair of braces. The paths inside come from
an untrusted response, so each is checked against traversal before it can become a file
path.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from cyberjury.sources.metadata import SOURCE_CONTROL_FILES, SourceError, SourceMeta, source_meta_from_dict

_MAX_SOURCE_FILES = 5000
_MAX_SOURCE_BYTES = 5_000_000
_MAX_TOTAL_SOURCE_BYTES = 50_000_000
_MAX_SOURCE_PATH_CHARS = 4096
_WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)


def _safe_relpath(path: str) -> str:
    """Reject response paths that could escape the output tree."""
    normalized = path.strip().replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        raise SourceError(f"unsafe source path: {path!r}")
    parts = [seg for seg in normalized.split("/") if seg not in ("", ".")]
    if not parts or any(
        seg == ".."
        or ":" in seg
        or seg.endswith((" ", "."))
        or _WINDOWS_RESERVED.fullmatch(seg)
        or unicodedata.normalize("NFC", seg) != seg
        for seg in parts
    ):
        raise SourceError(f"unsafe source path: {path!r}")
    result = "/".join(parts)
    if len(result) > _MAX_SOURCE_PATH_CHARS:
        raise SourceError(f"source path is too long: {path!r}")
    if result.casefold() in {name.casefold() for name in SOURCE_CONTROL_FILES}:
        raise SourceError(f"source path is reserved for acquisition control data: {path!r}")
    return result


def _content_of(entry: object) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("content"), str):
        return entry["content"]
    return None


def _sources_map(obj: dict[str, Any]) -> dict[str, Any]:
    """Return the sources entry map from standard JSON input or a direct path map."""
    inner = obj.get("sources")
    if isinstance(inner, dict):
        return inner
    return obj


def _parse_json_sources(text: str) -> dict[str, str]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise SourceError(f"source code JSON contains duplicate key {key!r}")
            value[key] = item
        return value

    try:
        obj = json.loads(text, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise SourceError(f"source code is not valid JSON: {error}") from error
    if not isinstance(obj, dict):
        raise SourceError("source code JSON is not an object")
    files: dict[str, str] = {}
    portable_paths: set[str] = set()
    total_bytes = 0
    for path, entry in _sources_map(obj).items():
        content = _content_of(entry)
        if content is None:
            raise SourceError(f"source {path!r} has no inline content")
        normalized = _safe_relpath(str(path))
        portable = normalized.casefold()
        if normalized in files or portable in portable_paths:
            raise SourceError(f"source paths collide after normalization: {path!r}")
        encoded_size = len(content.encode("utf-8"))
        if encoded_size > _MAX_SOURCE_BYTES:
            raise SourceError(f"source {path!r} exceeds the per-file byte limit")
        total_bytes += encoded_size
        if total_bytes > _MAX_TOTAL_SOURCE_BYTES:
            raise SourceError("source tree exceeds the total byte limit")
        files[normalized] = content
        portable_paths.add(portable)
        if len(files) > _MAX_SOURCE_FILES:
            raise SourceError("source tree exceeds the file count limit")
    if not files:
        raise SourceError("source code JSON has no sources")
    portable_paths = {path.casefold() for path in files}
    for path in files:
        parts = path.split("/")
        if any("/".join(parts[:index]).casefold() in portable_paths for index in range(1, len(parts))):
            raise SourceError(f"source path conflicts with a file parent: {path!r}")
    return files


def parse_source_code(source_code: str, contract_name: str) -> dict[str, str]:
    """Convert the SourceCode field into a path to content map across explorer shapes.

    An empty field means the contract is not verified, so fail loud.
    """
    stripped = source_code.strip()
    if not stripped:
        raise SourceError("contract source is not verified")
    if stripped.startswith("{{") and stripped.endswith("}}"):
        return _parse_json_sources(stripped[1:-1])
    if stripped.startswith("{") and stripped.endswith("}"):
        return _parse_json_sources(stripped)
    name = contract_name.strip() or "Contract"
    path = _safe_relpath(f"{name}.sol")
    if len(source_code.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise SourceError("plain contract source exceeds the per-file byte limit")
    return {path: source_code}


def parse_getsourcecode(
    payload: object,
    *,
    source: str,
    chain: str,
    chain_id: int | None,
    address: str,
    source_url: str,
    fetched_at: str,
) -> tuple[SourceMeta, dict[str, str]]:
    """Validate an explorer response and return SourceMeta plus the source tree.

    Fail loud on an error, an unverified contract, or an empty response, invariant 4. The
    caller supplies the chain context the response does not carry.
    """
    if not isinstance(payload, dict):
        raise SourceError("explorer response is not a JSON object")
    if str(payload.get("status", "")).strip() == "0":
        detail = payload.get("result") or payload.get("message") or "unknown error"
        raise SourceError(f"explorer error: {detail}")
    result = payload.get("result")
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):
        raise SourceError("explorer response has no source result")
    entry = result[0]
    files = parse_source_code(str(entry.get("SourceCode", "")), str(entry.get("ContractName", "")))
    meta = source_meta_from_dict(
        {
            "source": source,
            "chain": chain,
            "chain_id": chain_id,
            "address": address,
            "source_url": source_url,
            "contract_name": entry.get("ContractName", ""),
            "compiler_version": entry.get("CompilerVersion", ""),
            "optimization_used": entry.get("OptimizationUsed", ""),
            "runs": entry.get("Runs", ""),
            "constructor_arguments": entry.get("ConstructorArguments", ""),
            "evm_version": entry.get("EVMVersion", ""),
            "license_type": entry.get("LicenseType", ""),
            "proxy": entry.get("Proxy", ""),
            "implementation_address": entry.get("Implementation", ""),
            "fetched_at": fetched_at,
        }
    )
    if meta.proxy is True or meta.implementation_address:
        raise SourceError("proxy source acquisition requires the implementation source and is not yet supported")
    return meta, files
