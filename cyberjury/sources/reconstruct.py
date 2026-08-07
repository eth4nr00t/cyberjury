"""Turn a block explorer getsourcecode response into a source tree and its SourceMeta.

Pure, no network and no filesystem, so tests drive it with fixtures. An explorer returns
the SourceCode field in one of three shapes: plain Solidity text, a single JSON object,
or a standard JSON input wrapped in an extra pair of braces. The paths inside come from
an untrusted response, so each is checked against traversal before it can become a file
path.
"""

from __future__ import annotations

import json
from typing import Any

from cyberjury.sources.metadata import SourceError, SourceMeta, source_meta_from_dict


def _safe_relpath(path: str) -> str:
    """A source path from the response, rejected loud if it could escape the output tree.

    so an absolute path or a `..` segment never writes outside it.
    """
    normalized = path.strip().replace("\\", "/")
    head = normalized.split("/", 1)[0]
    if not normalized or normalized.startswith("/") or ":" in head:
        raise SourceError(f"unsafe source path: {path!r}")
    parts = [seg for seg in normalized.split("/") if seg not in ("", ".")]
    if not parts or any(seg == ".." for seg in parts):
        raise SourceError(f"unsafe source path: {path!r}")
    return "/".join(parts)


def _content_of(entry: object) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("content"), str):
        return entry["content"]
    return None


def _sources_map(obj: dict[str, Any]) -> dict[str, Any]:
    """The path to entry map, whether the JSON is a standard JSON input with a sources key or.

    a direct path map.
    """
    inner = obj.get("sources")
    if isinstance(inner, dict):
        return inner
    return obj


def _parse_json_sources(text: str) -> dict[str, str]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as error:
        raise SourceError(f"source code is not valid JSON: {error}") from error
    if not isinstance(obj, dict):
        raise SourceError("source code JSON is not an object")
    files: dict[str, str] = {}
    for path, entry in _sources_map(obj).items():
        content = _content_of(entry)
        if content is None:
            raise SourceError(f"source {path!r} has no inline content")
        files[_safe_relpath(str(path))] = content
    if not files:
        raise SourceError("source code JSON has no sources")
    return files


def parse_source_code(source_code: str, contract_name: str) -> dict[str, str]:
    """The SourceCode field to a path to content map, across the three explorer shapes.

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
    return {_safe_relpath(f"{name}.sol"): source_code}


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
    """Validate an explorer getsourcecode response and split it into SourceMeta and a source.

    tree, or fail loud on an error, an unverified, or an empty response, invariant 4. The
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
    return meta, files
