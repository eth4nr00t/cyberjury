"""Source reconstruction tests cover explorer responses and source trees."""

from __future__ import annotations

import json

import pytest

from cyberjury.sources import (
    SourceError,
    SourceMeta,
    parse_getsourcecode,
    parse_source_code,
)

_PLAIN = "pragma solidity ^0.8.20;\ncontract Token {}\n"

_STANDARD_JSON = {
    "language": "Solidity",
    "sources": {
        "contracts/Token.sol": {"content": "contract Token {}"},
        "contracts/lib/Math.sol": {"content": "library Math {}"},
    },
    "settings": {"optimizer": {"enabled": True, "runs": 200}},
}

_DIRECT_MAP = {
    "Token.sol": {"content": "contract Token {}"},
    "Ownable.sol": {"content": "contract Ownable {}"},
}


def test_parse_plain_solidity_names_file_from_contract():
    """Plain Solidity parsing names the file from the contract."""
    files = parse_source_code(_PLAIN, "Token")
    assert files == {"Token.sol": _PLAIN}


def test_parse_plain_solidity_without_name_falls_back():
    """Plain Solidity parsing falls back when the name is missing."""
    files = parse_source_code(_PLAIN, "")
    assert set(files) == {"Contract.sol"}


def test_parse_standard_json_input_double_brace():
    """Standard JSON input parsing handles double braces."""
    wrapped = "{" + json.dumps(_STANDARD_JSON) + "}"
    files = parse_source_code(wrapped, "Token")
    assert set(files) == {"contracts/Token.sol", "contracts/lib/Math.sol"}
    assert files["contracts/Token.sol"] == "contract Token {}"


def test_parse_single_json_with_sources_key():
    """Single JSON parsing accepts a sources key."""
    files = parse_source_code(json.dumps(_STANDARD_JSON), "Token")
    assert set(files) == {"contracts/Token.sol", "contracts/lib/Math.sol"}


def test_parse_single_json_direct_path_map():
    """Single JSON parsing accepts a direct path map."""
    files = parse_source_code(json.dumps(_DIRECT_MAP), "Token")
    assert set(files) == {"Token.sol", "Ownable.sol"}


def test_parse_empty_source_is_unverified():
    with pytest.raises(SourceError, match="not verified"):
        parse_source_code("   ", "Token")


@pytest.mark.parametrize("bad", ["../evil.sol", "/etc/passwd", "C:/win.sol", "a/../../x.sol"])
def test_parse_rejects_unsafe_paths(bad):
    payload = json.dumps({bad: {"content": "x"}})
    with pytest.raises(SourceError, match="unsafe source path"):
        parse_source_code(payload, "Token")


def test_parse_rejects_source_without_inline_content():
    payload = json.dumps({"sources": {"Token.sol": {"urls": ["ipfs://x"]}}})
    with pytest.raises(SourceError, match="no inline content"):
        parse_source_code(payload, "Token")


def _response(source_code: str, **overrides: object) -> dict:
    entry = {
        "SourceCode": source_code,
        "ContractName": "Token",
        "CompilerVersion": "v0.8.20+commit.a1b79de6",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "00ff",
        "EVMVersion": "Default",
        "LicenseType": "MIT",
        "Proxy": "0",
        "Implementation": "",
    }
    entry.update(overrides)
    return {"status": "1", "message": "OK", "result": [entry]}


def _parse(payload: dict) -> tuple[SourceMeta, dict[str, str]]:
    return parse_getsourcecode(
        payload,
        source="bscscan",
        chain="bsc",
        chain_id=56,
        address="0xabc",
        source_url="https://bscscan.com/address/0xabc#code",
        fetched_at="2026-07-07T00:00:00Z",
    )


def test_getsourcecode_builds_meta_and_tree():
    """Parsing getsourcecode builds metadata and a source tree."""
    meta, files = _parse(_response(_PLAIN))
    assert files == {"Token.sol": _PLAIN}
    assert meta.chain == "bsc"
    assert meta.chain_id == 56
    assert meta.contract_name == "Token"
    assert meta.optimization_used is True
    assert meta.runs == 200
    assert meta.proxy is False
    assert meta.fetched_at == "2026-07-07T00:00:00Z"


def test_getsourcecode_fails_loud_on_error_status():
    """Parsing getsourcecode fails loud on an error status."""
    with pytest.raises(SourceError):
        _parse({"status": "0", "message": "NOTOK", "result": "Invalid API Key"})


def test_getsourcecode_fails_loud_on_unverified():
    """Parsing getsourcecode fails loud on unverified source."""
    with pytest.raises(SourceError):
        _parse(_response("", ABI="Contract source code not verified"))


def test_getsourcecode_fails_loud_on_missing_result():
    """Parsing getsourcecode fails loud on a missing result."""
    with pytest.raises(SourceError):
        _parse({"status": "1", "message": "OK", "result": []})
