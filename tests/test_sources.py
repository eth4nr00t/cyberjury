"""The SourceMeta data class and the pure explorer parser.

No network and no filesystem, the parser is driven with inline fixtures shaped
like a block explorer getsourcecode response.
"""

from __future__ import annotations

import json

import pytest

from cyberjury.sources import (
    SourceError,
    SourceMeta,
    parse_getsourcecode,
    parse_source_code,
    source_meta_from_dict,
)

_PLAIN = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Token {}\n"

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


def test_source_meta_round_trips_through_json():
    meta = SourceMeta(
        source="bscscan",
        chain="bsc",
        chain_id=56,
        address="0xabc",
        contract_name="Token",
        optimization_used=True,
        runs=200,
        proxy=False,
    )
    back = source_meta_from_dict(json.loads(meta.to_json()))
    assert back == meta


def test_source_meta_from_dict_fails_loud_on_non_object():
    with pytest.raises(SourceError):
        source_meta_from_dict(["not", "an", "object"])


def test_source_meta_from_dict_leaves_missing_fields_empty():
    meta = source_meta_from_dict({"chain": "bsc"})
    assert meta.chain == "bsc"
    assert meta.chain_id is None
    assert meta.optimization_used is None
    assert meta.contract_name == ""


def test_empty_meta_is_reported_empty():
    assert SourceMeta().is_empty()
    assert not SourceMeta(chain="bsc").is_empty()


def test_parse_plain_solidity_names_file_from_contract():
    files = parse_source_code(_PLAIN, "Token")
    assert files == {"Token.sol": _PLAIN}


def test_parse_plain_solidity_without_name_falls_back():
    files = parse_source_code(_PLAIN, "")
    assert set(files) == {"Contract.sol"}


def test_parse_standard_json_input_double_brace():
    wrapped = "{" + json.dumps(_STANDARD_JSON) + "}"
    files = parse_source_code(wrapped, "Token")
    assert set(files) == {"contracts/Token.sol", "contracts/lib/Math.sol"}
    assert files["contracts/Token.sol"] == "contract Token {}"


def test_parse_single_json_with_sources_key():
    files = parse_source_code(json.dumps(_STANDARD_JSON), "Token")
    assert set(files) == {"contracts/Token.sol", "contracts/lib/Math.sol"}


def test_parse_single_json_direct_path_map():
    files = parse_source_code(json.dumps(_DIRECT_MAP), "Token")
    assert set(files) == {"Token.sol", "Ownable.sol"}


def test_parse_empty_source_is_unverified():
    with pytest.raises(SourceError):
        parse_source_code("   ", "Token")


@pytest.mark.parametrize("bad", ["../evil.sol", "/etc/passwd", "C:/win.sol", "a/../../x.sol"])
def test_parse_rejects_unsafe_paths(bad):
    payload = json.dumps({bad: {"content": "x"}})
    with pytest.raises(SourceError):
        parse_source_code(payload, "Token")


def test_parse_rejects_source_without_inline_content():
    payload = json.dumps({"sources": {"Token.sol": {"urls": ["ipfs://x"]}}})
    with pytest.raises(SourceError):
        parse_source_code(payload, "Token")


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
    with pytest.raises(SourceError):
        _parse({"status": "0", "message": "NOTOK", "result": "Invalid API Key"})


def test_getsourcecode_fails_loud_on_unverified():
    with pytest.raises(SourceError):
        _parse(_response("", ABI="Contract source code not verified"))


def test_getsourcecode_fails_loud_on_missing_result():
    with pytest.raises(SourceError):
        _parse({"status": "1", "message": "OK", "result": []})
