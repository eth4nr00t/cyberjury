"""Source fetch writes one verified tree and preserves existing output by default."""

from __future__ import annotations

import json

import pytest

from cyberjury.sources.fetch import fetch_source
from cyberjury.sources.metadata import SourceError, source_meta_from_dict

_ADDR = "0x" + "ab" * 20

_PLAIN = "pragma solidity ^0.8.20;\ncontract Token {}\n"


def _payload(source_code: str = _PLAIN, **overrides: object) -> dict:
    entry = {
        "SourceCode": source_code,
        "ContractName": "Token",
        "CompilerVersion": "v0.8.20+commit.a1b79de6",
        "OptimizationUsed": "1",
        "Runs": "200",
        "ConstructorArguments": "",
        "EVMVersion": "Default",
        "LicenseType": "MIT",
        "Proxy": "0",
        "Implementation": "",
    }
    entry.update(overrides)
    return {"status": "1", "message": "OK", "result": [entry]}


class _FakeResponse:
    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return self._body


def _opener(payload: dict):
    def opener(url, timeout=None):
        assert "getsourcecode" in url
        return _FakeResponse(json.dumps(payload))

    return opener


def _fetch(tmp_path, payload=None, opener=None, **kwargs):
    return fetch_source(
        chain_key=kwargs.pop("chain_key", "bsc"),
        address=kwargs.pop("address", _ADDR),
        api_key=kwargs.pop("api_key", "KEY"),
        out=str(kwargs.pop("out", tmp_path / "target")),
        fetched_at="2026-07-07T00:00:00Z",
        opener=opener or _opener(payload if payload is not None else _payload()),
        **kwargs,
    )


def test_fetch_writes_tree_and_metadata(tmp_path):
    result = _fetch(tmp_path)
    assert result.file_count == 1
    tree = result.out_dir
    assert (tree / "Token.sol").read_text() == _PLAIN
    meta = source_meta_from_dict(json.loads((tree / "cyberjury-source.json").read_text()))
    assert meta.chain == "bsc"
    assert meta.chain_id == 56
    assert meta.address == _ADDR
    assert meta.source_url.endswith(f"{_ADDR}#code")
    assert (tree / "explorer-raw.json").exists()


def test_fetch_rejects_bad_address(tmp_path):
    with pytest.raises(SourceError):
        _fetch(tmp_path, address="0xnothex")


def test_fetch_requires_api_key(tmp_path):
    with pytest.raises(SourceError):
        _fetch(tmp_path, api_key="")


def test_fetch_fails_loud_on_unverified(tmp_path):
    with pytest.raises(SourceError):
        _fetch(tmp_path, payload=_payload("", ABI="Contract source code not verified"))


def test_fetch_refuses_non_empty_out_without_overwrite(tmp_path):
    out = tmp_path / "target"
    out.mkdir()
    (out / "keep.txt").write_text("existing")
    with pytest.raises(SourceError):
        _fetch(tmp_path, out=out)


def test_fetch_overwrite_allows_non_empty_out(tmp_path):
    out = tmp_path / "target"
    out.mkdir()
    (out / "keep.txt").write_text("existing")
    result = _fetch(tmp_path, out=out, overwrite=True)
    assert (result.out_dir / "Token.sol").exists()
    assert not (result.out_dir / "keep.txt").exists()


def test_fetch_does_not_write_on_failure(tmp_path):
    out = tmp_path / "target"
    with pytest.raises(SourceError):
        _fetch(tmp_path, out=out, payload=_payload(""))
    assert not (out / "cyberjury-source.json").exists()
