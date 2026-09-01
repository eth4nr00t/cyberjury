"""Source fetch writes one verified tree and preserves existing output by default."""

from __future__ import annotations

import json

import pytest

import cyberjury.sources.fetch as fetchmod
from cyberjury.review.paths import repository_files
from cyberjury.review.target import resolve_repository_target
from cyberjury.sources.fetch import fetch_source
from cyberjury.sources.metadata import (
    SOURCE_ACQUISITION_FILE,
    SourceError,
    read_source_acquisition,
    source_meta_from_dict,
)

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

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


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
    assert (tree / SOURCE_ACQUISITION_FILE).exists()
    assert read_source_acquisition(tree) is not None
    acquisition = read_source_acquisition(tree)
    assert acquisition is not None
    assert resolve_repository_target(tree).source_acquisition_sha256 == acquisition.acquisition_sha256
    assert repository_files(tree) == ("Token.sol",)


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
    _fetch(tmp_path, out=out)
    replacement = _payload("contract Replacement {}\n")

    result = _fetch(tmp_path, out=out, payload=replacement, overwrite=True)

    assert (result.out_dir / "Token.sol").read_text() == "contract Replacement {}\n"


def test_fetch_overwrite_rejects_an_unowned_nonempty_directory(tmp_path):
    out = tmp_path / "target"
    out.mkdir()
    (out / "keep.txt").write_text("existing")

    with pytest.raises(SourceError, match="valid source acquisition"):
        _fetch(tmp_path, out=out, overwrite=True)

    assert (out / "keep.txt").read_text() == "existing"


def test_fetch_does_not_write_on_failure(tmp_path):
    out = tmp_path / "target"
    with pytest.raises(SourceError):
        _fetch(tmp_path, out=out, payload=_payload(""))
    assert not (out / "cyberjury-source.json").exists()


def test_fetch_staging_failure_preserves_existing_output(monkeypatch, tmp_path):
    out = tmp_path / "target"
    _fetch(tmp_path, out=out)
    before = {path.name: path.read_bytes() for path in out.iterdir()}
    original = fetchmod._write_text

    def fail_raw(path, value):
        if path.name == "explorer-raw.json":
            raise OSError("disk full")
        return original(path, value)

    monkeypatch.setattr(fetchmod, "_write_text", fail_raw)

    with pytest.raises(OSError, match="disk full"):
        _fetch(tmp_path, out=out, overwrite=True)

    assert {path.name: path.read_bytes() for path in out.iterdir()} == before
    assert not list(tmp_path.glob(".target.staging-*"))


def test_fetch_recovers_a_stale_backup_before_a_network_failure(tmp_path):
    out = tmp_path / "target"
    _fetch(tmp_path, out=out)
    backup = tmp_path / f".target.backup-{'a' * 32}"
    out.rename(backup)

    def fail_network(_url, timeout=None):
        raise OSError("offline")

    with pytest.raises(SourceError, match="explorer request failed"):
        _fetch(tmp_path, out=out, overwrite=True, opener=fail_network)

    assert read_source_acquisition(out) is not None
    assert not backup.exists()


def test_fetch_restores_a_valid_backup_over_a_partial_publication(tmp_path):
    out = tmp_path / "target"
    _fetch(tmp_path, out=out)
    backup = tmp_path / f".target.backup-{'b' * 32}"
    out.rename(backup)
    out.mkdir()
    (out / "partial.sol").write_text("partial\n")

    def fail_network(_url, timeout=None):
        raise OSError("offline")

    with pytest.raises(SourceError, match="explorer request failed"):
        _fetch(tmp_path, out=out, overwrite=True, opener=fail_network)

    assert read_source_acquisition(out) is not None
    assert not (out / "partial.sol").exists()


def test_tampered_acquisition_manifest_fails_loud(tmp_path):
    result = _fetch(tmp_path)
    manifest = result.acquisition_path
    value = json.loads(manifest.read_text())
    value["published_response_sha256"] = "0" * 64
    manifest.write_text(json.dumps(value))

    with pytest.raises(SourceError, match="published response hash"):
        read_source_acquisition(result.out_dir)


def test_verified_acquisition_rejects_an_added_source_file(tmp_path):
    result = _fetch(tmp_path)
    (result.out_dir / "Injected.sol").write_text("contract Injected {}\n")

    with pytest.raises(SourceError, match="no longer match"):
        read_source_acquisition(result.out_dir)
