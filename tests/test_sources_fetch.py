"""The explorer HTTP layer and the fetch orchestration.

A fake opener stands in for the network, so no test reaches out. The fetch path writes a
source tree plus metadata and fails loud on every bad input.
"""

from __future__ import annotations

import json

import pytest

from cyberjury.cli import main
from cyberjury.sources.explorer import chain_for, fetch_getsourcecode
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


def _raising_opener(error: Exception):
    def opener(url, timeout=None):
        raise error

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


def test_chain_for_rejects_unknown_chain():
    """Exercise the chain for rejects unknown chain case."""
    with pytest.raises(SourceError):
        chain_for("dogecoin")


def test_getsourcecode_uses_etherscan_v2_endpoint_with_chainid():
    """Exercise the getsourcecode uses etherscan v2 endpoint with chainid case."""
    seen = {}

    def opener(url, timeout=None):
        seen["url"] = url
        return _FakeResponse(json.dumps(_payload()))

    fetch_getsourcecode(chain_for("bsc"), _ADDR, "KEY", opener=opener)
    assert seen["url"].startswith("https://api.etherscan.io/v2/api?")
    assert "chainid=56" in seen["url"]
    assert "api.bscscan.com" not in seen["url"]


def test_fetch_getsourcecode_fails_loud_on_non_json():
    """Exercise the fetch getsourcecode fails loud on non json case."""
    chain = chain_for("bsc")

    def opener(url, timeout=None):
        return _FakeResponse("<html>rate limited</html>")

    with pytest.raises(SourceError):
        fetch_getsourcecode(chain, _ADDR, "KEY", opener=opener)


def test_fetch_getsourcecode_fails_loud_on_network_error():
    """Exercise the fetch getsourcecode fails loud on network error case."""
    chain = chain_for("bsc")
    with pytest.raises(SourceError):
        fetch_getsourcecode(chain, _ADDR, "KEY", opener=_raising_opener(OSError("no route")))


def test_fetch_writes_tree_and_metadata(tmp_path):
    """Exercise the fetch writes tree and metadata case."""
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
    """Exercise the fetch rejects bad address case."""
    with pytest.raises(SourceError):
        _fetch(tmp_path, address="0xnothex")


def test_fetch_requires_api_key(tmp_path):
    """Exercise the fetch requires api key case."""
    with pytest.raises(SourceError):
        _fetch(tmp_path, api_key="")


def test_fetch_fails_loud_on_unverified(tmp_path):
    """Exercise the fetch fails loud on unverified case."""
    with pytest.raises(SourceError):
        _fetch(tmp_path, payload=_payload("", ABI="Contract source code not verified"))


def test_fetch_refuses_non_empty_out_without_overwrite(tmp_path):
    """Exercise the fetch refuses non empty out without overwrite case."""
    out = tmp_path / "target"
    out.mkdir()
    (out / "keep.txt").write_text("existing")
    with pytest.raises(SourceError):
        _fetch(tmp_path, out=out)


def test_fetch_overwrite_allows_non_empty_out(tmp_path):
    """Exercise the fetch overwrite allows non empty out case."""
    out = tmp_path / "target"
    out.mkdir()
    (out / "keep.txt").write_text("existing")
    result = _fetch(tmp_path, out=out, overwrite=True)
    assert (result.out_dir / "Token.sol").exists()


def test_fetch_does_not_write_on_failure(tmp_path):
    """Exercise the fetch does not write on failure case."""
    out = tmp_path / "target"
    with pytest.raises(SourceError):
        _fetch(tmp_path, out=out, payload=_payload(""))
    assert not (out / "cyberjury-source.json").exists()


def test_cli_fetch_source_writes_tree(tmp_path, monkeypatch, capsys):
    """Exercise the cli fetch source writes tree case."""
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload())))
    out = tmp_path / "target"
    rc = main(["fetch", "source", "--chain", "bsc", "--address", _ADDR, "--out", str(out), "--api-key", "KEY"])
    assert rc == 0
    assert (out / "Token.sol").exists()
    assert (out / "cyberjury-source.json").exists()
    assert "Fetched 1 source file" in capsys.readouterr().out


def test_cli_fetch_source_fails_loud_on_unverified(tmp_path, monkeypatch):
    """Exercise the cli fetch source fails loud on unverified case."""
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload(""))))
    rc = main(["fetch", "source", "--address", _ADDR, "--out", str(tmp_path / "target"), "--api-key", "KEY"])
    assert rc == 1


def test_cli_fetch_without_subcommand_shows_usage(capsys):
    """Exercise the cli fetch without subcommand shows usage case."""
    rc = main(["fetch"])
    assert rc == 1
    assert "fetch source" in capsys.readouterr().err


def test_cli_diff_source_meta_shows_target(tmp_path, capsys):
    """Exercise the cli diff source meta shows target case."""
    meta = tmp_path / "cyberjury-source.json"
    meta.write_text(json.dumps({"chain": "bsc", "chain_id": 56, "address": _ADDR}))
    rc = main(["review", "diff", "--dry-run", "--format", "markdown", "--source-meta", str(meta)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "## Target" in out
    assert "Chain: bsc" in out


def test_cli_diff_source_meta_missing_file_fails_loud(tmp_path, capsys):
    """Exercise the cli diff source meta missing file fails loud case."""
    rc = main(["review", "diff", "--dry-run", "--source-meta", str(tmp_path / "nope.json")])
    assert rc == 1
