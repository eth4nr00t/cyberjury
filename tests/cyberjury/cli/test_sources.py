"""Source fetch commands report explorer failures before writing a target tree."""

from __future__ import annotations

import json

from cyberjury.cli import main

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


def test_cli_fetch_source_writes_tree(tmp_path, monkeypatch, capsys):
    """CLI fetch source writes tree."""
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload())))
    out = tmp_path / "target"
    rc = main(["fetch", "source", "--chain", "bsc", "--address", _ADDR, "--out", str(out), "--api-key", "KEY"])
    assert rc == 0
    assert (out / "Token.sol").exists()
    assert (out / "cyberjury-source.json").exists()
    assert "Fetched 1 source file" in capsys.readouterr().out


def test_cli_fetch_source_fails_loud_on_unverified(tmp_path, monkeypatch):
    """CLI fetch source fails loud on unverified."""
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=None: _FakeResponse(json.dumps(_payload(""))))
    rc = main(["fetch", "source", "--address", _ADDR, "--out", str(tmp_path / "target"), "--api-key", "KEY"])
    assert rc == 1


def test_cli_fetch_without_subcommand_shows_usage(capsys):
    """CLI fetch without subcommand shows usage."""
    rc = main(["fetch"])
    assert rc == 1
    assert "fetch source" in capsys.readouterr().err
