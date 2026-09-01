"""Explorer API calls reject unknown chains and malformed responses."""

from __future__ import annotations

import json

import pytest

import cyberjury.sources.explorer as explorermod
from cyberjury.sources.explorer import chain_for, fetch_getsourcecode
from cyberjury.sources.metadata import SourceError

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


def _raising_opener(error: Exception):
    def opener(url, timeout=None):
        raise error

    return opener


def test_chain_for_rejects_unknown_chain():
    """The chain lookup rejects an unknown chain."""
    with pytest.raises(SourceError, match="unsupported chain"):
        chain_for("dogecoin")


def test_getsourcecode_uses_etherscan_v2_endpoint_with_chainid():
    """The getsourcecode call uses the Etherscan v2 endpoint and chainid."""
    seen = {}

    def opener(url, timeout=None):
        seen["url"] = url
        return _FakeResponse(json.dumps(_payload()))

    fetch_getsourcecode(chain_for("bsc"), _ADDR, "KEY", opener=opener)
    assert seen["url"].startswith("https://api.etherscan.io/v2/api?")
    assert "chainid=56" in seen["url"]
    assert "api.bscscan.com" not in seen["url"]


def test_fetch_getsourcecode_fails_loud_on_non_json():
    """Fetching getsourcecode fails loud on non JSON."""
    chain = chain_for("bsc")

    def opener(url, timeout=None):
        return _FakeResponse("<html>rate limited</html>")

    with pytest.raises(SourceError, match="not JSON"):
        fetch_getsourcecode(chain, _ADDR, "KEY", opener=opener)


def test_fetch_getsourcecode_fails_loud_on_network_error():
    chain = chain_for("bsc")
    with pytest.raises(SourceError):
        fetch_getsourcecode(chain, _ADDR, "KEY", opener=_raising_opener(OSError("no route")))


def test_fetch_getsourcecode_bounds_the_response_before_json_parsing(monkeypatch):
    monkeypatch.setattr(explorermod, "_MAX_RESPONSE_BYTES", 10)

    with pytest.raises(SourceError, match="byte limit"):
        fetch_getsourcecode(chain_for("bsc"), _ADDR, "KEY", opener=lambda *_args, **_kwargs: _FakeResponse("x" * 11))


def test_fetch_getsourcecode_rejects_duplicate_outer_json_keys():
    response = '{"status":"1","status":"0","result":[]}'

    with pytest.raises(SourceError, match="duplicate JSON key"):
        fetch_getsourcecode(chain_for("bsc"), _ADDR, "KEY", opener=lambda *_args, **_kwargs: _FakeResponse(response))
