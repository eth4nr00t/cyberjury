"""Verified source fetch for the Etherscan family of explorers over stdlib HTTP.

Etherscan API V2 serves every supported chain from one endpoint with a `chainid`
parameter and one Etherscan key, so the per-chain V1 hosts such as api.bscscan.com are
gone. The table maps a chain to its id, its explorer web URL for the report's Source
link, and a provenance label. Network code stays here and in the CLI, never in the
review engine.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass

from cyberjury.sources.metadata import SourceError

_TIMEOUT = 30
_API_BASE = "https://api.etherscan.io/v2/api"


@dataclass(frozen=True)
class Chain:
    """Explorer routing metadata for one supported chain."""

    key: str
    chain_id: int
    address_url: str
    source: str


CHAINS: dict[str, Chain] = {
    "arbitrum": Chain("arbitrum", 42161, "https://arbiscan.io/address/{address}#code", "arbiscan"),
    "bsc": Chain("bsc", 56, "https://bscscan.com/address/{address}#code", "bscscan"),
    "eth": Chain("eth", 1, "https://etherscan.io/address/{address}#code", "etherscan"),
    "polygon": Chain("polygon", 137, "https://polygonscan.com/address/{address}#code", "polygonscan"),
}


def chain_for(key: str) -> Chain:
    """Resolve an explorer chain name to its routing metadata."""
    chain = CHAINS.get(key.strip().lower())
    if chain is None:
        raise SourceError(f"unsupported chain {key!r}, one of: {', '.join(sorted(CHAINS))}")
    return chain


def fetch_getsourcecode(chain: Chain, address: str, api_key: str, *, opener=None) -> dict:
    """The raw getsourcecode payload for an address.

    or fail loud on a network failure or a non-JSON response, invariant 4. The opener is
    injectable so tests never touch the network, and resolves at call time so a monkeypatch
    on urllib takes effect.
    """
    if opener is None:
        opener = urllib.request.urlopen
    query = urllib.parse.urlencode(
        {
            "chainid": chain.chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        }
    )
    url = f"{_API_BASE}?{query}"
    try:
        with opener(url, timeout=_TIMEOUT) as response:
            body = response.read().decode("utf-8")
    except OSError as error:
        raise SourceError(f"explorer request failed: {error}") from error
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise SourceError(f"explorer response is not JSON: {error}") from error
    if not isinstance(payload, dict):
        raise SourceError("explorer response is not a JSON object")
    return payload
