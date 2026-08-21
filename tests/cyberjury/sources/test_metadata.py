"""Source metadata has a stable JSON contract and explicit empty state."""

from __future__ import annotations

import json

import pytest

from cyberjury.sources import (
    SourceError,
    SourceMeta,
    source_meta_from_dict,
)


def test_source_meta_round_trips_through_json():
    """Source metadata round trips through JSON."""
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
    """Source metadata parsing fails loud on a non object."""
    with pytest.raises(SourceError, match="JSON object"):
        source_meta_from_dict(["not", "an", "object"])


def test_source_meta_from_dict_leaves_missing_fields_empty():
    """Source metadata parsing leaves missing fields empty."""
    meta = source_meta_from_dict({"chain": "bsc"})
    assert meta.chain == "bsc"
    assert meta.chain_id is None
    assert meta.optimization_used is None
    assert meta.contract_name == ""


def test_empty_meta_is_reported_empty():
    """Empty meta is reported empty."""
    assert SourceMeta().is_empty()
    assert not SourceMeta(chain="bsc").is_empty()
