"""Canonical hashes identify persisted content independent of mapping key order."""

import hashlib

import pytest

from cyberjury.canonical import canonical_sha256


def test_canonical_hash_ignores_mapping_key_order_but_not_list_order():
    """Reordered keys keep the hash, and a reordered list changes it."""
    value = {"a": 1, "b": [1, 2]}

    assert canonical_sha256({"b": [1, 2], "a": 1}) == canonical_sha256(value)
    assert canonical_sha256({"a": 1, "b": [2, 1]}) != canonical_sha256(value)


def test_canonical_hash_is_the_sha256_of_compact_sorted_unescaped_json():
    """The hash equals sha256 of the sorted, separator-compact JSON text that keeps é unescaped."""
    expected = hashlib.sha256('{"a":[1.5,null],"b":"é"}'.encode()).hexdigest()

    assert canonical_sha256({"b": "é", "a": [1.5, None]}) == expected


def test_canonical_hash_rejects_a_non_finite_number():
    """A NaN value raises instead of hashing a non-JSON encoding."""
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_sha256({"value": float("nan")})
