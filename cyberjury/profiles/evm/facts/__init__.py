"""Expose the EVM facts backend while keeping Slither lazy."""

from cyberjury.profiles.evm.facts.backend import SlitherFacts

__all__ = ["SlitherFacts"]
