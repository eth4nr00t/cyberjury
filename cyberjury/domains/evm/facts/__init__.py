"""Deterministic fact backends for the evm domain, grounded by a Slither call graph.

Importing this package never imports the heavy tools, each backend lazy-checks its own
toolchain, so the domain loads even without a Solidity compiler or Foundry present.
"""
