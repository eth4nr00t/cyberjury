# Vulnerability Class Index

Smart contract vulnerability classes for Solidity and the EVM, one file per weakness
under `vulnerabilities/`, named by the specific weakness. Each states impact, the markers
to hunt in `triggers`, and vulnerable-vs-secure examples. The diff-audit engine injects
the classes relevant to a change into the prompt. The repository-review agent reads them for
the target. A finding's `category` is one of these ids.

## Vulnerability Classes

### Value Movement
- `reentrancy` external call before state update, cross-function and read-only
- `unchecked-low-level-call` ignored `.call`/`send` return, swallowed failure
- `denial-of-service` unbounded loop, push payment, gas griefing, stuck funds

### Authorization and Upgradeability
- `access-control` missing or wrong modifier, tx.origin, public privileged function
- `proxy-delegatecall` storage collision, unprotected or re-callable initializer, untrusted delegatecall

### Economic and Accounting
- `oracle-price-manipulation` spot price or balance as price, flash-loan assisted
- `front-running` no minOut or deadline, sandwich, profitable action front-run
- `accounting-precision` rounding, division before multiplication, ERC-4626 first-depositor inflation
- `weird-erc20` fee-on-transfer, rebasing, ERC-777 callback, received below the requested amount
- `unsafe-math` unchecked-block overflow, narrowing downcast truncation

### Signatures
- `signature-replay` missing nonce, chainid, or domain separator, ecrecover malleability

### Randomness
- `bad-randomness` block.timestamp, blockhash, or prevrandao as a randomness source

Report only real, exploitable, high-confidence issues with a concrete exploit path and a
fund or control impact. Do not report gas-optimization or style notes, floating-pragma or
compiler advisories, dependency CVEs, or 0.8 checked-arithmetic overflow outside an
`unchecked` block. The set is data: add a class by dropping a new
`vulnerabilities/<id>.md` with the same frontmatter of id, title, impact, tags,
triggers, and lens, plus vulnerable and secure examples.
