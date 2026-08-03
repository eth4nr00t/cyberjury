---
id: unsafe-math
title: Unchecked Math and Unsafe Cast
lens: unsafe-math
impact: HIGH
tags: [swc-101, overflow, downcast, fund-loss]
aliases: [unchecked-math, unsafe-cast, downcast-truncation]
triggers: ["unchecked", "uint128", "uint96", "uint64", "uint32", "int128", "SafeCast", "toUint", "downcast", "overflow"]
---

# Unchecked Math and Unsafe Cast

Solidity 0.8 reverts on overflow by default, but arithmetic inside an `unchecked` block,
or any code on a pre-0.8 pragma, wraps silently. Separately, a narrowing cast such as
`uint256` to `uint128` truncates the high bits with no revert, so a large value becomes a
small one. Either corrupts accounting, a balance, a share count, or a fee, and the
contract acts on the wrong number. Keep value math checked, and use a checked cast such as
OpenZeppelin SafeCast when narrowing a width.

## Vulnerable
```solidity
function record(uint256 amount) external {
    totalShares += uint128(amount);   // a value above 2**128-1 truncates, supply under-counts
}
```

## Secure
```solidity
function record(uint256 amount) external {
    totalShares += SafeCast.toUint128(amount);   // reverts instead of truncating
}
```
