---
id: unsafe-math
title: Unchecked Math and Unsafe Cast
impact: HIGH
tags: [swc-101, overflow, downcast, fund-loss]
selection_hints: ["unchecked {", "unchecked", "uint128(", "uint96(", "uint64(", "uint32(", "int128(", "SafeCast", "toUint", "toInt", "downcast", "overflow"]
aliases: [unchecked-math, unsafe-cast, downcast-truncation]
---

# Unchecked Math and Unsafe Cast

Solidity 0.8 arithmetic reverts on overflow except inside `unchecked`, while pre-0.8 arithmetic
wraps. A narrowing cast still truncates high bits without reverting. Either can corrupt balances,
shares, or fees. Keep value math checked and prove the range before narrowing.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableAccounting {
    uint128 public totalShares;

    function record(uint256 amount) external {
        totalShares += uint128(amount);
    }
}

contract SecureAccounting {
    uint128 public totalShares;

    function record(uint256 amount) external {
        require(amount <= type(uint128).max, "cast overflow");
        totalShares += uint128(amount);
    }
}
```

## Not a Finding

Solidity 0.8 arithmetic outside `unchecked` is not reportable for overflow. Unchecked math is safe
when readable bounds prove every result fits. A narrowing cast is safe when a checked cast or
preceding range check proves the value fits its destination type.
