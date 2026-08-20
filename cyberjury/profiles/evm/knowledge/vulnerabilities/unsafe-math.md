---
id: unsafe-math
title: Unchecked Math and Unsafe Cast
impact: HIGH
tags: [swc-101, overflow, downcast, fund-loss]
selection_hints: ["unchecked {", "unchecked", "uint128(", "uint96(", "uint64(", "uint32(", "int128(", "SafeCast", "toUint", "toInt", "downcast", "overflow"]
aliases: [unchecked-math, unsafe-cast, downcast-truncation]
---

# Unchecked Math and Unsafe Cast

Unchecked arithmetic and narrowing casts bypass different range protections. Both become findings
when attacker controlled values can corrupt a balance, share, fee, limit, or authorization
invariant.

## Arithmetic Wraparound

Solidity 0.8 reverts on arithmetic overflow unless the operation is inside `unchecked`. Earlier
compiler versions wrap ordinary arithmetic too. Without a proven bound, subtraction can turn an
insufficient credit into a near maximum value.

```solidity
pragma solidity ^0.8.20;

contract VulnerableUncheckedCredit {
    mapping(address => uint256) public credit;

    function debit(uint256 amount) external {
        unchecked {
            credit[msg.sender] -= amount;
        }
    }
}

contract SecureCheckedCredit {
    mapping(address => uint256) public credit;

    function debit(uint256 amount) external {
        credit[msg.sender] -= amount;
    }
}
```

## Narrowing Cast Truncation

Converting to a smaller integer type discards high bits without reverting. Prove the source value
fits before casting or use a checked cast helper whose implementation is visible.

```solidity
pragma solidity ^0.8.20;

contract VulnerableNarrowingCast {
    uint128 public totalShares;

    function record(uint256 amount) external {
        totalShares += uint128(amount);
    }
}

contract SecureNarrowingCast {
    uint128 public totalShares;

    function record(uint256 amount) external {
        require(amount <= type(uint128).max, "cast overflow");
        totalShares += uint128(amount);
    }
}
```

## Not a Finding

Solidity 0.8 arithmetic outside `unchecked` is not reportable for wraparound. Unchecked math is
safe when readable bounds prove every result fits and the bounds hold on every reachable path. A
narrowing cast is safe when a preceding range check or readable checked cast proves the value fits
the destination type.
