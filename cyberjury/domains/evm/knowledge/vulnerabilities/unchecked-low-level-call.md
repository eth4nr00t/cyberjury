---
id: unchecked-low-level-call
title: Unchecked Low-Level Call
lens: unchecked-low-level-call
impact: HIGH
tags: [swc-104, low-level-call, return-value, fund-loss]
aliases: [unchecked-call, unchecked-return]
triggers: [".call(", ".call{value", ".delegatecall(", ".send(", "transfer(", "bool success", "bool ok", "(bool", "safeTransfer", "returndata", "returndatacopy", "abi.decode(returndata", "excessivelySafeCall"]
---

# Unchecked Low-Level Call

A low-level `.call`, `.delegatecall`, or `.send` returns success as a boolean rather than
reverting on failure. Ignoring that return value lets a failed transfer or call pass
silently, so the contract proceeds as if value moved when it did not, the accounting and
the reality diverge, and funds are credited or marked sent without leaving. Likewise a
raw ERC-20 `transfer` on a token that returns false on failure, or returns nothing, must
be checked or wrapped with SafeERC20. Check every low-level return, or use a wrapper that
reverts.

The mirror risk is trusting the returned data rather than the boolean: a callee can return
an enormous bytes blob so that copying it, an implicit `returndatacopy` or an
`abi.decode(returndata, ...)`, burns all forwarded gas and griefs the caller, the return-bomb.
When the return payload is attacker-influenced, cap the copied size or use an
`excessivelySafeCall` style helper, and never let a callee's return data dictate gas.

## Vulnerable
```solidity
function payout(address to, uint256 amount) external {
    to.call{value: amount}("");          // return value ignored, a failed send looks successful
    paid[to] += amount;                   // credited even though nothing left the contract
}
```

## Secure
```solidity
function payout(address to, uint256 amount) external {
    (bool ok, ) = to.call{value: amount}("");
    require(ok, "transfer failed");       // failure reverts, accounting stays true
    paid[to] += amount;
}
```
