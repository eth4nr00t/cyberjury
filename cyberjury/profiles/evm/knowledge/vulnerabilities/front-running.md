---
id: front-running
title: Front-Running and Slippage
impact: HIGH
tags: [swc-114, front-running, mev, sandwich, slippage, fund-loss]
selection_hints: ["minOut", "amountOutMin", "minAmountOut", "amountOutMinimum", "deadline", "slippage", "MEV", "sandwich", "front-run", "getAmountOut", "swapExactTokensForTokens", "addLiquidity", "removeLiquidity", "claim", "harvest"]
aliases: [front-run, frontrunning, mev, sandwich, slippage]
---

# Front-Running and Slippage

## Security Condition

A swap, deposit, or redemption with no caller chosen minimum output can execute at an
attacker-chosen price after adversarial mempool ordering. A missing deadline also leaves a stale
quote executable. In a sandwich, the attacker trades before and after the victim for a concrete
profit.

## Review Guidance

Bind the action to a caller supplied `minOut` and `deadline`. Treat a bound derived from a movable
spot price in the same call as untrusted, as described by oracle-price-manipulation.

## Examples

### Slippage and Deadline Binding

```solidity
pragma solidity ^0.8.20;

interface SwapRouter {
    function swapNative(uint256 minOut, uint256 deadline) external payable returns (uint256);
}

contract VulnerableSwap {
    SwapRouter public immutable router;

    constructor(SwapRouter trustedRouter) {
        router = trustedRouter;
    }

    function execute() external payable returns (uint256) {
        return router.swapNative{value: msg.value}(0, block.timestamp);
    }
}

contract SecureSwap {
    SwapRouter public immutable router;

    constructor(SwapRouter trustedRouter) {
        router = trustedRouter;
    }

    function execute(uint256 minOut, uint256 deadline) external payable returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "expired");
        amountOut = router.swapNative{value: msg.value}(minOut, deadline);
        require(amountOut >= minOut, "slippage");
    }
}
```

## Not a Finding

A trade is safe when it passes the caller's `minOut` and `deadline` to the router. Report a zero
bound, a deadline replaced with `block.timestamp`, a bound derived from the same spot price, or
another concrete ordering advantage. A view function, an action with no economic advantage, and
generic mempool visibility are not findings.
