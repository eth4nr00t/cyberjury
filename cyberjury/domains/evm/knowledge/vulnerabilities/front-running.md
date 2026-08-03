---
id: front-running
title: Front-Running and Slippage
lens: front-running
impact: HIGH
tags: [swc-114, front-running, mev, sandwich, slippage, fund-loss]
aliases: [mev, sandwich, slippage, frontrunning, front-run]
triggers: ["swap", "minOut", "amountOutMin", "minAmountOut", "amountOutMinimum", "deadline", "getAmountOut", "addLiquidity", "removeLiquidity", "swapExactTokensForTokens", "0, path", "claim", "harvest"]
---

# Front-Running and Slippage

A state-changing action is ordered against the victim in the mempool. A swap, deposit,
or redeem that enforces no minimum output and no deadline executes at an attacker-chosen
price, or a profitable action is observed and front-run. The classic shape is a sandwich,
the attacker buys ahead of the victim, lets the victim's trade move the price, then sells
into it. Bind every trade with a caller-supplied `minOut` and a `deadline`, and treat any
value the transaction derives from a movable on-chain source as untrusted, see the
oracle-price-manipulation class.

## Vulnerable
```solidity
function zapIn(uint256 amountIn) external {
    // minOut hardcoded to 0 and block.timestamp as the deadline, so a sandwich sets the price
    uint256[] memory out = router.swapExactTokensForTokens(
        amountIn, 0, path, address(this), block.timestamp
    );
    deposit(out[out.length - 1]);
}
```

## Secure
```solidity
function zapIn(uint256 amountIn, uint256 minOut, uint256 deadline) external {
    uint256[] memory out = router.swapExactTokensForTokens(
        amountIn, minOut, path, address(this), deadline
    );
    deposit(out[out.length - 1]);
}
```

## Not a Finding

A trade that passes the caller's `minOut` and `deadline` straight through to the router
is the expected control and is not reportable. Report it only when the slippage bound is
hardcoded to 0, the deadline is replaced with `block.timestamp` so it can never expire,
`minOut` is computed from a spot price read in the same call, or a privileged action's
ordering grants a concrete and quantifiable fund advantage. A pure view function, an
action with no economic ordering advantage, or generic mempool-visibility commentary is
not a finding.
