---
id: defi-primitives
title: DeFi Primitives
kind: protocol
detect:
  content: ["getReserves", "getAmountOut", "addLiquidity", "removeLiquidity", "borrow", "repay", "liquidate", "collateral", "healthFactor", "rewardPerToken", "getVotes", "propose", "quorum", "flashLoan"]
---
# DeFi Primitive Review Notes

Protocol-level invariants for the common money legos, the AMM, the lending market, the
staking vault, and governance. Read the `languages/solidity` guide for the idioms. The
high-value bugs here are cross-function and cross-contract invariants, price manipulation,
and transaction ordering, so confirm each property against the real multi-step flow rather
than a single function.

## AMM and Pricing
- A price read from spot reserves, `getReserves`, `slot0`, or `balanceOf`, moves in one
  transaction under a flash loan. Use a manipulation-resistant source with a staleness and
  a bounds check, see the oracle-price-manipulation class.
- A swap, deposit, or redeem that enforces no minimum output and no deadline lets a
  sandwich or a stale transaction execute at an attacker-chosen price. Confirm a `minOut`
  and a deadline bind the trade.

## Lending
- Collateral value and the health factor are read at action time from a sound oracle, a
  borrow cannot exceed the collateral after rounding, and a liquidation cannot be blocked
  or front-run for free.
- Closing or liquidating a position updates debt and collateral accounting before any
  external transfer or token callback, see the reentrancy class.

## Staking and Rewards
- Reward accounting, the `rewardPerToken` accumulator and the per-user checkpoints, updates
  before a stake, withdraw, or claim changes the balance it is computed from, or rewards are
  over or under paid, see the accounting-precision class.

## Governance
- Voting power is read from a snapshot taken before the proposal, not the live balance, or
  a flash loan borrows votes for one block to pass a proposal. Confirm a checkpoint or
  snapshot and a timelock on execution.
- A privileged governance or parameter action is gated to the executor and timelocked, see
  the access-control class.
