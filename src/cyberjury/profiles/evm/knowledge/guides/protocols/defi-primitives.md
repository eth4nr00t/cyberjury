---
id: defi-primitives
title: DeFi Primitives
kind: protocol
detect:
  content: ["getReserves", "getAmountOut", "addLiquidity", "removeLiquidity", "borrow", "repay", "liquidate", "collateral", "healthFactor", "rewardPerToken", "getVotes", "propose", "quorum", "flashLoan"]
---

# DeFi Primitives Review Notes

## Attack Surface

Review protocol-level invariants across the common money legos: the AMM, the lending market, the
staking vault, and governance. Read the `languages/solidity` guide for the idioms. The high-value
bugs here are cross-function and cross-contract invariants, price manipulation, and transaction
ordering, so confirm each property against the real multi-step flow rather than a single function.

## Trust Boundaries

### Protocol Model

- Actors are depositors, borrowers, liquidity providers, liquidators, governance, keepers,
  price publishers, and the contracts or tokens they control.
- Assets are reserves, collateral, debt, shares, rewards, voting power, and the authority to
  change parameters or move protocol funds.
- Trust boundaries sit at public functions, token callbacks, oracle updates, governance
  execution, and every integration selected through configuration or user input.
- Follow each position through deposit, borrow, repay, accrue, liquidate, redeem, claim, and
  emergency exit. Check the invariant before and after each transition and during callbacks.

### Bindings, Expiry, Revocation, and Replay

- A quote, signature, or delegated action binds the chain, contract, account, asset, amount,
  nonce, and deadline that the transition consumes. A successful action consumes its nonce in
  the same state change.
- Time limited prices and orders reject stale data. Emergency roles and token approvals have a
  reachable revocation path that takes effect before another protected transition.
- Repeated settlement, liquidation, claim, or governance execution is either idempotent or
  rejected by durable state. A reverted external call must not leave replayable partial state.

## Review Guidance

### AMM and Pricing

- A price read from spot reserves, `getReserves`, `slot0`, or `balanceOf`, moves in one
  transaction under a flash loan. Use a manipulation-resistant source with a staleness and
  a bounds check, see the oracle-price-manipulation class.
- A swap, deposit, or redeem that enforces no minimum output and no deadline lets a
  sandwich or a stale transaction execute at an attacker-chosen price. Confirm a `minOut`
  and a deadline bind the trade.

### Lending

- Read collateral value and the health factor at action time from a sound oracle.
- A borrow cannot exceed the collateral after rounding.
- A liquidation cannot be blocked or front-run for free.
- Closing or liquidating a position updates debt and collateral accounting before any
  external transfer or token callback, see the reentrancy class.

### Staking and Rewards

- Reward accounting, the `rewardPerToken` accumulator and the per-user checkpoints, updates
  before a stake, withdraw, or claim changes the balance it is computed from, or rewards are
  over or under paid, see the accounting-precision class.

### Governance

- Voting power is read from a snapshot taken before the proposal, not the live balance, or
  a flash loan borrows votes for one block to pass a proposal. Confirm a checkpoint or
  snapshot and a timelock on execution.
- A privileged governance or parameter action is gated to the executor and timelocked, see
  the access-control class.

## Safe Boundaries

A DeFi transition is bounded when value, authority, prices, state, and one time artifacts are read
from the intended source and updated atomically before callbacks. Time limits, revocation,
manipulation resistance, and replay protection must hold across the complete multi-contract flow.
