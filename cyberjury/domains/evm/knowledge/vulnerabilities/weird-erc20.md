---
id: weird-erc20
title: Weird ERC-20 Behavior
lens: weird-erc20
impact: HIGH
tags: [fee-on-transfer, rebasing, erc777, accounting, fund-loss]
aliases: [fee-on-transfer, deflationary-token, rebasing-token, erc777-hook]
triggers: ["transferFrom", "transfer(", "balanceOf", "amount", "ERC777", "tokensReceived", "tokensToSend", "rebas", "fee", "safeTransferFrom", "received", "_rOwned", "_tOwned", "reflectionFromToken", "isExcluded", "_reflectFee"]
---

# Weird ERC-20 Behavior

A contract that integrates an arbitrary token often assumes the token moves exactly the
requested `amount`, returns true, and never hands back control. Many real tokens break
those assumptions. A fee-on-transfer or deflationary token delivers less than `amount`,
so crediting the caller the requested amount over-credits a deposit and inflates shares,
balances, or accounting against the pool. A rebasing token changes balances out from
under a stored amount, so a figure recorded at deposit no longer matches the real
balance. An ERC-777 token runs a `tokensReceived` or `tokensToSend` hook inside a plain
`transfer` or `transferFrom`, handing control to a party the caller chooses, which is a
reentrancy vector covered in reentrancy. The boundary with unchecked-low-level-call is
that the return value here is honored, the bug is that the amount moved is not the amount
assumed. For value that must be exact, measure the real balance delta across the transfer
rather than trusting the requested amount, and treat a token address that is not one
fixed constant as possibly any of these.

A reflection token, or one with an owner-set transfer fee, breaks the same assumptions from
the inside. A reflection token holds balances in a scaled space, `_rOwned` against a
shrinking rate, so `balanceOf`
drifts between transfers and an account marked excluded is accounted a different way, which
desynchronizes any integrator that snapshots a balance. An owner-set transfer fee means the
delivered amount is not fixed and can change under the integrator after the fact. Measure
the real balance delta and do not assume a token's fee or balance is constant.

## Vulnerable
```solidity
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    shares[msg.sender] += amount;        // credits the requested amount, a fee token delivered less
}
```

## Secure
```solidity
function deposit(uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    shares[msg.sender] += received;       // credit only what actually arrived
}
```
