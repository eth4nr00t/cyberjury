---
id: reentrancy
title: Reentrancy
lens: reentrancy
impact: CRITICAL
tags: [swc-107, reentrancy, fund-loss]
aliases: [read-only-reentrancy]
triggers: [".call{value", ".call(", "transfer(", "send(", "external call", "balances[", "withdraw", "nonReentrant", "safeTransfer", "onERC721Received", "tokensToSend", "tokensReceived", "ERC777", "buyout", "before state", "get_virtual_price", "getReserves", "getRate", "sharePrice", "view returns", "balanceOf(address(this))"]
---

# Reentrancy

An external call hands control to the callee before the contract finishes updating its
own state, so the callee can call back in and act on the stale pre-update state. The
classic form drains a balance by re-entering a withdraw before the balance is zeroed.
Cross-function reentrancy re-enters a different function that shares the same state, and
read-only reentrancy reads a view mid-update from another protocol. The read-only form
needs no state write in the reentered call: a price or share view such as a Curve
`get_virtual_price`, a Balancer `getRate`, or a `getReserves` or `balanceOf(address(this))`
spot read returns a stale value while a withdraw or exit has sent value but not yet synced
its reserves, and a consumer that prices collateral off that view is fooled. Write state
before the external call, or guard with `nonReentrant`, and remember a guard on the mutating
function does not stop the cross-contract read-only form, the view must be consistent at the
moment of the external call.

A token transfer is an external call too. An ERC-777 token runs a `tokensToSend` hook on
the sender and a `tokensReceived` hook on the recipient, and other tokens add their own
transfer callback, so a plain `transfer` or `safeTransfer` of an ERC-20 can hand control to
an attacker exactly like a raw `call`. Treat any token whose address is not a fixed trusted
constant as possibly hook bearing and check every token-move path for reentrancy, not only
the `call{value}` paths. Clearing a path because the token is assumed to be a normal ERC-20
with no hook is an assumed off-file control unless the token set is pinned to a known
allowlist, so keep the finding, see the recall red line.

Ordering effects before interactions in the one function under review is not enough on its
own. A transfer hook can reenter a different function that reads or writes the same position,
loan, or reserve while this flow is only half finished, the cross-function form, so trace
where control can go during every transfer and check the whole flow's invariants, not just
the local ones. In a lending, auction, or buyout flow that pays the current holder before it
finalizes the position's terms, that payout is the callback window, so audit the order of
the payout against the state writes.

## Vulnerable
```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");   // call before the state update
    require(ok);
    balances[msg.sender] = 0;                          // too late, attacker reentered
}
```

## Secure
```solidity
function withdraw() external nonReentrant {
    uint256 bal = balances[msg.sender];
    balances[msg.sender] = 0;                          // effects before interaction
    (bool ok, ) = msg.sender.call{value: bal}("");
    require(ok);
}
```
