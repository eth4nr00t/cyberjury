---
id: access-control
title: Missing or Broken Access Control
lens: access-control
impact: CRITICAL
tags: [swc-105, swc-115, access-control, fund-loss]
aliases: [missing-access-control, broken-access-control]
triggers: ["onlyOwner", "function mint", "function burn", "function withdraw", "selfdestruct", "tx.origin", "require(msg.sender", "_mint", "setOwner", "transferOwnership", "function approve", "blacklist", "isBlacklisted", "whenNotPaused", "external", "public", "tradingEnabled", "enableTrading", "maxTxAmount", "maxWallet", "setFee", "setTaxFee"]
---

# Missing or Broken Access Control

A privileged function, one that moves funds, mints or burns, sets a critical parameter,
upgrades, or destroys the contract, is callable by an account that should not reach it.
The cause is a missing modifier, a modifier on the wrong function, an authorization on
`tx.origin` instead of `msg.sender`, or a check that proves the caller is some address
but not the right one. Gate every state-changing privileged function to the exact role,
and use `msg.sender`.

A security gate that some entrypoints enforce and a sibling omits is a broken invariant,
report the gap even when the omitted path does not itself move value. A token with a
blacklist, pause, or sanctions check that runs on `transfer` and `transferFrom` but not on
`approve`, `permit`, or `increaseAllowance` lets a barred account still take part in the
flow, so the control is not the invariant it claims. Enumerate the sibling entrypoints a
stated invariant should cover and name the one missing the check, do not clear it because a
later step looks gated.

Owner control that can trap a holder after they commit funds is a concrete harm, not a
style note. A one-way trading switch the owner flips on but a buyer cannot escape, a sell
tax or `maxTxAmount` the owner can raise to block or confiscate a sale, or a blacklist the
owner can add a holder to after that holder buys, all let the owner take or freeze value a
user already paid for. Report the owner-only setter when a buyer's funds are reachable and
unrecoverable through it, name the setter and the trapped path, and do not clear it merely
because the contract has an owner.

## Vulnerable
```solidity
function mint(address to, uint256 amount) external {   // no access control
    _mint(to, amount);                                  // anyone mints unlimited supply
}

function withdrawAll() external {
    require(tx.origin == owner);                         // tx.origin is phishable
    payable(msg.sender).transfer(address(this).balance);
}
```

## Secure
```solidity
function mint(address to, uint256 amount) external onlyMinter {
    _mint(to, amount);
}

function withdrawAll() external onlyOwner {             // msg.sender, scoped role
    payable(owner).transfer(address(this).balance);
}
```
