---
id: access-control
title: Missing or Broken Access Control
impact: CRITICAL
tags: [swc-105, swc-115, access-control, fund-loss]
selection_hints: ["onlyOwner", "Ownable", "require(msg.sender", "msg.sender == owner", "tx.origin", "function mint", "function burn", "function withdraw", "_mint", "setOwner", "transferOwnership", "setFee", "setTaxFee", "setOracle", "pause", "unpause", "blacklist", "isBlacklisted", "tradingEnabled", "enableTrading", "upgradeTo"]
aliases: [missing-access-control, broken-access-control]
---

# Missing or Broken Access Control

A privileged function that moves funds, grants authority, mints, upgrades, or changes a
critical parameter is callable by the wrong account. Causes include a missing or misplaced
modifier, a `tx.origin` check, and a sibling entrypoint that bypasses the protected path. Trace
every route to the dangerous operation and gate it to the exact role with `msg.sender`.

Owner authority is also reportable when it can trap value after a user commits funds, such as
an unrestricted sell tax or blacklist. Name the controlling setter and the path that loses or
freezes value. A preparatory action is not the reportable location when every path that consumes
its state still enforces the intended role.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableTreasury {
    function withdraw(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    receive() external payable {}
}

contract SecureTreasury {
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function withdraw(address payable recipient) external onlyOwner {
        recipient.transfer(address(this).balance);
    }

    receive() external payable {}
}
```

## Not a Finding

A privileged action is safe when every reachable path checks the exact role and no sibling path
bypasses it. An owner role alone is not a vulnerability. Report it only when an unintended caller
can gain or bypass the role, or when readable code gives that role a concrete harmful power
outside the stated trust model.
