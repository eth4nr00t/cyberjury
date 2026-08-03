---
id: denial-of-service
title: Denial of Service
lens: denial-of-service
impact: HIGH
tags: [swc-113, swc-128, dos, griefing, gas, fund-loss]
aliases: [dos]
triggers: ["for (", "while (", ".length", "push(", "transfer(", "revert", "external call", "unbounded", "for(uint", "selfdestruct"]
---

# Denial of Service

A contract is wedged so a function can no longer succeed, locking funds or halting the
protocol. The common forms are an unbounded loop over an array an attacker can grow until
it exceeds the block gas limit, a push payment loop where one reverting recipient blocks
the whole batch, and a critical step that depends on an external call a griefer can force
to revert. Favor pull payments over push, bound or paginate loops over attacker-grown
arrays, and isolate one recipient's failure from the rest.

## Vulnerable
```solidity
function payWinners() external {
    for (uint256 i = 0; i < winners.length; i++) {     // attacker-grown array, unbounded gas
        winners[i].transfer(prize);                     // one reverting recipient blocks everyone
    }
}
```

## Secure
```solidity
mapping(address => uint256) public owed;               // pull payment, isolate failures
function claim() external {
    uint256 amount = owed[msg.sender];
    owed[msg.sender] = 0;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "claim failed");
}
```
