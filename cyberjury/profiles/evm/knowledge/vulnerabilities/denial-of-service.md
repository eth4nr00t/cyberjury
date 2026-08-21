---
id: denial-of-service
title: Denial of Service
impact: HIGH
tags: [swc-113, swc-128, dos, griefing, gas, fund-loss]
selection_hints: ["for (uint", "while (", "unbounded", "array length", "loop", "block gas", "gas grief", "refund", "selfdestruct", "revert"]
aliases: [dos]
---

# Denial of Service

## Security Condition

A contract is wedged when attacker-grown work exceeds the block gas limit, one reverting recipient
blocks a push payment loop, or a griefer can revert a critical external call.

## Review Guidance

Report the reachable operation that locks funds or halts required progress. Bound or paginate work,
isolate failures, and prefer pull payments.

## Examples

### Recipient Controlled Payout Liveness

```solidity
pragma solidity ^0.8.20;

contract VulnerablePayout {
    address payable[] public recipients;

    function add(address payable recipient) external {
        recipients.push(recipient);
    }

    function payAll() external {
        for (uint256 i; i < recipients.length; i++) {
            recipients[i].transfer(1 wei);
        }
    }

    receive() external payable {}
}

contract SecurePayout {
    mapping(address => uint256) public owed;

    function fund(address recipient) external payable {
        owed[recipient] += msg.value;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "claim failed");
    }
}
```

## Not a Finding

A loop is safe when every write enforces a gas safe maximum. Pagination is safe when each call
makes durable progress that an attacker cannot reset. An external failure is not protocol denial
of service when it affects only the caller's optional action and blocks no other account.
