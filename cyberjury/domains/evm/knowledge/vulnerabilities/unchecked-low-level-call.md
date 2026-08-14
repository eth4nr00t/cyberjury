---
id: unchecked-low-level-call
title: Unchecked Low-Level Call
impact: HIGH
tags: [swc-104, low-level-call, return-value, fund-loss]
selection_hints: [".call(", ".call{value", ".delegatecall(", ".send(", "bool success", "bool ok", "(bool", "success,", "returndata", "returndatacopy", "abi.decode(returndata", "excessivelySafeCall"]
aliases: [unchecked-call, unchecked-return]
---

# Unchecked Low-Level Call

A low level `.call`, `.delegatecall`, or `.send` reports failure as a boolean. Ignoring it can mark
value sent when no transfer occurred. Raw token calls also need a wrapper that handles false or
empty returns. Conversely, blindly copying attacker controlled return data can exhaust gas. Check
failure and cap copied return data before allocation or decoding.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerablePayout {
    mapping(address => uint256) public owed;

    function fund(address recipient) external payable {
        owed[recipient] += msg.value;
    }

    function claim() external {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        payable(msg.sender).call{value: amount}("");
    }
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
        require(ok, "transfer failed");
    }
}
```

## Not a Finding

A low level call is safe when failure reverts or is reflected accurately in state. A best effort
notification may ignore failure when no value, authority, or completion record depends on it.
Returned data is safe when bounded before copying. A wrapper is evidence only when its enforcing
implementation is visible.
