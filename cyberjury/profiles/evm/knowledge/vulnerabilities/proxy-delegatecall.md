---
id: proxy-delegatecall
title: Proxy, Delegatecall, and Initializer Flaws
impact: CRITICAL
tags: [swc-112, delegatecall, proxy, initializer, upgrade, fund-loss]
selection_hints: ["delegatecall", "initialize", "initializer", "_disableInitializers", "implementation", "upgradeTo", "upgradeToAndCall", "ProxyAdmin", "TransparentUpgradeableProxy", "UUPS", "__gap", "storage collision", "selfdestruct"]
aliases: [delegatecall, unprotected-upgrade]
---

# Proxy, Delegatecall, and Initializer Flaws

A proxy runs implementation code in its own storage through `delegatecall`. An unguarded
initializer lets a caller seize ownership, incompatible storage layouts corrupt state, and an
attacker controlled delegate target can take the proxy's storage and balance. Guard initialization,
disable initialization on the implementation, preserve storage layout across upgrades, authorize
the upgrade entrypoint, and never delegate to an untrusted target.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableExecutor {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}

contract SecureExecutor {
    address public immutable owner;
    address public immutable implementation;

    constructor(address trustedImplementation) {
        require(trustedImplementation.code.length > 0);
        owner = msg.sender;
        implementation = trustedImplementation;
    }

    function execute(bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = implementation.delegatecall(data);
        require(ok);
    }
}
```

## Not a Finding

An initializer is safe when the proxy can call it once and the implementation disables its own.
A delegate target is safe when fixed or chosen behind readable authorization. An upgrade is safe
when its entrypoint checks the administrator and the new implementation preserves storage layout.
