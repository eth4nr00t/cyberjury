---
id: proxy-delegatecall
title: Proxy, Delegatecall, and Initializer Flaws
impact: CRITICAL
tags: [swc-112, delegatecall, proxy, initializer, upgrade, fund-loss]
selection_hints: ["delegatecall", "initialize", "initializer", "_disableInitializers", "implementation", "upgradeTo", "upgradeToAndCall", "ProxyAdmin", "TransparentUpgradeableProxy", "UUPS", "__gap", "storage collision", "selfdestruct"]
aliases: [delegatecall, unprotected-upgrade]
---

# Proxy, Delegatecall, and Initializer Flaws

## Security Condition

A proxy or delegate executor is vulnerable when an attacker can initialize privileged proxy
storage, choose implementation code without authorization, or make an upgrade reinterpret the
existing storage layout. Because delegated code runs against the caller's storage and balance,
these failures can transfer authority, corrupt accounting, execute arbitrary state changes, or
lock and drain funds.

## Review Guidance

Review initialization, storage compatibility, upgrade authorization, and every delegate target as
separate controls. A safe control on one mechanism does not make the others safe.

## Examples

### Initializer Takeover

An externally callable initializer without a one time guard lets the first caller claim the
privileged storage of a proxy or directly deployed initializable contract. Initialize the proxy
atomically or restrict the first call to a trusted initializer, and guard later calls. In the
secure pair, the constructor locks the implementation contract's own storage. Its immutable
initializer authority remains part of the implementation code when a proxy delegates into it, so
an arbitrary account cannot claim the proxy's initially empty storage.

```solidity
pragma solidity ^0.8.20;

contract VulnerableInitializable {
    address public owner;

    function initialize(address newOwner) external {
        owner = newOwner;
    }
}

contract SecureInitializable {
    address private immutable initializerAuthority;
    address public owner;
    bool private initialized;

    constructor(address trustedInitializer) {
        require(trustedInitializer != address(0), "zero initializer");
        initializerAuthority = trustedInitializer;
        initialized = true;
    }

    function initialize(address newOwner) external {
        require(msg.sender == initializerAuthority, "not initializer");
        require(!initialized, "initialized");
        initialized = true;
        owner = newOwner;
    }
}
```

### Storage Layout Compatibility

Reordering or changing existing storage fields makes upgraded code interpret old values under new
types or names. Preserve inherited order and append new fields after the existing layout.

```solidity
pragma solidity ^0.8.20;

contract OriginalLayout {
    address public owner;
    uint256 public balance;
}

contract VulnerableReorderedLayout {
    uint256 public balance;
    address public owner;
}

contract SecureAppendedLayout {
    address public owner;
    uint256 public balance;
    uint256 public feeRate;
}
```

### Upgrade Authorization

An upgrade entrypoint lets its caller choose all code that later runs in proxy storage. Authenticate
the exact upgrade operation and reject an address with no deployed code.

```solidity
pragma solidity ^0.8.20;

contract VulnerableUpgrade {
    address public implementation;

    function upgradeTo(address next) external {
        implementation = next;
    }
}

contract SecureUpgrade {
    address public immutable admin = msg.sender;
    address public implementation;

    function upgradeTo(address next) external {
        require(msg.sender == admin, "not admin");
        require(next.code.length > 0, "not code");
        implementation = next;
    }
}
```

### Attacker Selected Delegatecall

Delegatecall gives the target authority over the caller's storage and balance. Do not let an
untrusted caller select the target, even when the called function or calldata appears harmless.

```solidity
pragma solidity ^0.8.20;

contract VulnerableDelegateExecutor {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok, "delegate failed");
    }
}

contract SecureDelegateExecutor {
    address public immutable owner = msg.sender;
    address public immutable implementation;

    constructor(address trustedImplementation) {
        require(trustedImplementation.code.length > 0, "not code");
        implementation = trustedImplementation;
    }

    function execute(bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = implementation.delegatecall(data);
        require(ok, "delegate failed");
    }
}
```

## Not a Finding

An initializer is safe when its first caller is fixed by atomic deployment or exact authorization,
the proxy can complete it only once, and the implementation cannot be initialized independently. A
new implementation is safe only when readable authorization and storage compatibility both hold. A
delegate target is safe when it is trusted, fixed or selected behind exact authorization, contains
code, and follows the caller's storage contract.
