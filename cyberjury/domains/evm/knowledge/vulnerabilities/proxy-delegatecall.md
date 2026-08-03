---
id: proxy-delegatecall
title: Proxy, Delegatecall, and Initializer Flaws
lens: proxy-delegatecall
impact: CRITICAL
tags: [swc-112, delegatecall, proxy, initializer, upgrade, fund-loss]
aliases: [delegatecall, unprotected-upgrade]
triggers: ["delegatecall", "initialize", "initializer", "_disableInitializers", "implementation", "upgradeTo", "selfdestruct", "storage", "__gap", "UUPS"]
---

# Proxy, Delegatecall, and Initializer Flaws

Upgradeable contracts run the implementation's code in the proxy's storage via
`delegatecall`, which creates three classic flaws. An initializer with no guard, or a
logic contract left uninitialized behind a proxy, lets anyone call `initialize` and seize
ownership. A storage layout that differs between proxy and implementation, or across an
upgrade, collides variables and corrupts state. A `delegatecall` into an
attacker-influenced address runs foreign code with this contract's storage and balance.
Guard initializers, keep storage layout append-only with a gap, and never delegatecall an
untrusted target.

## Vulnerable
```solidity
function initialize(address _owner) external {   // no initializer guard
    owner = _owner;                                // anyone calls this on the unguarded proxy
}

function execute(address target, bytes calldata data) external {
    target.delegatecall(data);                     // foreign code in our storage and balance
}
```

## Secure
```solidity
function initialize(address _owner) external initializer {   // runs once
    __Ownable_init();
    owner = _owner;
}

constructor() { _disableInitializers(); }          // logic contract cannot be initialized directly
// no delegatecall to a caller-supplied target
```
