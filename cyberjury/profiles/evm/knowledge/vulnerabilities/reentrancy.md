---
id: reentrancy
title: Reentrancy
impact: CRITICAL
tags: [swc-107, reentrancy, fund-loss]
selection_hints: [".call{value", ".call(", "send(", "external call", "balances[", "withdraw", "nonReentrant", "safeTransfer", "onERC721Received", "tokensToSend", "tokensReceived", "ERC777", "before state", "read-only reentrancy", "get_virtual_price", "getReserves", "getRate", "sharePrice", "view returns"]
aliases: [read-only-reentrancy]
---

# Reentrancy

## Security Condition

An external interaction is vulnerable when it hands control to an attacker controlled contract
before every state value in the shared invariant is consistent. The callee can return through the
same function, a sibling function, a view consumed by another protocol, or a token callback and
reuse or expose stale state. This can repeat a withdrawal, move the same credit twice, corrupt
accounting, or make another protocol act on a transient value.

## Review Guidance

Identify all state that must remain consistent across that boundary. Finalize it before interaction
or use a guard that covers every entrypoint sharing the invariant.

## Examples

### Same Function Reentrancy

Sending value before clearing a balance lets the recipient reenter the same withdrawal and collect
the recorded balance again.

```solidity
pragma solidity ^0.8.20;

contract VulnerableWithdrawal {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}

contract SecureWithdrawal {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
```

### Cross-Function Reentrancy

A callback can enter a sibling function that reads or moves the same stale balance. Guarding only
the function that makes the call leaves the shared invariant exposed.

```solidity
pragma solidity ^0.8.20;

contract VulnerableCrossFunction {
    mapping(address => uint256) public credits;

    function deposit() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credits[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        credits[msg.sender] = 0;
    }

    function moveCredit(address recipient, uint256 amount) external {
        credits[msg.sender] -= amount;
        credits[recipient] += amount;
    }
}

contract SecureCrossFunction {
    mapping(address => uint256) public credits;

    function deposit() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credits[msg.sender];
        credits[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function moveCredit(address recipient, uint256 amount) external {
        credits[msg.sender] -= amount;
        credits[recipient] += amount;
    }
}
```

### Read-Only Reentrancy

A callback may query a public rate while the contract balance has changed but its accounting has
not. Another protocol can act on that stale view even when the callback cannot mutate this pool.

```solidity
pragma solidity ^0.8.20;

contract VulnerableReadOnlyPool {
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        totalAssets += msg.value;
        totalShares += msg.value;
        sharesOf[msg.sender] += msg.value;
    }

    function sharePrice() external view returns (uint256) {
        return totalAssets * 1e18 / totalShares;
    }

    function withdraw(uint256 shares, address payable recipient) external {
        require(shares > 0 && shares <= sharesOf[msg.sender], "invalid shares");
        uint256 assets = shares * totalAssets / totalShares;
        sharesOf[msg.sender] -= shares;
        (bool ok,) = recipient.call{value: assets}("");
        require(ok, "transfer failed");
        totalAssets -= assets;
        totalShares -= shares;
    }
}

contract SecureReadOnlyPool {
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        totalAssets += msg.value;
        totalShares += msg.value;
        sharesOf[msg.sender] += msg.value;
    }

    function sharePrice() external view returns (uint256) {
        return totalAssets * 1e18 / totalShares;
    }

    function withdraw(uint256 shares, address payable recipient) external {
        require(shares > 0 && shares <= sharesOf[msg.sender], "invalid shares");
        uint256 assets = shares * totalAssets / totalShares;
        sharesOf[msg.sender] -= shares;
        totalAssets -= assets;
        totalShares -= shares;
        (bool ok,) = recipient.call{value: assets}("");
        require(ok, "transfer failed");
    }
}
```

### Token Callback Reentrancy

A custom token may invoke recipient code during `send`. In this pair, `fund` first transfers a fixed
exact amount into the claim contract and then records the recipient's credit. Treat the callback
bearing `send` like any other external interaction and settle the credit before making it.

```solidity
pragma solidity ^0.8.20;

interface CallbackToken {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function send(address recipient, uint256 amount) external;
}

contract VulnerableTokenClaim {
    CallbackToken public immutable token;
    mapping(address => uint256) public credits;

    constructor(CallbackToken asset) {
        token = asset;
    }

    function fund(address claimant, uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "funding failed");
        credits[claimant] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        token.send(msg.sender, amount);
        credits[msg.sender] = 0;
    }
}

contract SecureTokenClaim {
    CallbackToken public immutable token;
    mapping(address => uint256) public credits;

    constructor(CallbackToken asset) {
        token = asset;
    }

    function fund(address claimant, uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "funding failed");
        credits[claimant] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        credits[msg.sender] = 0;
        token.send(msg.sender, amount);
    }
}
```

## Not a Finding

An interaction is safe when every state value reachable from a callback is consistent before
control leaves, or one guard covers every relevant mutating entrypoint. A token is callback free
only when its fixed implementation or enforced allowlist proves that fact. A view is safe during
an interaction only when it reflects the current transition or no reachable consumer can act on
an intermediate value.
