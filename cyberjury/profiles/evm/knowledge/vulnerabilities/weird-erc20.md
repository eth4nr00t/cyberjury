---
id: weird-erc20
title: Weird ERC-20 Behavior
impact: HIGH
tags: [fee-on-transfer, rebasing, accounting, fund-loss]
selection_hints: ["transferFrom", "safeTransferFrom", "balanceOf", "balanceBefore", "balanceAfter", "rebasing", "rebase", "fee-on-transfer", "deflationary", "_rOwned", "_tOwned", "reflectionFromToken", "isExcluded", "_reflectFee"]
aliases: [fee-on-transfer, deflationary-token, rebasing-token]
---

# Weird ERC-20 Behavior

## Security Condition

An ERC-20 integration is vulnerable when it records the requested nominal amount although a fee on
transfer token delivers less, or when it keeps nominal claims while a rebase or reflection changes
the assets held. Stored claims then diverge from real backing, so an attacker or early withdrawer
can receive value owed to later users or leave claims that the contract cannot pay.

## Review Guidance

Review fee on transfer delivery and later balance rebases or reflections as separate mechanisms.
Token callbacks belong to the reentrancy class. Explicit `false` and optional empty return
conventions belong to the unchecked-low-level-call class.

## Examples

### Fee on Transfer Amounts

A transfer may deliver less than its requested amount. Crediting the request creates unbacked
claims. This pair assumes a fixed callback free token with a known boolean return convention and
isolates the delivered amount. Measure the recipient's actual balance delta.

```solidity
pragma solidity ^0.8.20;

interface FeeToken {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract VulnerableFeeDeposit {
    FeeToken public immutable token;
    mapping(address => uint256) public credit;

    constructor(FeeToken asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        credit[msg.sender] += amount;
    }
}

contract SecureFeeDeposit {
    FeeToken public immutable token;
    mapping(address => uint256) public credit;

    constructor(FeeToken asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        uint256 beforeBalance = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        uint256 received = token.balanceOf(address(this)) - beforeBalance;
        credit[msg.sender] += received;
    }
}
```

### Rebase and Reflection Balance Drift

A later rebase or reflection changes the pool's token balance without changing stored nominal
credits. Early withdrawals may consume value owed to later users, or surplus value may become
unclaimable. This pair assumes exact transfers and a callback free token that may rebase.
Proportional shares keep claims aligned with the current pool balance.

```solidity
pragma solidity ^0.8.20;

interface RebasingToken {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract VulnerableRebaseAccounting {
    RebasingToken public immutable token;
    mapping(address => uint256) public credit;

    constructor(RebasingToken asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        credit[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = credit[msg.sender];
        credit[msg.sender] = 0;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}

contract SecureRebaseAccounting {
    RebasingToken public immutable token;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    constructor(RebasingToken asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        uint256 assetsBefore = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        uint256 received = token.balanceOf(address(this)) - assetsBefore;
        uint256 shares = totalShares == 0 ? received : received * totalShares / assetsBefore;
        require(shares > 0, "zero shares");
        totalShares += shares;
        sharesOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external {
        require(shares > 0 && shares <= sharesOf[msg.sender], "invalid shares");
        uint256 amount = shares * token.balanceOf(address(this)) / totalShares;
        sharesOf[msg.sender] -= shares;
        totalShares -= shares;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
```

## Not a Finding

Crediting the requested amount is safe when a fixed readable token proves exact balance delivery.
Nominal credits are safe when the token cannot rebase or reflect, or when the protocol deliberately
assigns those changes under a documented invariant. An ERC-20 interface alone is not controlling
evidence for either property.
