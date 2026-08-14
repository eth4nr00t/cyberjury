---
id: weird-erc20
title: Weird ERC-20 Behavior
impact: HIGH
tags: [fee-on-transfer, rebasing, erc777, accounting, fund-loss]
selection_hints: ["transferFrom", "safeTransferFrom", "balanceOf", "balanceBefore", "balanceAfter", "ERC777", "tokensReceived", "tokensToSend", "rebasing", "rebase", "fee-on-transfer", "deflationary", "_rOwned", "_tOwned", "reflectionFromToken", "isExcluded", "_reflectFee"]
aliases: [fee-on-transfer, deflationary-token, rebasing-token, erc777-hook]
---

# Weird ERC-20 Behavior

An arbitrary token may deliver less than requested, rebase balances, change fees, return false,
or invoke a callback. Crediting the requested amount overstates a fee on transfer deposit. Stored
amounts drift under rebases or reflection accounting. ERC-777 and custom hooks create reentrancy
during an ordinary transfer. Measure the actual balance delta, handle future rebases when the
protocol supports them, check transfer success, and protect shared state across callbacks. The
boundary with unchecked-low-level-call is that this class includes a successful call whose amount
or callback behavior violates the integrator's assumption.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

interface Token {
    function balanceOf(address account) external view returns (uint256);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerablePool {
    Token public immutable token;
    mapping(address => uint256) public shares;

    constructor(Token asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount));
        shares[msg.sender] += amount;
    }
}

contract SecurePool {
    Token public immutable token;
    mapping(address => uint256) public shares;
    bool private entered;

    constructor(Token asset) {
        token = asset;
    }

    function deposit(uint256 amount) external {
        require(!entered, "reentrant");
        entered = true;
        uint256 balanceBefore = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount));
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        shares[msg.sender] += received;
        entered = false;
    }
}
```

## Not a Finding

Crediting the request is safe when a fixed, readable token cannot charge a fee, rebase, fail, or
invoke a callback. An arbitrary token integration is safe only when it handles every supported
behavior, including later rebases, and protects state during callbacks. An ERC-20 interface alone
is not controlling evidence.
