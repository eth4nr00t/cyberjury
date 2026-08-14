---
id: accounting-precision
title: Accounting and Precision Error
impact: HIGH
tags: [accounting, rounding, precision, erc4626, fund-loss]
selection_hints: ["* totalSupply", "/ totalSupply", "shares", "convertToShares", "convertToAssets", "totalAssets", "mulDiv", "first deposit", "previewDeposit", "previewRedeem", "rounding", "decimals()", "exchangeRate", "ratePerShare", "sharePrice"]
aliases: [accounting, precision]
---

# Accounting and Precision Error

A conversion loses value when it rounds in the attacker's favor, divides before multiplying,
mixes decimal scales, or lets a first depositor manipulate a share price. In a donation attack,
the attacker mints a tiny initial supply, inflates vault assets directly, and makes a victim's
deposit round to zero shares. Normalize units, multiply before dividing, choose rounding that
protects existing holders, reject zero output, and use seed shares or virtual offsets.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

contract VulnerableVault {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function deposit() external payable returns (uint256 shares) {
        uint256 oldAssets = address(this).balance - msg.value;
        shares = totalSupply == 0 ? msg.value : msg.value * totalSupply / oldAssets;
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && shares <= balanceOf[msg.sender]);
        assets = shares * address(this).balance / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        (bool ok,) = msg.sender.call{value: assets}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

contract SecureVault {
    uint256 private constant VIRTUAL_ASSETS = 1;
    uint256 private constant VIRTUAL_SHARES = 1_000_000;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function deposit() external payable returns (uint256 shares) {
        uint256 oldAssets = address(this).balance - msg.value;
        shares = (msg.value * (totalSupply + VIRTUAL_SHARES)) / (oldAssets + VIRTUAL_ASSETS);
        require(shares > 0, "zero shares");
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        require(shares > 0 && shares <= balanceOf[msg.sender]);
        assets = shares * (address(this).balance + VIRTUAL_ASSETS) / (totalSupply + VIRTUAL_SHARES);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        (bool ok,) = msg.sender.call{value: assets}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
```

## Not a Finding

Integer division alone is not reportable. Rounding is safe when its direction protects the
protocol, zero output is rejected, and a donation cannot manipulate later conversion. Unit
conversion is safe when operands use a documented common scale and a narrowing cast is bounded.
