---
id: accounting-precision
title: Accounting and Precision Error
impact: HIGH
tags: [accounting, rounding, precision, erc4626, fund-loss]
selection_hints: ["* totalSupply", "/ totalSupply", "shares", "convertToShares", "convertToAssets", "totalAssets", "mulDiv", "first deposit", "previewDeposit", "previewRedeem", "rounding", "decimals()", "exchangeRate", "ratePerShare", "sharePrice"]
aliases: [accounting, precision]
---

# Accounting and Precision Error

Integer accounting loses or creates value when rounding direction, operation order, unit scale,
or an attacker controlled initial state violates the economic invariant. Trace the units and
rounding rule through the value moving operation. A local formula is safe only when every caller
uses its result in the intended direction.

## Rounding Direction

When a withdrawal computes shares to burn, rounding down lets a caller receive assets while
burning too few shares. Round the charge up when the protocol must collect enough input for an
exact output.

```solidity
pragma solidity ^0.8.20;

contract VulnerableWithdrawalQuote {
    function sharesToBurn(uint256 assets, uint256 supply, uint256 assetsHeld)
        external
        pure
        returns (uint256)
    {
        return assets * supply / assetsHeld;
    }
}

contract SecureWithdrawalQuote {
    function sharesToBurn(uint256 assets, uint256 supply, uint256 assetsHeld)
        external
        pure
        returns (uint256 shares)
    {
        uint256 numerator = assets * supply;
        shares = numerator / assetsHeld;
        if (numerator % assetsHeld != 0) {
            shares += 1;
        }
    }
}
```

## Division Before Multiplication

Dividing first discards a remainder before later multiplication can preserve it. An attacker may
split an operation into amounts below the first divisor to avoid a fee or debt increment.

```solidity
pragma solidity ^0.8.20;

contract VulnerableFeeOrder {
    function fee(uint256 amount, uint256 rate) external pure returns (uint256) {
        return amount / 10_000 * rate;
    }
}

contract SecureFeeOrder {
    function fee(uint256 amount, uint256 rate) external pure returns (uint256) {
        return amount * rate / 10_000;
    }
}
```

## Decimal Scale

Combining token and oracle values without normalizing their documented decimals can overstate
collateral or understate debt. The scale is a property of each input, not its Solidity type.

```solidity
pragma solidity ^0.8.20;

contract VulnerablePriceScale {
    function maxDebt(uint256 collateralWei, uint256 priceWithEightDecimals)
        external
        pure
        returns (uint256)
    {
        return collateralWei * priceWithEightDecimals;
    }
}

contract SecurePriceScale {
    function maxDebt(uint256 collateralWei, uint256 priceWithEightDecimals)
        external
        pure
        returns (uint256)
    {
        return collateralWei * priceWithEightDecimals / 1e8;
    }
}
```

## First Depositor Donation

An attacker can mint a tiny initial share supply, donate assets directly, and make a later deposit
round to zero shares. Virtual liquidity or seed shares keep the initial exchange rate from being
set by one caller. Reject zero output as a final safety boundary.

```solidity
pragma solidity ^0.8.20;

contract VulnerableDonationVault {
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        uint256 assetsBefore = address(this).balance - msg.value;
        uint256 shares = totalShares == 0 ? msg.value : msg.value * totalShares / assetsBefore;
        totalShares += shares;
        sharesOf[msg.sender] += shares;
    }

    receive() external payable {}
}

contract SecureDonationVault {
    uint256 private constant VIRTUAL_ASSETS = 1;
    uint256 private constant VIRTUAL_SHARES = 1_000_000;
    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    function deposit() external payable {
        uint256 assetsBefore = address(this).balance - msg.value;
        uint256 shares = msg.value * (totalShares + VIRTUAL_SHARES)
            / (assetsBefore + VIRTUAL_ASSETS);
        require(shares > 0, "zero shares");
        totalShares += shares;
        sharesOf[msg.sender] += shares;
    }

    receive() external payable {}
}
```

## Not a Finding

Integer division alone is not reportable. Rounding is safe when its direction protects the party
that must receive enough value and zero output cannot create a free operation. Operation order is
safe when precision loss cannot change a security relevant amount. Unit conversion is safe when
every operand uses a documented common scale. Initial deposits are safe when attacker donations
cannot set the exchange rate for later users.
