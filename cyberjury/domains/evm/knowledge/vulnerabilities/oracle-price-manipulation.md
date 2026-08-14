---
id: oracle-price-manipulation
title: Oracle and Price Manipulation
impact: CRITICAL
tags: [oracle, price-manipulation, flash-loan, fund-loss]
selection_hints: ["getReserves", "slot0", "balanceOf(address(this))", "balanceOf(this)", "latestRoundData", "Chainlink", "oracle", "spot", "twap", "timeWeightedAverage", "getAmountOut", "/ reserve", "sync", "skim"]
aliases: [oracle, oracle-manipulation, oracle-validation, price-manipulation]
---

# Oracle and Price Manipulation

Spot prices, reserves, and raw balances can be shifted by a trade, transfer, `sync`, flash loan,
or token supply logic. Report this when the price controls a mint, loan, liquidation, redemption,
or swap. Use a resistant TWAP or trusted oracle with freshness, scale, and bound checks.

## Vulnerable and Secure

```solidity
pragma solidity ^0.8.20;

interface Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface PriceOracle {
    function latestPrice() external view returns (uint256 price, uint256 updatedAt);
}

abstract contract Lender {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function issue(uint256 amount, uint256 limit) internal {
        require(debt[msg.sender] + amount <= limit);
        debt[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

contract VulnerableLender is Lender {
    Pair public immutable pair;

    constructor(Pair liquidityPair) {
        pair = liquidityPair;
    }

    function borrow(uint256 amount) external {
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 spotPrice = (uint256(reserve1) * 1e18) / reserve0;
        issue(amount, collateral[msg.sender] * spotPrice / 1e18);
    }
}

contract SecureLender is Lender {
    uint256 private constant MAX_AGE = 1 hours;
    PriceOracle public immutable oracle;
    uint256 public immutable minPrice;
    uint256 public immutable maxPrice;

    constructor(PriceOracle trustedOracle, uint256 lowerBound, uint256 upperBound) {
        require(lowerBound > 0 && lowerBound < upperBound);
        oracle = trustedOracle;
        minPrice = lowerBound;
        maxPrice = upperBound;
    }

    function borrow(uint256 amount) external {
        (uint256 price, uint256 updatedAt) = oracle.latestPrice();
        require(updatedAt > 0 && updatedAt <= block.timestamp);
        require(block.timestamp - updatedAt <= MAX_AGE);
        require(price >= minPrice && price <= maxPrice);
        issue(amount, collateral[msg.sender] * price / 1e18);
    }
}
```

## Not a Finding

A price is safe when the caller cannot move its source and the consumer checks freshness, bounds,
and scale. A display value or caller protected quote is not exploitable. Report a spot read only
when it controls value without an independent bound. `skim` alone does not change reserves.
