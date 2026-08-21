---
id: oracle-price-manipulation
title: Oracle and Price Manipulation
impact: CRITICAL
tags: [oracle, price-manipulation, flash-loan, fund-loss]
selection_hints: ["getReserves", "slot0", "balanceOf(address(this))", "balanceOf(this)", "latestRoundData", "Chainlink", "oracle", "spot", "twap", "timeWeightedAverage", "getAmountOut", "/ reserve", "sync", "skim"]
aliases: [oracle, oracle-manipulation, oracle-validation, price-manipulation]
---

# Oracle and Price Manipulation

## Security Condition

An attacker can shift a spot price, reserve, or raw balance through a trade, transfer, `sync`, flash
loan, or token supply change. When a value moving transition treats that source as an authoritative
price without manipulation resistance, freshness, scale, and bound checks, the attacker can
overborrow, underpay, force a liquidation, or redeem more value than the protocol owes.

## Review Guidance

Report this when the price controls a mint, loan, liquidation, redemption, or swap. Use a resistant
TWAP or trusted oracle with freshness, scale, and bound checks.

## Examples

### Manipulation Resistant Price Input

```solidity
pragma solidity ^0.8.20;

interface Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface PriceOracle {
    function latestPrice18() external view returns (uint256 price18, uint256 updatedAt);
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
    uint256 public immutable minPrice18;
    uint256 public immutable maxPrice18;

    constructor(PriceOracle trustedOracle, uint256 lowerBound18, uint256 upperBound18) {
        require(lowerBound18 > 0 && lowerBound18 < upperBound18);
        oracle = trustedOracle;
        minPrice18 = lowerBound18;
        maxPrice18 = upperBound18;
    }

    function borrow(uint256 amount) external {
        (uint256 price18, uint256 updatedAt) = oracle.latestPrice18();
        require(updatedAt > 0 && updatedAt <= block.timestamp);
        require(block.timestamp - updatedAt <= MAX_AGE);
        require(price18 >= minPrice18 && price18 <= maxPrice18);
        issue(amount, collateral[msg.sender] * price18 / 1e18);
    }
}
```

## Not a Finding

A price is safe when the caller cannot move its source and the consumer checks freshness, bounds,
and scale. A display value or caller protected quote is not exploitable. Report a spot read only
when it controls value without an independent bound. `skim` alone does not change reserves.
