---
id: token-launches
title: Token Launch and Tax Tokens
kind: protocol
detect:
  content: ["tradingEnabled", "enableTrading", "swapAndLiquify", "maxTxAmount", "maxWalletAmount", "_reflectFee", "_rOwned", "_tOwned", "isExcludedFromFee", "setTaxFee", "liquidityFee", "marketingFee", "sync"]
---
# Token Launch and Tax Token Review Notes

These patterns are common to token-launch contracts, most visibly on BSC but not unique to
it, where a token layers a transfer tax, reflection, trading switches, and liquidity
handling on top of ERC-20. Read the `languages/solidity` guide for idioms and `erc-standards`
for the base token invariants. The high-value bugs are owner control that can trap a buyer
and price or reserve manipulation through the token's own liquidity, so confirm a concrete,
unrecoverable user harm rather than reporting that the owner is privileged.

## Owner Control That Traps a Buyer
- A one-way `enableTrading` switch, a sell tax or `maxTxAmount` the owner can raise after
  launch, or a blacklist the owner can add a holder to after purchase, all let the owner
  freeze or take value a user already paid for. See access-control, report the setter and
  the trapped path.

## Reserve and Price Manipulation Through Own Liquidity
- A token whose `burn`, `swapAndLiquify`, or fee handling moves supply into its own pair
  and calls `sync` shifts the reserve ratio and any price read from it within one
  transaction. See oracle-price-manipulation.

## Fee, Reflection, and Balance Drift
- A transfer tax means the delivered amount is not the requested amount, and a reflection
  token's balance drifts between transfers with excluded accounts accounted differently.
  See weird-erc20 for the integrator impact and accounting-precision for share and unit math.

## Decimal and Scale Mistakes
- A sale or staking contract that credits from a rate without matching each token's
  `decimals` over- or under-mints by orders of magnitude. See accounting-precision.

Report only real, exploitable, high-confidence issues with a concrete exploit path and a
fund or control impact. Do not report that a token has an owner, a tax, or a trading switch
when no buyer's funds are reachable through it, that is a design note, not a finding.
