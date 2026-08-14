---
id: token-launches
title: Token Launch and Tax Tokens
kind: protocol
detect:
  content: ["tradingEnabled", "enableTrading", "swapAndLiquify", "maxTxAmount", "maxWalletAmount", "_reflectFee", "_rOwned", "_tOwned", "isExcludedFromFee", "setTaxFee", "liquidityFee", "marketingFee", "sync"]
entrypoint_files: []
entrypoint_markers: []
logic_layer_files: []
public_api_patterns: []
---

# Token Launch and Tax Token Review Notes

These patterns are common to token-launch contracts, most visibly on BSC but not unique to
it, where a token layers a transfer tax, reflection, trading switches, and liquidity
handling on top of ERC-20. Read the `languages/solidity` guide for idioms and `erc-standards`
for the base token invariants. The high-value bugs are owner control that can trap a buyer
and price or reserve manipulation through the token's own liquidity, so confirm a concrete,
unrecoverable user harm rather than reporting that the owner is privileged.

## Protocol Model

- Actors are the deployer, fee and liquidity controllers, buyers, sellers, liquidity providers,
  routers, and the token or pair contracts they can influence.
- Assets are token balances, sale proceeds, liquidity reserves, fee inventory, trading access,
  and the authority to change taxes, limits, exemptions, or blocked accounts.
- Trust boundaries sit at public transfer and administration functions, router and pair calls,
  owner controlled configuration, and any exemption or block list.
- Follow the launch from disabled trading through liquidity creation, public trading, fee swaps,
  exclusion changes, and any emergency or ownership transition. Check whether a buyer can exit
  after every owner controlled transition.

## Owner Control That Traps a Buyer

- A trading switch, sell tax, transaction limit, or blacklist can trap a holder after purchase.
  Report the setter and trapped path only when an unintended caller can use the control, or when
  the implementation violates a stated immutable limit or revocation boundary. An explicitly
  centralized administrator acting within the documented trust model is not an access control
  bypass.

## Reserve and Price Manipulation Through Own Liquidity

- A token whose burn or fee handling changes the pair balance and then calls `sync` shifts the
  reserve ratio and any price read from it within one transaction. See
  oracle-price-manipulation when a value-moving operation trusts that price.

## Fee, Reflection, and Balance Drift

- A transfer tax means the delivered amount is not the requested amount, and a reflection
  token's balance drifts between transfers with excluded accounts accounted differently.
  See weird-erc20 for the integrator impact and accounting-precision for share and unit math.

## Decimal and Scale Mistakes

- A sale or staking contract that credits from a rate without matching each token's
  `decimals` over- or under-mints by orders of magnitude. See accounting-precision.

## Bindings and Revocation

- A signed launch authorization or allowlist entry binds the buyer, sale, chain, amount, nonce,
  and expiry. A successful use consumes the nonce so it cannot be replayed.
- Fee exemptions, blocked accounts, router approvals, and trading roles have explicit assignment
  and revocation paths. Revocation must affect every transfer path before another trade executes.
- A deadline is meaningful only when it comes from the caller or signed order. Replacing it with
  the current block time makes every pending transaction appear fresh.

Report only real, exploitable, high-confidence issues with a concrete exploit path and a
fund or control impact. Do not report that a token has an owner, a tax, or a trading switch
when no buyer's funds are reachable through it. That privilege is a design note, not a finding.
