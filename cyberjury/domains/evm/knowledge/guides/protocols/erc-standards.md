---
id: erc-standards
title: ERC Token Standards
kind: protocol
detect:
  content: ["ERC20", "ERC721", "ERC1155", "ERC4626", "IERC20", "transferFrom", "safeTransferFrom", "onERC721Received", "onERC1155Received", "convertToShares", "totalAssets", "decimals"]
---
# ERC Token Standards Review Notes

These are token-standard invariants, independent of the surrounding protocol. The way each
shows up in code differs by stack, so read the `languages/solidity` guide for the concrete
idioms and confirm each invariant against the real flow. The high-value bugs are accounting
divergence, share-price manipulation, and callback reentrancy rather than syntax.

## ERC-20
- A `transfer` or `transferFrom` return value must be honored or wrapped with SafeERC20,
  a token that returns false or nothing on failure makes the call look successful, see the
  unchecked-low-level-call class.
- A token address that is not one fixed constant may be fee-on-transfer, deflationary,
  rebasing, or ERC-777. Measure the real balance delta across the transfer for any value
  that must be exact, do not credit the requested amount, see the weird-erc20 class.
- Allowance has the approve then `transferFrom` race, and for a fee token the approval must
  cover the amount plus the fee, not the amount alone.

## ERC-721 and ERC-1155
- `safeTransferFrom` invokes `onERC721Received` or `onERC1155Received` on the recipient, a
  hook that hands control to a party the caller chooses, a reentrancy vector. Write state
  before the safe transfer, see the reentrancy class.
- `setApprovalForAll` grants blanket control of every token of an owner. Confirm it is
  scoped to a trusted operator and revocable, and that a transfer checks owner or approval.

## ERC-4626 Vaults
- Conversion rounds against the user, shares down on deposit and assets down on withdraw,
  or value leaks to the other side, see the accounting-precision class.
- First-depositor share-price inflation: an empty vault lets the first depositor donate
  assets to inflate the share price and steal later deposits. Confirm a seed deposit, a
  dead-shares mint, or a virtual-offset defense.
- `totalAssets` must reflect real holdings, not a spot read an attacker can move in one
  transaction, see the oracle-price-manipulation class.
