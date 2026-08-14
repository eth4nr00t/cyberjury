---
id: erc-standards
title: ERC Token Standards
kind: protocol
detect:
  content: ["ERC20", "ERC721", "ERC1155", "ERC4626", "IERC20", "transferFrom", "safeTransferFrom", "onERC721Received", "onERC1155Received", "convertToShares", "totalAssets", "decimals"]
entrypoint_files: []
entrypoint_markers: []
logic_layer_files: []
public_api_patterns: []
---

# ERC Token Standards Review Notes

These are token-standard invariants, independent of the surrounding protocol. The way each
shows up in code differs by stack, so read the `languages/solidity` guide for the concrete
idioms and confirm each invariant against the real flow. The high-value bugs are accounting
divergence, share-price manipulation, and callback reentrancy rather than syntax.

## Protocol Model

- Actors are token owners, approved spenders, operators, recipients, issuers, and vault share
  holders. Token and receiver contracts may be controlled by an attacker.
- Assets are balances, allowances, token ownership, operator authority, vault assets, and shares.
- State transitions include mint, burn, transfer, approve, permit, deposit, withdraw, redeem,
  and callback acceptance. Check both the token state and the integrating protocol state across
  each transition.

## ERC-20

- A `transfer` or `transferFrom` return value must be honored or wrapped with SafeERC20,
  a token that returns false or nothing on failure makes the call look successful, see the
  unchecked-low-level-call class.
- A token whose implementation and behavior are not fixed may be fee-on-transfer,
  deflationary, rebasing, or callback bearing. Measure the real balance delta across the
  transfer for any value that must be exact. Do not credit the requested amount, see the
  weird-erc20 class.
- Changing a nonzero allowance directly can let a spender use both the old and new values by
  ordering a `transferFrom` before the update. Prefer an atomic allowance adjustment or set the
  allowance to zero before assigning a replacement value.

## ERC-721 and ERC-1155

- `safeTransferFrom` invokes `onERC721Received` or `onERC1155Received` on the recipient, a
  hook that hands control to a party the caller chooses, a reentrancy vector. Write state
  before the safe transfer, see the reentrancy class.
- `setApprovalForAll` grants blanket control of every token of an owner. Confirm only the owner
  can grant or revoke that authority and every transfer checks current ownership or approval.

## ERC-4626 Vaults

- Conversion rounds shares down for deposits and assets down for redemptions. The shares needed
  to withdraw assets and the assets needed to mint shares round up. A wrong direction can leak
  value to the caller, see the accounting-precision class.
- First-depositor share-price inflation: an empty vault lets the first depositor donate
  assets to inflate the share price and steal later deposits. Confirm a seed deposit, a
  dead-shares mint, or a virtual-offset defense.
- `totalAssets` must use the vault's documented accounting basis. If donations can change it,
  share conversion must remain safe under that change. Do not substitute an unrelated spot
  price for asset accounting, see the accounting-precision and oracle-price-manipulation classes.

## Authorization Lifecycle

- A permit binds the owner, spender, value, token contract, chain, nonce, and deadline. Consume
  the nonce atomically and reject an expired or malleable signature, see signature-replay.
- Approval and operator authority remain active until spent, replaced, or revoked. Confirm that
  revocation reaches every transfer entrypoint and that a paused or blocked account cannot use a
  sibling authorization path to preserve forbidden authority.
- Receiver callbacks occur inside safe transfers. Finalize shared ownership and accounting state
  before the callback, and do not assume an interface alone makes the receiver trusted.
