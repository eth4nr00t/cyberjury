---
id: solidity
title: Solidity
kind: language
detect:
  files: ["*.sol"]
  manifest: ["foundry.toml", "hardhat", "@openzeppelin", "solidity"]
  imports: ["pragma solidity", "import \"@", "import {"]
  content: ["pragma solidity", "contract ", "library ", "interface "]
entrypoint_files: []
entrypoint_markers: ["external", "public", "fallback", "receive", "function"]
logic_layers: ["*/libraries/*.sol", "*Library.sol", "*/base/*.sol", "*Base.sol", "*/utils/*.sol"]
---
# Solidity Review Notes

The attack surface is every function an external account or contract can call: the
`external` and `public` functions, plus `fallback` and `receive`. Trace each into the
internal functions, libraries, and base contracts it reaches, and across the contracts
it calls, since the flaw often lives in a base contract or a called protocol, not the
entrypoint. Money is the asset, so a finding's worth is measured in funds moved, locked,
or stolen.

## Where Value and Trust Live
- Balances and accounting in storage, the share or LP math of a vault or pool, and any
  `transfer`, `transferFrom`, `call{value:}`, or `mint`/`burn` that moves value.
- Privileged roles: `owner`, `Ownable`, `AccessControl` roles, a `governance` or
  `admin` address, and the modifiers that gate them.
- The trust boundary is the contract's public ABI. An external caller is untrusted and
  may be a contract that reenters, a flash-loan borrower, or a crafted token.

## Common Sinks and Sources
- External calls: `.call`, `.delegatecall`, `.transfer`, `.send`, and any call into a
  user-supplied address or token, the reentrancy and unchecked-return surface.
- Price and supply reads: `balanceOf(this)`, `getReserves`, `slot0`, a spot AMM price,
  or `totalSupply` used in share math, the manipulation surface.
- Signatures: `ecrecover`, EIP-712 `hashTypedData`, permit, the replay and malleability
  surface.
- Upgrade machinery: `delegatecall`, proxy `implementation`, `initialize`, `selfdestruct`.

## Gotchas
- Checks-effects-interactions: state must be written before an external call, or the
  callee can reenter the pre-update state. A `nonReentrant` guard does not stop
  cross-function or read-only reentrancy.
- Solidity 0.8 checks arithmetic by default, so overflow is reverting unless the code is
  in an `unchecked` block or a pre-0.8 pragma. Do not report 0.8 overflow outside those.
- `tx.origin` for authorization is phishable, use `msg.sender`.
- A low-level `.call` returns success as a bool, an ignored return value swallows the
  failure. `transfer`/`send` forward only 2300 gas.
- An `initialize` with no initializer guard, or a proxy left uninitialized, lets anyone
  take ownership. `delegatecall` runs foreign code in this contract's storage.
- Rounding direction matters: a vault must round shares against the depositor and assets
  against the redeemer, or value leaks.
