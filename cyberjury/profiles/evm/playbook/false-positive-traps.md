# False-Positive Traps

Recurring ways a static read misjudges a finding, in both directions: calling it real
when it is safe, and refuting a real one on an incomplete read. The refutation step checks
each candidate against every trap below. Most name the controlling fact to confirm in the
code. When a real run proves a new recurring misjudgement, add it here.

## State Changes and External Effects

- A `nonReentrant` modifier guards only the function it is on. It does not stop
  cross-function reentrancy into another function sharing the same state, nor read-only
  reentrancy where another protocol reads this contract's view mid-update. Controlling
  fact: is state written before the external call on this path, and are other functions
  touching the same state also guarded or already updated?
- The obvious state change does not refute reentrancy by itself. A buyout, settlement, or
  swap can write the main struct, make a payout, and hand over an ownership token in stages.
  Controlling fact: during the callback window, what do each `ownerOf`, balance, or role read
  return, and can a reentrant call be paid or authorized against stale ownership?
- A plain ERC-20 `transfer` or `safeTransfer` still hands control to the recipient when the
  token is ERC-777 or carries a transfer hook. Controlling fact: is the asset one fixed
  address you can read and confirm has no callback, or is it set per market, per loan, or by
  the caller?
- A `.transfer` or `.send` forwards only 2300 gas, too little to reenter, so plain ETH
  `transfer` is not a reentrancy sink. A `.call{value:}` forwards all gas and is a
  reentrancy sink.

## Controls off the Entry Point

- An `onlyOwner` or role modifier may be declared in an inherited base contract, not in the
  file being read. Controlling fact: does the check live anywhere in the inheritance chain,
  including the modifier definition?
- A `constructor` with `_disableInitializers()` or an `initializer` modifier makes
  `initialize` non-recallable. Controlling fact: is the initializer guarded, and is the
  proxy initialized at deploy?

## Input and Value Sources

- Solidity 0.8 and later revert on overflow and underflow by default. An add or subtract
  outside an `unchecked` block is not an overflow finding. Controlling fact: is the pragma
  below 0.8, or does the code sit in an `unchecked` block?
- The `SafeERC20` helpers `safeTransfer` and `safeTransferFrom` revert on failure, so they are not
  unchecked-return findings. A raw `IERC20.transfer` whose bool is ignored is. Controlling
  fact: is the call wrapped or its return checked?
- A `constant`, an `immutable` set in the constructor, or a value only an owner-gated path
  can set is not attacker-controlled even though it feeds a sink. Controlling fact: where
  is the value actually set, not where it is read?
- An address passed by an arbitrary external caller is attacker-controlled, including a
  token or callback target, so treat it as hostile. Controlling fact: can the caller choose
  the address on the path to the sink?
- A price feed is manipulable only if its source moves within a transaction. A vetted oracle
  with staleness and bounds checks is not the same as a spot AMM read. Controlling fact:
  which source does the value actually come from, and can a flash loan move it for free in
  one transaction?

## Reachability

- A dangerous sink is exploitable only if an external caller can reach it with chosen values.
  Controlling fact: is there a concrete path from an external function to the sink? If the
  value is constant or owner-set, or the only caller is internal, there is no exploit.

## Refuting Safely: Recall Comes First

Refute only when a controlling fact makes the code genuinely safe: access is gated,
reentrancy ordering holds on every path, the value source is not movable, and the signature
is bound and single use. A real finding wrongly refuted is worse than a false positive kept,
so these rules bind the refutation:

- Do not refute for bounded impact, an array that is usually small, or an owner who would
  not act maliciously. Those lower the severity. They do not delete a real finding.
- A finding usually has several harm paths: fund theft, fund lock, accounting corruption,
  and griefing. Rule out every path to refute, not just the first one.
- When you are not certain it is safe on all paths, keep it real.
- When a controlling deploy-time or runtime fact is unavailable, keep the candidate blocked
  with its exact `Needs:` rather than treating the missing fact as a refutation.
