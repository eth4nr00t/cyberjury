# False-Positive Traps

Recurring ways a static read misjudges a contract finding, in both directions: calling it
real when it is safe, and refuting a real one on an incomplete read. The refutation step
checks a candidate against every trap below. Most name the controlling fact to confirm in
the code, the rest state that fact themselves. When a real run later proves a new
recurring misjudgement, add it here.

## Reentrancy Guards

- A `nonReentrant` modifier guards only the function it is on. It does not stop
  cross-function reentrancy into a different function sharing the same state, nor read-only
  reentrancy where another protocol reads this contract's view mid-update.
  Controlling fact: is state written before the external call on this path, and are the
  other functions that touch the same state also guarded or already updated?
- The obvious record being written before the external call does not refute the finding by
  itself. A buyout, a settlement, or a swap often finalizes in stages: it writes the main
  struct, makes a payout, then hands an ownership token or a position to the new party. List
  every state write and every ownership or authorization handover that runs after the
  external call, in this function and in any function the callback can reach such as a repay
  or close that reads `ownerOf`. The reentrant caller still holds whatever a later handover
  has not yet moved. Controlling fact: during the callback window, what does each `ownerOf`,
  balance, or role read return, and can a reentrant call into another function be paid or
  authorized against that stale ownership?
- A payout made with a plain ERC-20 `transfer` or `safeTransfer` still hands control to the
  recipient when that token is ERC-777 or carries a transfer hook, so paying a recipient the
  caller chooses before the position is finalized is a reentrancy sink, not only a
  `.call{value:}` or an NFT `safeTransferFrom`. Controlling fact: is the asset one fixed
  address you can read and confirm has no callback, or is it set per market, per loan, or by
  the caller?
- A `.transfer` or `.send` forwards only 2300 gas, too little to reenter, so a plain ETH
  `transfer` is not a reentrancy sink. A `.call{value:}` forwards all gas and is.

## Access Control off the Function Body

- The `onlyOwner` or role modifier may be declared in an inherited base contract, not in
  the file you are reading. Controlling fact: does the check live anywhere in the
  inheritance chain, including the modifier definition?
- A `constructor` with `_disableInitializers()` or an `initializer` modifier makes
  `initialize` non-re-callable. Controlling fact: is the initializer actually guarded, and
  is the proxy initialized at deploy?

## Arithmetic

- Solidity 0.8 and later revert on overflow and underflow by default. An add or subtract
  outside an `unchecked` block is not an overflow finding. Controlling fact: is the pragma
  below 0.8, or does the code sit in an `unchecked` block?

## Token and Call Returns

- `SafeERC20`'s `safeTransfer`/`safeTransferFrom` revert on failure, so they are not an
  unchecked-return finding. A raw `IERC20.transfer` whose bool is ignored is.
  Controlling fact: is the call wrapped or its return checked?

## Input That Looks Attacker-Controlled but Is Not

- A `constant`, an `immutable` set in the constructor, or a value only an owner-gated path
  can set is not attacker-controlled even though it feeds a sink. Controlling fact: where
  is the value actually set, not where it is read?
- An address passed by an arbitrary external caller is attacker-controlled, including a
  token or callback target, so treat it as hostile.

## Oracles and Reachability

- A price feed is only manipulable if the source moves within a transaction. A vetted
  oracle with a staleness and bounds check is not the same as a spot AMM read.
  Controlling fact: which source does the value actually come from, and can a flash loan
  move it for free in one transaction?
- A dangerous sink is only exploitable if an external caller can reach it with chosen
  values. Controlling fact: is there a concrete path from an external function to the sink?

## Refuting Safely: Recall Comes First

Refute only when a controlling fact makes the code genuinely safe: the access is actually
gated, the reentrancy ordering holds on every path, the value source is not movable, the
signature is bound and single-use. A real finding wrongly refuted is worse than a false
positive kept, so these bind the refutation:

- Do not refute for bounded impact, an array "usually small", or "the owner would not do
  that". Those lower the severity, they do not delete a real finding.
- A finding usually has several harm paths: fund theft, fund lock, accounting corruption,
  griefing. Rule out every path to refute, not just the first.
- When you are not certain it is safe on all paths, keep it real.
