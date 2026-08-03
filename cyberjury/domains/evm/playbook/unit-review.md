# Unit Review Mandate

You own only the files listed in this unit. Going deep on them is your whole job, do not
review anything else.

Read every `external`, `public`, `fallback`, and `receive` function these files expose and
trace each one into the internal functions, libraries, base contracts it inherits, and
external contracts it calls, down to where value moves or state changes. The flaw often
lives in an inherited modifier, a library, or a called protocol, not the entrypoint. Read
the shared `_stack.md` and `inventory/_auth_model.md` for the role and ownership model,
`inventory/_invariants.md` for the operator-seeded intent invariants, `_vulnerabilities.md`
for the class definitions with vulnerable and secure examples, and `_false_positive_traps.md`
for the recurring ways a static read misjudges them.

Hunt the high-impact classes: reentrancy, missing or broken access control, oracle and
price manipulation, accounting and precision errors, proxy, delegatecall, and initializer
flaws, signature replay, unchecked low-level calls, weird ERC-20 behavior such as
fee-on-transfer and rebasing tokens, and denial of service. Money is the asset, grade
every finding by funds moved, locked, or stolen.

For every control on the path, decide on the code you actually read, never on the presence
of a named guard:

- **Reentrancy**: is state written before every external call or token transfer on this
  path? A `nonReentrant` modifier guards one function, not the cross-function path that
  shares the same state, nor a read-only reentrancy where another protocol reads this
  contract's view mid-update. A push transfer re-enters too: when this contract itself
  calls `safeTransferFrom` of an NFT or an ERC-1155, or sends an ERC-777 token, to a
  recipient the caller controls, the recipient's `onERC721Received`, `onERC1155Received`,
  or `tokensReceived` hook runs before the calling function returns, so a liquidation, a
  settlement, or a loan cleanup that moves a position to its owner before it finishes
  updating collateral or debt accounting hands that owner a reentry into the partly updated
  state, and the owner can instead revert in the hook to block the transfer for an
  unliquidatable position. Trace the full effects-then-interactions ordering, an internal
  settlement function counts even though it is not an entrypoint. Do not clear a token
  transfer as safe because the token is typed `ERC20`. If the token address is not one
  hardcoded constant but is set per loan, per market, or by the caller, the concrete token
  may be an `ERC777`, whose `tokensReceived` hook runs inside a plain `transfer` or
  `safeTransfer` and hands control to the recipient. A payout, a buyout, or a settlement that
  sends such a token to a recipient the caller controls, and only afterward finalizes the loan
  or position record, is a reentrancy you must surface, the same as an NFT push. A fungible
  token does not close the hook. Refute this only when the asset is one fixed address you can
  read and confirm has no callback.
- **Access control**: is the privileged function gated to the exact role, by a modifier
  that may live in an inherited base, and on `msg.sender` not `tx.origin`? Compare
  siblings: where most privileged functions carry a modifier and one does not, that one is
  the likely hole. The gate is not only a modifier, it may be a call to a shared check, a
  blacklist, a pause, a freeze, a sanity hook. Enumerate every entrypoint that should carry
  the invariant and confirm each one does, do not stop at the first that holds: when
  `transfer` and `transferFrom` route through a blacklist or sanity check but `approve`,
  `permit`, or a sibling that grants or moves value does not, that uncovered sibling breaks
  the invariant. The uncovered sibling may be inherited and not restated in this file: a
  token that gates `transfer` and `transferFrom` but leaves the inherited `approve`,
  `increaseAllowance`, or `permit` ungated still lets a blacklisted account hold an
  allowance, so treat the standard inherited entrypoints as present even when the file does
  not redefine them. Check the initializer is guarded and the proxy cannot be re-initialized.
- **Oracle and value source**: is a price or value read from a manipulation-resistant
  source with a staleness and bounds check, or from an in-transaction-movable spot price,
  reserves, or raw balance a flash loan can move for free?
- **Accounting**: does share, fee, or balance math round against the user and multiply
  before dividing, and is the first deposit seeded or capped against share-price inflation?
  When a `transferFrom` or a pull payment charges a fee on top of the amount, confirm the
  allowance or approval covers the amount plus the fee, not the amount alone, or a spender
  moves more of the holder's balance than was approved.
- **Signatures**: is a signed privileged message bound to a nonce, a chainid, and a domain
  separator, the signer checked nonzero? A signature alone is replayable.
- **Failure mode**: when a call or a guard fails, does the path fail closed or fail open? A
  low-level `call`, `delegatecall`, or `send` whose returned success bool is not checked lets
  execution continue as if it succeeded, and a `try/catch` whose catch branch proceeds rather
  than reverting leaves the contract in a partly updated state. Confirm a failed external call
  or check reverts the transaction rather than silently continuing.
- **Trusted-source**: is a value treated as safe only because a caller you treat as trusted
  set it, when that caller is an arbitrary external account or contract?
- **Seeded invariant**: can a reachable path break a property the operator asserts must
  always hold in `inventory/_invariants.md`, conservation of value, single-use of a nonce
  or voucher, monotonic supply or balances, ownership of a position, ordering across a
  flow? Check only the invariants whose assets or functions this unit's code actually
  touches, and skip every other row. Trace each one that applies, an unconserved mint, a
  reused signature, a balance moved the wrong way, a position mutated by a non-owner, a
  step run out of order, and treat a breakable invariant as a finding, the same as any
  guard you read. Decide on the code you read, not on the row: a seeded property is a
  hypothesis to test against this path, never a finding on its own. When the file is blank,
  or no seeded row touches this unit's code, there is nothing to check here and you report
  nothing for it. A confirmed break is graded by funds moved, locked, or stolen per the
  rubric, the seeded blast radius is its floor, and a property the code preserves is a
  cleared control you record, not a finding.

Refute in place: name the one controlling fact that would make the code safe, read that
exact code, including inherited modifiers and the called contract, and settle it. Confirmed
if the control is absent or bypassable, refuted if it holds, blocked if it turns on a
deploy-time or runtime fact you cannot read, for example which oracle address is wired in.

Recall comes first within the high-impact classes: when you are unsure a fund-moving flaw
is real, surface it, and never drop a real exploitable finding to keep the report clean. A
weaker signal on a high-impact class is a lower severity, not a dropped finding.

These are not findings here, do not report them:

- A trusted owner, admin, or role acting through a correctly gated privileged function.
  Centralization by design, an admin who can pause, seize, mint, or redirect fees on a
  properly restricted path, is not a finding. Report it only when the gate is missing, the
  wrong role, or reachable by an arbitrary caller.
- Upgrade and initializer hygiene with no exploit shown: a missing storage gap, a missing
  or unused initializer, a loop that "could" run out of gas. Report these only with a
  concrete reachable path that moves, locks, or corrupts funds.
- A guess about code outside this unit. When a flaw turns on a function or value you could
  not read, trace it or mark it `blocked` with the exact `Needs:`, never report it confirmed
  on a "not visible in this unit" basis.
- Dependency or compiler advisories, gas and style notes with no security impact, and a
  candidate the facts refute.

Write a runnable proof when you can, a Foundry test that reproduces the exploit strengthens
a finding. When you cannot run one, still report it, marking `Status: blocked` with the
exact `Needs:`, for example a deployed address or live state, or citing the traced controlling
fact in Analysis. Lack of a proof lowers confidence, it does not drop a real finding. Never
broadcast a transaction, never hold a private key, run a proof only as a local Foundry test
or a fresh local deploy.

Grade every real finding by the severity rubric in `inventory/_severity.md` and report all
of them. There is no refuting a real exploitable finding for low impact. Do not talk a real
finding down with a plausible word: "the guard is on another function", "the array is
usually small", "the owner would not do that" lower the severity per the rubric, they do
not make the finding disappear.

Write each confirmed or blocked finding to `candidates/<name>.md`: Risk, Type, Source as the
contract and function, Status, Analysis citing `file:line`, Attack Path, and Fix. Save a
runnable proof to `pocs/<name>.<ext>` under the same `<name>`, so finalize can match it.
Record any cleared control with the controlling fact that cleared it. Then set this unit's
Status to `reviewed`.
