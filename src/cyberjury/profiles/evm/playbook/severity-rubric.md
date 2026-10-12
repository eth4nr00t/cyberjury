# Severity Rubric

Every real finding is reported at a calibrated severity. There is no "refuted for low
impact" outcome. A real, evidenced defect is graded and surfaced, never talked out of
existence.
Only an unreal finding, one whose controlling fact holds when you read the code, is
dropped. That is a refutation on the facts, not on the impact.

Grade by impact times exploitability, on the code you read:

- **CRITICAL**: direct theft, unauthorized minting, or permanent loss or lock of funds
  with little or no precondition. Drain a pool or vault through reentrancy, mint unlimited
  supply through a missing access check, seize ownership through an unguarded initializer
  or proxy, execute arbitrary `delegatecall`, or reach `selfdestruct` that bricks held
  funds.
- **HIGH**: funds are taken or locked with a precondition that is one line in the attack
  path, not a reason to drop the finding. Examples include a flash loan, a particular
  market state, winning a race, holding one signed message, flash-loan oracle
  manipulation, a replayable privileged signature, griefing that locks user funds, and a
  rounding or first-depositor attack that captures deposits.
- **MEDIUM**: a real but bounded defect. Examples include a precision leak of dust, a DoS
  that recovers or only delays, a manipulation needing capital out of proportion to the
  gain, or an issue gated by a trusted role misbehaving. Report it. Do not refute it.
- **LOW**: a real issue with a narrow or weak exploit path, such as a bypassable control or
  a concrete low-impact defect. A pure hardening gap, a missing event, or a missing
  zero-address check with no concrete exploit is not LOW. It is not reported. See the
  out-of-scope list.

Firm rules override a cautious instinct to downgrade to nothing:

- An external call or token transfer before the state update on a value-moving path is a
  reentrancy finding, at least HIGH, even with a guard elsewhere, until cross-function and
  read-only paths have been read and shown safe.
- A privileged function that mints, burns, moves funds, upgrades, or destroys the contract
  and is reachable without the access control its siblings require is at least HIGH, and
  CRITICAL when it directly moves or mints funds.
- An unguarded or re-callable `initialize`, or a logic contract left initializable behind a
  proxy, is at least HIGH because it hands over ownership or the implementation.
- A price or value read from an in-transaction-movable source, a spot AMM price, reserves,
  or a raw balance, used in a value decision is at least HIGH.
- When unsure between two levels, report the higher and say why. Uncertainty about grading
  is not a reason to drop a finding. Only an unreal finding is dropped.

## Out of Scope vs LOW

Recall comes first, so a real finding is almost never dropped. Do not report dependency or
compiler-version advisories, gas-optimization and style notes with no security impact, a
missing event or zero-address check with no concrete exploit, a pure hardening gap, or a
candidate the facts refute.

Everything else real is reported and graded. A weak signal is LOW, not dropped. A
bounded-impact finding with a real exploit path is LOW or MEDIUM and surfaced. Noise is
managed by sorting on severity, never by suppressing a real finding. A missed real finding
is worse than a LOW the reader skips.
