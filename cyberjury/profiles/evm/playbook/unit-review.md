# Unit Review Mandate

## Scope and Context

You own only the files listed in this unit. Going deep on them is your whole job. Do not
review anything else.

Read every `external`, `public`, `fallback`, and `receive` function these files expose and
trace each one into internal functions, libraries, inherited base contracts, and external
contracts it calls, down to where value moves or state changes. The flaw often lives in an
inherited modifier, a library, or a called protocol, not the entrypoint. Read the shared
`_stack.md` and `inventory/_auth_model.md` for the role and ownership model,
`_vulnerabilities.md` for the relevant class definitions with vulnerable and secure examples,
and `_false_positive_traps.md` for recurring ways a static read misjudges them.

## Hunt High-Impact Classes

Hunt reentrancy, missing or broken access control, oracle and price manipulation, accounting
and precision errors, proxy, delegatecall, and initializer flaws, signature replay,
unchecked low-level calls, unusual ERC-20 behavior such as fee-on-transfer and rebasing
tokens, and denial of service.

## Enumerate Harm

When attacker-controlled input or a caller-controlled asset reaches a value-moving call,
external contract, callback, or state transition, enumerate every harm it enables, not only
the first one you see, and grade by the worst. The same flow can steal funds, lock funds,
corrupt accounting, authorize a second call, or grief another user. Name each harm path.

## Verify Controls

For every control on the path, decide on the code you actually read, never on the presence
of a named guard:

- **Authorization granularity**: does the check scope to the right principal, owner,
  tenant, or role, or only prove the caller is some valid account? Compare sibling
  functions, inherited entrypoints, and standard methods for a dropped or weakened check.
- **Disclosure and value exposure**: does a view, transfer, or state transition expose funds,
  balances, allowances, ownership, or privileged state to a caller with less authority? A
  hidden field or internal balance is safe only when the code actually protects it.
- **Replay and signatures**: does a signed privileged message consume a nonce and bind the
  chain id, domain separator, and signer? A signature alone is not enough.
- **State and concurrency**: is state written before every external call or token transfer?
  A `nonReentrant` modifier guards one function, not a cross-function or read-only path. A
  token hook still hands control to a caller-controlled recipient.
- **Input and value sources**: can a caller choose a token, callback target, oracle input,
  spot price, reserve, or raw balance? A value source is trusted only when the code proves
  it is fixed or manipulation-resistant.
- **State and accounting**: does share, fee, allowance, or balance math round against the
  user and multiply before dividing? Does every branch preserve the right ownership and
  debt invariant, including first deposit and fee-on-transfer behavior?
- **Failure mode**: when a call or guard fails, does the path fail closed or fail open? A
  low-level `call`, `delegatecall`, or `send` whose success bool is ignored, or a catch
  branch that proceeds, can leave the contract in a partly updated state.
- **Reachability and siblings**: can every exposed entrypoint reach the sink with chosen
  values, and do inherited or sibling functions carry the same invariant? An internal-only
  caller or a constant value is not an exploit.

## Refute in Place

Name the one controlling fact that would make a candidate safe, read that exact code,
including inherited modifiers and the called contract, and settle it. Confirmed if the
control is absent or bypassable, refuted if it holds, and blocked if it turns on a deploy
time or runtime fact you cannot read.

## Recall and Scope

Recall comes first. When unsure whether a fund-moving flaw is real, surface it. A weaker
signal on a high-impact class is a lower severity, not a dropped finding. Report every real
issue with a concrete exploit path. Do not report a correctly gated privileged action,
upgrade or initializer hygiene with no exploit shown, a guess about code outside this unit,
dependency or compiler advisories, gas or style notes with no security impact, or a
candidate the facts refute.

## Proof

Write a runnable proof when you can. A Foundry test that reproduces the exploit strengthens a
finding. When you cannot run one, still report it with `Status: blocked` and the exact
`Needs:`, or cite the traced controlling fact in Analysis. Lack of a proof lowers
confidence. It does not drop a real finding. Never broadcast a transaction or use a private
key. Run a proof only as a local Foundry test or a fresh local deploy.

## Grade Findings

Grade every real finding by `inventory/_severity.md` and report all of them, CRITICAL
through LOW. There is no refuting a real exploitable finding for low impact. A real,
evidenced defect is graded and surfaced at its level. Only a finding whose controlling fact
holds when you read the code is dropped. Do not talk a real finding down with a plausible
word such as "the guard is on another function", "the array is usually small", or "the
owner would not do that". Those lower the severity per the rubric. They do not make the
finding disappear.

## Write Findings

Write each confirmed or blocked finding to `candidates/<name>.md`: Risk, Type, Source as
the contract and function, Status, Analysis citing `file:line`, Attack Path, and Fix. Save
a runnable proof to `pocs/<name>.<ext>` under the same `<name>` so finalize can match it.
Record every cleared control with the controlling fact that cleared it, so a wrong clear is
visible. Then set this unit's Status to `reviewed`.
