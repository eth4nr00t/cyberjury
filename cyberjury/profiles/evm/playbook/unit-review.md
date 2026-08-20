# Unit Review Mandate

## Scope and Context

Review only the source and facts supplied for this unit. Trace every `external`, `public`,
`fallback`, and `receive` entrypoint into the included internal functions, inherited contracts,
libraries, and external calls until value moves or state changes. Use the shared stack, role,
ownership, vulnerability, severity, and false positive context supplied with the unit.

Do not assume a control exists outside the supplied evidence. When the prompt publishes an
evidence id for a missing controlling fact, request that id instead of guessing.

## Hunt High Impact Classes

Hunt reentrancy, missing or broken access control, oracle and price manipulation, accounting and
precision errors, proxy, delegatecall, and initializer flaws, signature replay, unchecked low
level calls, unusual ERC-20 behavior such as fee on transfer and rebasing tokens, and denial of
service.

## Enumerate Harm

When attacker controlled input or a caller controlled asset reaches a value moving call, external
contract, callback, or state transition, enumerate every concrete harm the flow enables. The same
flow may steal funds, lock funds, corrupt accounting, authorize another call, or grief another
user. Grade the finding by the most severe demonstrated harm.

## Verify Controls

For every control on the path, decide from the supplied code and facts, never from the presence of
a named guard:

- **Authorization granularity**: check that the right principal, owner, or role protects the exact
  operation. Compare inherited and sibling entrypoints for a dropped or weaker check.
- **Disclosure and value exposure**: check whether a view, transfer, or state transition exposes
  funds, balances, allowances, ownership, or privileged state to a caller with less authority.
- **Replay and signatures**: check that a privileged message consumes a nonce and binds the chain,
  domain, signer, payload, and intended operation.
- **State and concurrency**: check that shared state is consistent before every external call or
  token transfer. A guard on one function does not protect an unguarded sibling or a stale view.
- **Input and value sources**: check whether a caller chooses a token, callback target, oracle,
  spot price, reserve, or raw balance. Treat a source as trusted only when the evidence fixes it or
  proves it manipulation resistant.
- **State and accounting**: check rounding direction, operation order, unit scale, fee handling,
  first depositor behavior, and ownership or debt invariants on every branch.
- **Failure mode**: check whether a failed call reverts or can leave completion state recorded.
  Inspect low level call status, token return data, and permissive catch branches.
- **Reachability and siblings**: prove that an exposed entrypoint reaches the sink with attacker
  controlled values. Trace inherited and sibling functions that share the invariant.

## Refute in Place

For each candidate, name the controlling fact that would make it safe and inspect that exact
evidence. Confirm the candidate when the control is absent or bypassable. Refute it only when the
control holds. Mark it blocked when a necessary deploy time or runtime fact is unavailable.

## Finding Standard

Report only a real exploitable issue with a concrete file, line, category, exploit path, and
controlling evidence. Do not report a correctly gated privileged action, harmless hygiene,
dependency or compiler advisories, gas or style notes, a guess about unavailable code, or a
candidate that the evidence refutes.

Grade every reported issue by the supplied severity rubric from `CRITICAL` through `LOW`. A weaker
impact lowers severity. It does not refute an evidenced issue. Keep a blocked issue when only an
unavailable controlling fact prevents confirmation, and state the exact missing fact.

## Response

Return only the role specific JSON object requested after this mandate. Do not claim to run tools,
write candidate or proof files, record cleared controls, or change unit status. The coded workflow
owns persistence, verification, proof execution, and completion state.
