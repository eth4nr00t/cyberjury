# Repository Security Review: Agent Methodology

A whole repository smart contract audit run by an interactive coding agent such as Claude
Code or Codex. The agent does not review the repository in one pass. It maps the attack
surface, splits it into small units, runs a focused deep review on each unit in parallel,
and aggregates the results.

## Why Fan Out

A single agent reviewing a whole protocol dilutes. Its attention spreads across every
contract, each function gets a shallow look, and deep cross-contract flaws below the
entrypoint are missed. Decomposing the surface into per-contract units with one focused
sub-review each keeps recall at scale. Recall comes from per-unit focus and parallelism,
not from one agent's rounds or from re-running the whole review many times.

So the work is three phases:

- **Map**: build the attack-surface inventory, the role and ownership model, and the
  value map. The inventory is the coverage denominator. You cannot claim coverage against
  what you happened to notice, only against an enumerated list.
- **Fan Out**: decompose the surface into units and run a focused deep sub-review on each,
  in parallel. Each unit gets full attention on a small slice, traces it to where value
  moves or state changes, and challenges every control. This is where findings are made.
- **Aggregate**: collect the unit verdicts, derive coverage against the inventory, and
  report the confirmed findings, each carrying the refutation it survived.

The one irreducible human dependency, credentials and approval to run a proof safely, is
deferred to a separate phase and never requested mid-run.

Workspace: `<workspace>/<project>/`, created for you, holding `inventory/`, `units/`,
`candidates/`, `pocs/`, and `findings/`. The workspace marker lives in
`.cyberjury/workspace.json`. You write proposals into `candidates/` and proofs into
`pocs/`. Finalize confirms them into `findings/`.

---

## On Start

1. Read `_stack.md`, the Solidity review notes, so you know where this stack's contract
   entrypoints, value, and sinks live. Read `_facts.md` when it is present, the
   Slither-derived call graph and storage facts the scaffold extracted.
2. Read the relevant classes in `_vulnerabilities.md`, the shipped class definitions with
   vulnerable and secure examples, and `_false_positive_traps.md`, the recurring ways a
   static read misjudges them. Apply both per unit, not from memory.

---

## Phase 1: Map the Attack Surface

*Build the denominator. A unit you never list is a unit you never review.*

Enumerate every externally reachable entrypoint into `inventory/`, one row each, grouped
by contract: every `external` and `public` function, plus `fallback` and `receive`. For
each entrypoint record the contract, function, access control, role or owner requirement,
and review status.

Untrusted input enters at more than direct function arguments:

- External calls, token callbacks, ERC-721 and ERC-1155 receiver hooks, and fallback and
  receive functions.
- Caller-selected token, oracle, callback, implementation, delegatecall, and target
  addresses.
- Signatures, permits, approvals, prices, reserves, balances, and deployment parameters
  that a contract treats as trusted.
- Cross-contract calls, proxy wiring, governance actions, and configuration read as fixed.

Then record two cross-cutting artifacts in `inventory/_auth_model.md`:

- **The role and ownership model**: every privileged role, owner, admin, governance,
  minter, and upgrader, which functions each can call, how each role is granted or
  transferred, and the trust boundaries between them. Every unit refers to this instead
  of re-deriving it.
- **The value map**: where funds and value-bearing state live, vault and pool balances,
  share and accounting math, price and oracle sources, and every path that mints, burns,
  or moves value. A value leak has no obvious entrypoint, so an entrypoint-anchored read
  misses it.

---

## Phase 2: Fan Out

*Decompose the surface into units and review each deeply, in parallel.*

### Define the Units

The scaffold has already written the seeded unit worklist into `units/`, based on candidate
contract sources. A large source may be split into slices, and facts or import-closure
analysis may add derived units. Each unit opens with `- Status: open` and carries the same
fixed deep-review mandate. Do not change seeded boundaries or depth. Check coverage, then
complete the worklist.

Add only uncovered units that glob-based seeding cannot know, copying the mandate from a
seeded unit:

- **Contracts no guide flagged**: add a unit for every contract with an external surface.
- **Sequence units**: add one per multi-step or multi-contract flow whose invariant spans
  several calls, for example deposit then borrow then liquidate, or a cross-contract
  callback, where a per-contract look misses an invariant that breaks across the sequence.
- **Callback units**: add one for each token hook, callback, or cross-contract handoff whose
  effects span several contracts or functions.

Every entrypoint in `inventory/_surface.md` must be owned by some unit. A unit's sub-review
flips its status to `- Status: reviewed` when it returns with findings or an evidenced
clear. The gate refuses to call the review complete while any unit is still open, so the
unit list is the coverage ledger.

### Review Each Unit, in Parallel

This step decides recall, so it is mechanical, not discretionary. For every unit in
`units/`, launch one dedicated sub-review, a subagent that owns only that unit. One
subagent per unit, no unit skipped, and no two units merged to save calls. Run them in
parallel.

Do not review units yourself in this main context. Your job is to orchestrate, enumerate,
decompose, spawn one sub-review per unit, and aggregate. Keep this context lean so it does
not dilute. The deep reading happens inside each subagent.

Give each sub-review only its slice plus the shared artifacts: `_stack.md`, the inventory's
role and ownership model, `_vulnerabilities.md`, `_false_positive_traps.md`, and
`inventory/_severity.md`. Each sub-review follows the full mandate below:

1. **Traces** every external, public, fallback, and receive entrypoint in its unit into
   internal functions, inherited base contracts, libraries, and called contracts, to where
   value moves or state changes.
2. **Hunts** reentrancy, missing or broken access control, oracle and price manipulation,
   accounting and precision errors, proxy, delegatecall, and initializer flaws, signature
   replay, unchecked low-level calls, unusual ERC-20 behavior, and denial of service.
3. **Verifies** each control on the path, on the code it actually reads, never on the
   presence of a named guard. Challenge each one:
   - **Authorization granularity**: does the exact role gate the function through inherited
     modifiers and every sibling entrypoint, with checks on `msg.sender` rather than
     `tx.origin`?
   - **Disclosure and value exposure**: does a view, transfer, or state transition expose
     funds, balances, allowances, ownership, or privileged state to a caller with less
     authority? A hidden field or internal balance is safe only when the code protects it.
   - **Replay and signatures**: is the message bound to a nonce, chain id, domain separator,
     and a nonzero signer? A signature alone is not enough.
   - **State and concurrency**: is state written before every external call or token
     transfer, including cross-function and read-only paths? A token hook still hands
     control to a caller-controlled recipient.
   - **Input and value sources**: can a caller choose a token, callback target, oracle input,
     spot price, reserve, or raw balance? A value source is trusted only when the code proves
     it is fixed or manipulation-resistant.
   - **State and accounting**: does rounding, fee handling, or first-depositor behavior let
     an attacker move or lock value? Does every branch preserve ownership and debt?
   - **Failure mode**: do failed calls and guard errors revert, or can execution continue
     after a failed low-level call or permissive catch branch?
   - **Trusted source**: is a value treated as safe only because an arbitrary caller or
     contract set it?
4. **Refutes** in place. A candidate is a hypothesis. Name the one controlling fact that
   would make the code safe, then read that exact code, including inherited modifiers and
   called contracts, and settle it. If it holds, refute the candidate. If it is absent or
   bypassable, confirm it. If it turns on a deploy-time or runtime fact you cannot read,
   block it with the exact need. Refutation is part of the unit, not a later pass.

Each sub-review returns its findings with the contract and function, class, exact
`file:line` of the controlling fact, the end-to-end exploit, and the refutation it
survived. It returns cleared controls too, each with the controlling fact that cleared it,
so a wrong clear is visible.

---

## Phase 3: Aggregate

*Pull the unit results together, derive coverage, and report what survived.*

- **Coverage**: count the units with a verdict over the units in the inventory. Every unit
  must return with findings or an evidenced clear. An unreviewed unit is a known gap. List
  it and do not report the review clean with units outstanding.
- **Dedup**: merge findings reached from different entrypoints, keeping the highest-impact
  instance.
- **Severity**: report every real finding, graded by `inventory/_severity.md`, CRITICAL
  through LOW. A real, evidenced defect is graded and surfaced. Only a finding whose
  controlling fact holds when you read the code is dropped. When unsure between two
  levels, report the higher and say why.

Write each candidate finding to `candidates/<name>.md` with a runnable proof at
`pocs/<name>.<ext>` under the same `<name>`, so finalize can match the proof to the
confirmed finding it writes into `findings/`:

```markdown
# <title>
- Risk: CRITICAL | HIGH | MEDIUM | LOW
- Type: reentrancy | access-control | oracle-price-manipulation | ...
- Source: `<Contract>.<function>`
- Status: confirmed | blocked
- Needs: only when blocked, the exact fact a follow-up run must supply
## Analysis
(cite exact file:line)
## Attack Path
## Verification
(the refutation it survived, and any proof output, or the exact blocker)
## Fix
```

A finding needs a concrete controlling fact traced to a `file:line`. A runnable Foundry
proof strengthens it. When a deploy or runtime fact is missing, mark it `blocked` with the
exact `Needs:` rather than dropping it. Only a finding with no traced evidence at all is a
guess, so do not report it.

---

## Operator Verification

The review above runs unattended to completion and never pauses to ask the operator
anything. When a finding needs a runtime fact, deployed address, live state, or credential,
mark it `blocked` with the exact `Needs:`, grade it on the conservative assumption, and keep
going. Gather every operator need into one list at the end.

When the operator returns with answers, re-run over the same workspace driven by `Status`.
Act only on `blocked` findings, settle each with the available fact or a proof, and rewrite
the status in place. Never run a proof against production, a live deployment, or a fork.
Never broadcast a transaction, hold a private key, or run a destructive action without the
operator's explicit approval. A proof runs only as a local Foundry test or a fresh local
deploy.

---

## Accumulate Across Runs

The persistent workspace carries settled work across runs, so a re-run extends coverage
instead of restarting. A unit already marked `- Status: reviewed` is not re-reviewed, the
proposals in `candidates/` are not re-derived, and a finding already verified is not
re-litigated. A re-run, including after a usage limit, picks up the units still open and
stops when the gate passes.
