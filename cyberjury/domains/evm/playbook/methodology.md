# Contract Security Review: Agent Methodology

A whole-protocol smart contract audit run by an interactive coding agent such as Claude
Code or Codex. The agent does not review the protocol in one pass. It maps the attack
surface, splits it into per-contract units, runs a focused deep review on each in
parallel, and aggregates the results.

## Why Fan Out

A single agent reviewing a whole protocol dilutes. Its attention spreads across every
contract, each function gets a shallow look, and the deep cross-contract flaws below the
entrypoint are missed. Decomposed into per-contract units with one focused sub-review
each, recall holds at scale. Recall comes from per-unit focus and parallelism, not from
one agent's rounds.

So the work is three phases:

- **Map**: build the attack-surface inventory, the role and ownership model, and the
  value map. The inventory is the coverage denominator: you cannot claim coverage against
  what you happened to notice, only against an enumerated list of external entrypoints.
- **Fan Out**: decompose the surface into per-contract units and run a focused deep
  sub-review on each, in parallel. Each traces its functions to where value moves and
  challenges every control. This is where findings are made.
- **Aggregate**: collect the unit verdicts, derive coverage against the inventory, and
  report the confirmed findings, each carrying the refutation it survived.

Workspace: `<workspace>/<project>/`, holding `inventory/`, `units/`, `candidates/`,
`pocs/`, and `findings/`. You write proposals into `candidates/` and proofs into `pocs/`.
Finalize confirms them into `findings/`.

---

## On Start

1. Read `_stack.md`, the Solidity review notes, so you know where contract entrypoints,
   value, and sinks live. Read `_facts.md` when it is present, the Slither-derived call
   graph and storage facts the scaffold extracted.
2. Read the relevant classes in `_vulnerabilities.md` and `_false_positive_traps.md`. You
   apply both per unit, not from memory.

---

## Phase 1: Map the Attack Surface

*Build the denominator. A function you never list is a function you never review.*

Enumerate every externally reachable entrypoint into `inventory/`, one row each, grouped
by contract: every `external` and `public` function, plus `fallback` and `receive`. For
each record the contract, the function, the access control on it, owner-only or
role-gated or open, and a review status.

Then record three cross-cutting artifacts in `inventory/`:

- **The role and ownership model**: every privileged role, owner, admin, governance, the
  minter and upgrader, which functions each can call, and how a role is granted or
  transferred. Every unit refers to this instead of re-deriving it.
- **The value map**: where funds and value-bearing state live, the vault and pool
  balances, the share and accounting math, the price and oracle sources, and every path
  that mints, burns, or moves value, since a value-leak has no obvious entrypoint and an
  entrypoint-anchored read misses it.
- **The intent invariants**: the operator-seeded `inventory/_invariants.md`, the core
  assets, who may legitimately move each, and the properties that must always hold,
  conservation of value, single-use of a nonce or voucher, monotonic supply and balances,
  ownership of a position, ordering across a multi-call flow, with the blast radius if one
  breaks. A static read sees the modifiers but not the protocol's intended accounting, so
  this names the intent a unit checks against. When the operator left it blank, it seeds
  nothing and a unit reviews exactly as before.

---

## Phase 2: Fan Out

*Decompose the surface into units and review each deeply, in parallel.*

### Define the Units

The scaffold has written the unit worklist into `units/`, one unit per candidate contract
the Solidity guide flagged, each opening with `- Status: open` and carrying the same fixed
deep-review mandate. You do not invent the units or decide how deep each goes. Your job is
to make the worklist complete, then run it.

Supplement the seeded units with what glob-based seeding cannot know, copying the mandate
from a seeded one:

- **Contracts no glob flagged**: add a unit for each contract with external surface.
- **Sequence units**: add one per multi-step or multi-contract flow whose invariant spans
  several calls, for example deposit then borrow then liquidate, or a cross-contract
  callback, where a per-contract look misses an invariant that breaks across the sequence.

Every entrypoint in `inventory/_surface.md` must be owned by some unit. A unit's
sub-review flips its status to `- Status: reviewed` when it returns with findings or an
evidenced clear, and the gate refuses to call the review complete while any unit is still
open.

### Review Each Unit, in Parallel

This step decides recall, so it is mechanical, not discretionary. For every unit in
`units/`, launch one dedicated sub-review that owns only that unit. One subagent per unit,
no unit skipped, no two merged to save calls. Run them in parallel.

Do not review units yourself in this main context. Your job here is to orchestrate:
enumerate, decompose, spawn one sub-review per unit, and aggregate. The deep reading
happens inside each subagent. Each sub-review follows the full mandate in the unit file:
it traces every external function into the internal code, inherited base contracts,
libraries, and called contracts it reaches, hunts the high-impact classes, verifies each
control on the code it actually reads, including inherited modifiers and the called
protocol, refutes its own candidates, and grades every real finding by the rubric.

---

## Phase 3: Aggregate

*Pull the unit results together, derive coverage, and report what survived.*

- **Coverage**: count the units with a verdict over the units in the inventory. An
  un-reviewed unit is a known gap, list it, do not report the review clean with units
  outstanding.
- **Dedup**: merge the findings several units reached from different contracts, keeping
  the highest-impact instance.
- **Severity**: report every real finding, graded by the severity rubric in
  `inventory/_severity.md`, CRITICAL through LOW. The only thing dropped is a finding whose
  controlling fact holds when you read the code. When unsure between two levels, report at
  the higher and say why.

Write each candidate to `candidates/<name>.md` with a runnable proof at `pocs/<name>.<ext>`
under the same `<name>`:

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
proof strengthens it, but when a deploy or runtime fact is missing, mark it `blocked` with
the exact `Needs:` rather than dropping it.

---

## Operator Verification and Safety

The review runs unattended to completion and never pauses to ask the operator anything.
When a finding needs a fact you cannot read, which oracle is wired in, a deployed address,
live state, mark it `blocked` with the exact `Needs:`, grade it on the conservative
assumption, and keep going. Gather every operator need into one list at the end.

Proof execution is local and human-in-the-loop. Run a proof only as a local Foundry test or a
fresh local deploy, never against mainnet, a live deployment, or a fork. Never
broadcast a transaction, never hold or use a private key, never run a destructive action
without the operator's explicit go-ahead. The tool finds and proves, the operator
discloses.

---

## Accumulate Across Runs

The persistent workspace carries settled work across runs. A unit already marked
`- Status: reviewed` is not re-reviewed, proposals in `candidates/` are not re-derived, and
a finding already verified is not re-litigated. A re-run picks up the units still open and
stops when the gate passes.
