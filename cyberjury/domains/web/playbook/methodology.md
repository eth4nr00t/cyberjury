# Repository Security Review: Agent Methodology

A whole-repository security audit run by an interactive coding agent such as Claude Code
or Codex. The agent does not review the repository in one pass. It maps the attack
surface, splits it into small units, runs a focused deep review on each unit in
parallel, and aggregates the results.

## Why Fan Out

A single agent reviewing a whole large repository dilutes. Its attention spreads across
the entire surface, every endpoint gets a shallow look, and the deep cross-file
flaws below the entrypoint are missed. Measured on a real 30k-line backend, a
single cold pass recovered about a quarter of the known issues. The same surface,
decomposed into per-module units with one focused sub-review each, recovered all of
them. Recall at scale comes from per-unit focus and parallelism, not from one
agent's rounds and not from re-running the whole review many times.

So the work is three phases:

- **Map**: build the attack-surface inventory, the authorization model, and the
  sensitive-data map. The inventory is the coverage denominator: a real repository has
  100+ endpoints, and you cannot claim coverage against what you happened to
  notice, only against an enumerated list.
- **Fan Out**: decompose the surface into units and run a focused deep sub-review on
  each, in parallel. Each unit gets full attention on a small slice, traces it to
  its real sink, and challenges every control. This is where findings are made.
- **Aggregate**: collect the unit verdicts, derive coverage against the inventory,
  and report the confirmed findings, each carrying the refutation it survived.

The one irreducible human dependency, the credentials and go-ahead to run a PoC
safely, is deferred to a separate phase and never asked for mid-run.

Workspace: `<workspace>/<project>/`, created for you, holding `inventory/`,
`units/`, `candidates/`, `pocs/`, and `findings/`. You write proposals into
`candidates/` and PoCs into `pocs/`. Finalize confirms them into `findings/`.

---

## On Start

1. Read `_stack.md`, the seeded languages, frameworks, and protocols plus their
   review notes, so you know where this stack's entrypoints and sinks live.
2. Read the relevant classes in `_vulnerabilities.md`, the shipped class definitions
   with vulnerable and secure examples, and `_false_positive_traps.md`, the recurring
   ways a static read misjudges them. You apply both per unit, not from memory.

---

## Phase 1: Map the Attack Surface

*Build the denominator. A unit you never list is a unit you never review.*

Enumerate every attacker-influenced entrypoint into `inventory/`, one row each,
grouped by module. Untrusted input enters at more than HTTP:

- HTTP, GraphQL, gRPC, WebSocket handlers, CLI commands, scheduled jobs, queue and
  topic consumers, webhooks and third-party callbacks.
- Deserialization points such as pickle, yaml.load, or marshal, file and document
  parsers for XML, YAML, CSV, zip, or images, and template rendering of user input.
- File uploads, archive extraction, any filesystem path built from user input.
- Inbound inter-service calls, and headers, cookies, or config read as trusted.

Use the seeded entrypoint candidates as a starting subset, not the whole surface.
Open the route modules and read the actual registrations. For each entrypoint
record the module, the route, the auth method, and a review status.

Then record three cross-cutting artifacts in `inventory/`:

- **The authorization model**: how this codebase enforces access control, by a
  decorator, middleware, permission class, signature, or guard, the actors, tenants,
  and services, and the trust boundaries between them. Every unit refers to this
  instead of re-deriving it.
- **The sensitive-data map**: where tokens, secrets, PII, keys, and other tenants'
  data live, since the data-exposure class has no attacker entrypoint and an
  entrypoint-anchored read misses it.
- **The intent invariants**: the operator-seeded `inventory/_invariants.md`, the core
  assets, who may legitimately move each, and the properties that must always hold,
  conservation, single-use, monotonic, ownership, ordering, with the blast radius if
  one breaks. A static read sees the controls but not the business intent behind them,
  so this names the intent a unit checks against. When the operator left it blank, it
  seeds nothing and a unit reviews exactly as before.

---

## Phase 2: Fan Out

*Decompose the surface into units and review each deeply, in parallel.*

### Define the Units

The scaffold has already written the unit worklist into `units/`, one unit per
candidate entrypoint the stack guides flagged, each opening with `- Status: open`
and carrying the same fixed deep-review mandate. You do not invent the units or
decide how deep each goes, that is fixed by the scaffold so per-unit depth does not
vary with your judgment. Your job is to make the worklist complete, then run it.

Supplement the seeded units with the ones glob-based seeding cannot know, copying
the mandate from a seeded unit:

- **Entrypoint modules no guide flagged**: add a unit for each.
- **Non-HTTP sources**: add a unit for each deserializer, queue and topic consumer,
  file parser, webhook, and callback.
- **Sequence units**: add one per multi-step flow whose invariant spans several
  endpoints, for example create then approve then execute, or set then trigger,
  where a per-endpoint look misses an invariant that breaks across the sequence,
  such as a resource mutated after it was approved.

Every entrypoint in `inventory/_surface.md` must be owned by some unit. A unit's
sub-review flips its status to `- Status: reviewed` when it returns with findings or
an evidenced clear, and the gate refuses to call the review complete while any unit
is still open, so the unit list is the coverage ledger.

### Review Each Unit, in Parallel

This step decides recall, so it is mechanical, not discretionary. For every unit in
`units/`, launch one dedicated sub-review, a subagent that owns only that unit. One
subagent per unit, no unit skipped, no two units merged to save calls. Run them in
parallel.

Do not review units yourself in this main context. Your job here is to orchestrate:
enumerate, decompose, spawn one sub-review per unit, and aggregate. Keep this context
lean so it does not dilute. The deep reading happens inside each subagent, never here.
A unit looked at in passing by the orchestrator is the shallow whole-repository pass this
method exists to replace, and it is the single thing that drops recall.

Give each sub-review only its slice plus the shared artifacts: `_stack.md`, the
inventory's auth model, the seeded `inventory/_invariants.md`, `_vulnerabilities.md`,
`_false_positive_traps.md`, and the severity inventory `inventory/_severity.md`.
Each sub-review follows the full mandate below:

1. **Traces** every entrypoint in its unit out of the view into the managers,
   controllers, DAO, and libraries it calls, to the real sink. The flaw usually
   lives below the entrypoint, in a manager or DAO, not in the view.
2. **Hunts** the high-impact classes: broken authorization and IDOR, business-logic
   and state-machine bypass, replay, signature and key-trust flaws, race conditions,
   injection, mass assignment, SSRF, missing authentication.
3. **Verifies** each control on the path, on the code it actually reads, never on the
   presence of a named control. Challenges each one:
   - **Authorization granularity**: does the check scope to the right principal,
     owner vs tenant vs service, or only prove the caller is some valid user?
     Compare the unit's siblings and versions for a dropped or weakened check.
   - **Replay**: does a signed or authenticated privileged request both consume a
     one-time nonce and enforce a freshness window? A signature alone is not enough.
   - **Concurrency**: is a check-then-act serialized by a lock held across the act?
     Read the real mechanism. A `select_for_update` whose result is discarded still
     holds the row lock on a production RDBMS inside a transaction, so judge against
     production semantics, not a SQLite or in-memory test where locking is a no-op.
   - **Trusted-source**: is a value treated as safe only because a caller you treat as
     trusted set it, when that caller is a distinct tenant or service?
4. **Refutes** in place. A candidate is a hypothesis. From a fresh skeptical read,
   name the one controlling fact that would make the code safe, then read that exact
   code and settle it. If it holds, the candidate is refuted. If it is absent or
   bypassable, it is confirmed. If it turns on a runtime fact you cannot read, it is
   blocked with the exact need. Refutation is part of the unit, not a later pass.

Each sub-review returns its findings with, for each: the route, the class, the exact
`file:line` of the controlling fact, the end-to-end exploit, and the refutation it
survived. It returns its cleared controls too, each with the controlling fact that
cleared it, so a wrong clear is visible.

---

## Phase 3: Aggregate

*Pull the unit results together, derive coverage, and report what survived.*

- **Coverage**: count the units with a verdict over the units in the inventory.
  Every unit must come back with findings or an evidenced clear. An un-reviewed unit
  is a known gap, list it, do not report the review clean with units outstanding.
- **Dedup**: merge the findings that several units reached from different entrypoints,
  keeping the highest-impact instance.
- **Severity**: report every real finding, graded by the severity rubric in
  `inventory/_severity.md`, CRITICAL through LOW. A real, evidenced defect is graded
  at its level and surfaced. The only thing dropped is a finding whose controlling
  fact holds when you read the code, which is a refutation on the facts, never a
  discount for low impact. A missing-authentication, enumerable-id, or replay defect
  on a privileged path that looks bounded lands at MEDIUM or higher and is reported,
  not refuted. When unsure between two levels, report at the higher and say why.

Write each candidate finding to `candidates/<name>.md` with a runnable PoC at
`pocs/<name>.<ext>` under the same `<name>`, so finalize can match the PoC to the
confirmed finding it writes into `findings/`:

```markdown
# <title>
- Risk: CRITICAL | HIGH | MEDIUM | LOW
- Type: IDOR | auth bypass | replay | business logic | ...
- Source: `<METHOD> <path>` or the non-HTTP entrypoint
- Status: confirmed | blocked
- Needs: only when blocked, the exact input a follow-up run must supply
## Analysis
(cite exact file:line)
## Attack Path
## Verification
(the refutation it survived, and any PoC output, or the exact blocker)
## Fix
```

A finding needs a concrete controlling fact traced to a `file:line`. A runnable PoC
strengthens it, but when a runtime fact or credential is missing, mark it `blocked`
with the exact `Needs:` rather than dropping it. Only a finding with no traced
evidence at all is a guess, do not report that.

---

## Operator Verification

The review above runs unattended to completion and never pauses to ask the operator anything.
When a finding needs a runtime fact you cannot read, a credential, a deploy-config
value, or live behavior, mark it `blocked` with the exact `Needs:`, grade it on the
conservative assumption, and keep going. Gather every operator need into one list at
the end.

When the operator returns with credentials and answers, re-run over the same
workspace driven by `Status`: act only on `blocked` findings, settle each with the
now-available fact or a PoC, and rewrite the status in place. Never run a PoC against
production, never use real credentials, and never run a destructive action without
the operator's explicit go-ahead. A stateful PoC must run against an environment that
models production locking, not a SQLite or in-memory stand-in, or its result is not
evidence.

---

## Accumulate Across Runs

The persistent workspace carries the settled work across runs, so a re-run extends
coverage instead of restarting. A unit already marked `- Status: reviewed` is not
re-reviewed, the proposals in `candidates/` are not re-derived, and a finding already
verified is not re-litigated. A re-run, including after a usage limit, picks up the
units still open and stops when the gate passes.
