# Repository Security Review: Agent Methodology

A whole repository web application security audit run by an interactive coding agent such
as Claude Code or Codex. The agent does not review the repository in one pass. It maps the
attack surface, splits it into small units, runs a focused deep review on each unit in
parallel, and aggregates the results.

## Why Fan Out

A single agent reviewing a whole large repository dilutes. Its attention spreads across
the entire surface, every endpoint gets a shallow look, and deep cross-file flaws below
the entrypoint are missed. Decomposing the surface into per-module units with one focused
sub-review each keeps recall at scale. Recall comes from per-unit focus and parallelism,
not from one agent's rounds or from re-running the whole review many times.

So the work is three phases:

- **Map**: build the attack-surface inventory, the authorization model, and the
  sensitive-data map. The inventory is the coverage denominator. You cannot claim coverage
  against what you happened to notice, only against an enumerated list.
- **Fan Out**: decompose the surface into units and run a focused deep sub-review on each,
  in parallel. Each unit gets full attention on a small slice, traces it to its real sink,
  and challenges every control. This is where findings are made.
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

1. Read `_stack.md`, the seeded languages, frameworks, and protocols plus their review
   notes, so you know where this stack's entrypoints and sinks live.
2. Read the relevant classes in `_vulnerabilities.md`, the shipped class definitions with
   vulnerable and secure examples, and `_false_positive_traps.md`, the recurring ways a
   static read misjudges them. Apply both per unit, not from memory.

---

## Phase 1: Map the Attack Surface

*Build the denominator. A unit you never list is a unit you never review.*

Enumerate every attacker-influenced entrypoint into `inventory/`, one row each, grouped by
module. Untrusted input enters at more than HTTP:

- HTTP, GraphQL, gRPC, WebSocket handlers, CLI commands, scheduled jobs, queue and topic
  consumers, webhooks, and third-party callbacks.
- Deserialization points such as pickle, `yaml.load`, or marshal, file and document
  parsers for XML, YAML, CSV, zip, or images, and template rendering of user input.
- File uploads, archive extraction, and every filesystem path built from user input.
- Inbound inter-service calls, headers, cookies, and config read as trusted.

Use the seeded entrypoint candidates as a starting subset, not the whole surface. Open the
route modules and read the actual registrations. For each entrypoint record the module,
route, authentication method, and review status.

Then record two cross-cutting artifacts in `inventory/_auth_model.md`:

- **The authorization model**: how this codebase enforces access control through a
  decorator, middleware, permission class, signature, or guard, the actors, tenants, and
  services, and the trust boundaries between them. Every unit refers to this instead of
  re-deriving it.
- **The sensitive-data map**: where tokens, secrets, PII, keys, and other tenants' data
  live. The data-exposure class has no attacker entrypoint, so an entrypoint-anchored read
  misses it.

---

## Phase 2: Fan Out

*Decompose the surface into units and review each deeply, in parallel.*

### Define the Units

The scaffold has already written the seeded unit worklist into `units/`, based on candidate
entrypoint sources. A large source may be split into slices, and facts or import-closure
analysis may add derived units. Each unit opens with `- Status: open` and carries the same
fixed deep-review mandate. Do not change seeded boundaries or depth. Check coverage, then
complete the worklist.

Add only uncovered units that glob-based seeding cannot know, copying the mandate from a
seeded unit:

- **Entrypoint modules no guide flagged**: add a unit for each.
- **Non-HTTP sources**: add a unit for each deserializer, queue and topic consumer, file
  parser, webhook, and callback.
- **Sequence units**: add one per multi-step flow whose invariant spans several endpoints,
  for example create then approve then execute, or set then trigger, where a per-endpoint
  look misses an invariant that breaks across the sequence.

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
authorization model, `_vulnerabilities.md`, `_false_positive_traps.md`, and
`inventory/_severity.md`. Each sub-review follows the full mandate below:

1. **Traces** every entrypoint in its unit out of the view into managers, controllers,
   DAOs, and libraries it calls, to the real sink. The flaw usually lives below the
   entrypoint, in a manager or DAO, not in the view.
2. **Hunts** broken authorization and IDOR, business-logic and state-machine bypass,
   replay, signature and key-trust flaws, race conditions, injection, mass assignment,
   SSRF, and missing authentication.
3. **Verifies** each control on the path, on the code it actually reads, never on the
   presence of a named control. Challenge each one:
   - **Authorization granularity**: does the check scope to the right principal, owner,
     tenant, or service, or only prove the caller is some valid user? Compare sibling
     endpoints, versions, branches, and object types for dropped or weakened checks.
   - **Disclosure and value exposure**: does a list or `ReadAll` return a secret field,
     hash, token, password, or key to a caller with less privilege? A hidden field or
     cross-tenant record is safe only when the code actually excludes it.
   - **Replay and signatures**: does a signed or authenticated privileged request both
     consume a one-time nonce and enforce a freshness window? A signature alone is not
     enough.
   - **State and concurrency**: is a check-then-act serialized by a lock held across the
     act? Read the real mechanism. A `select_for_update` whose result is discarded still
     holds the row lock on a production RDBMS inside a transaction, so judge production
     semantics, not a SQLite or in-memory test where locking is a no-op.
   - **Input and value sources**: does attacker input reach the sink through a request,
     session, cookie, service, or tenant boundary? A server-derived value is trusted only
     when the code proves where it was set.
   - **State and accounting**: does the path update the right record, tenant, or resource
     on every branch? A bounded or idempotent state change is still a finding when an
     attacker can trigger it without the required authorization.
   - **Failure mode**: when a control errors, times out, or falls back, does the path fail
     closed or fail open? Read error and fallback branches, not only the success path.
   - **Trusted source**: is a value treated as safe only because a caller you treat as
     trusted set it, when that caller is a distinct tenant or service?
4. **Refutes** in place. A candidate is a hypothesis. Name the one controlling fact that
   would make the code safe, then read that exact code and settle it. If it holds, refute
   the candidate. If it is absent or bypassable, confirm it. If it turns on a runtime fact
   you cannot read, block it with the exact need. Refutation is part of the unit, not a
   later pass.

Each sub-review returns its findings with the route, class, exact `file:line` of the
controlling fact, the end-to-end exploit, and the refutation it survived. It returns
cleared controls too, each with the controlling fact that cleared it, so a wrong clear is
visible.

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

Write each candidate finding to `candidates/<name>.md` with a runnable PoC at
`pocs/<name>.<ext>` under the same `<name>`, so finalize can match the proof to the
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
(the refutation it survived, and any proof output, or the exact blocker)
## Fix
```

A finding needs a concrete controlling fact traced to a `file:line`. A runnable proof
strengthens it. When a runtime fact or credential is missing, mark it `blocked` with the
exact `Needs:` rather than dropping it. Only a finding with no traced evidence at all is a
guess, so do not report it.

---

## Operator Verification

The review above runs unattended to completion and never pauses to ask the operator
anything. When a finding needs a runtime fact, credential, deploy configuration value, or
live behavior, mark it `blocked` with the exact `Needs:`, grade it on the conservative
assumption, and keep going. Gather every operator need into one list at the end.

When the operator returns with credentials and answers, re-run over the same workspace
driven by `Status`. Act only on `blocked` findings, settle each with the now-available fact
or a proof, and rewrite the status in place. Never run a proof against production, never
use real credentials, and never run a destructive action without the operator's explicit
approval. A stateful proof must run against an environment that models production locking,
not a SQLite or in-memory stand-in.

---

## Accumulate Across Runs

The persistent workspace carries settled work across runs, so a re-run extends coverage
instead of restarting. A unit already marked `- Status: reviewed` is not re-reviewed, the
proposals in `candidates/` are not re-derived, and a finding already verified is not
re-litigated. A re-run, including after a usage limit, picks up the units still open and
stops when the gate passes.
