# Repository Review Methodology

Repository Review uses a coded workflow to map the target, split it into focused units, run model
judgments, accumulate candidates, verify survivors, and persist completion state. The model judges
one bounded unit at a time. Code owns orchestration, coverage, retries, storage, and the gate.

## Why Fan Out

A prompt that contains an entire repository spreads attention across too many functions and
weakens deep tracing. The coded runner gives each unit a bounded source slice, its dependency
context, extracted facts, and the relevant vulnerability classes. Units run concurrently when
configured, while the shared engine applies the same review plan and failure rules to every unit.

The workflow has three review phases:

- **Map**: scaffold detects the stack, extracts facts, seeds candidate sources, and writes the
  initial inventory and unit worklist.
- **Fan Out**: run reconciles the worklist to the actual source and fact units, then executes the
  configured role sequence. It uses Finder alone or Finder, Challenger, and Judge over every open
  unit.
- **Aggregate**: the shared accumulator merges repeated identities, stabilizes repeated severity
  votes by their median, verifies candidates, and persists findings and completion state.

The workspace lives at `<workspace>/<project>/`. Its `.cyberjury/workspace.json` marker binds the
resolved target, selected profile, and source fingerprint. The workspace is review state, not a
second source of security knowledge.

## Phase 1: Map the Attack Surface

Scaffold reads the profile detection data and guides, extracts the Slither facts, and writes the
stack notes, vulnerability catalog, playbooks, inventory, and seeded units. Facts extraction failure
fails the scaffold instead of producing an ungrounded review.

The run stage rebuilds the exact worklist from candidate sources, definition relationships, and
extracted fact units. It then writes one row per actual unit to `inventory/_surface.md`. This
worklist is the coverage denominator. Each unit file starts with `Status: open`.

## Phase 2: Fan Out

Run supplies each open unit with its owned source, reachable dependency evidence, Slither facts,
shared authorization context, severity rubric, and selected vulnerability classes. Standard mode
runs a Finder judgment. Adversarial mode runs Finder, Challenger, and Judge roles according to the
validated review plan.

The shared engine schedules units and rounds. Configured concurrency changes timing, not ownership
or completion semantics. Each role returns its required JSON object. A blank, malformed, failed,
or incomplete role response is a failed review step rather than a clean unit.

The runner marks a unit `Status: reviewed` only after its required judgments complete without a
unit failure. A failed unit remains open. When adversarial convergence is required, every unit in
the current worklist remains open until the run converges.

## Phase 3: Aggregate

The candidate union is monotonic. Repeated reports with the same identity merge evidence and
provenance. A confirmed report can upgrade a blocked report. Repeated severity votes use their
median so one extreme grade does not overwrite the other judgments.

Verification may refute a candidate only through readable controlling evidence and the required
independent confirmation. A missing confirmer, verifier failure, malformed verdict, or incomplete
source check keeps the candidate and marks the run incomplete. The run writes the union,
verification records, confirmed findings, timing, usage, and `_run.json`.

## Resume

A later run over the same unchanged target restores `_union.json`, keeps reviewed units settled,
and schedules only units that remain open. A reviewed marker without its union checkpoint is an
error because the prior candidates would be lost. A corrupt checkpoint also fails loudly. Use a
fresh run when the target identity or source fingerprint changes.

## Finalize

Finalize is optional after a coded run because run already writes confirmed findings. It remains
available for candidate Markdown stored in the workspace and for an existing coded union.
Finalize parses and canonicalizes candidates, deduplicates by the repository identity policy,
verifies survivors, reconciles available proofs, and rewrites confirmed reports. Failed or
incomplete verification is recorded as incomplete and does not silently remove a candidate.

Proof execution is code owned and local only. It may use a configured EVM proof backend against a
local test or fresh local deployment. Never use production systems, live credentials, private
keys, or destructive actions without explicit operator approval.

## Gate

Gate is the final deterministic completeness check. It checks the workspace identity, attack
surface, unit ownership and reviewed status, candidate grades, run state, verification state, and
finalize state when finalize ran. An open unit, failed review, incomplete verification, malformed
status record, or incomplete finalize state fails the gate.

## Accumulate Across Runs

The persistent workspace extends a review without discarding settled work. Resume carries the
existing union and reviewed markers forward, then adds evidence and new finding identities from
the remaining units. It never treats missing or corrupt prior state as a clean restart. A review
is complete only when the coded outcome is complete and the gate passes.
