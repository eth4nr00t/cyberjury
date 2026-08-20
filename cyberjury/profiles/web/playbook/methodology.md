# Repository Review Methodology

This document describes the coded repository review lifecycle. The CLI owns target resolution,
facts extraction, unit planning, model calls, accumulation, verification, persistence, and
completion. Models judge bounded units and return structured results. They do not write workspace
files, change unit status, or decide that failed work is clean.

## Why Fan Out

Repository review divides the attack surface into bounded units so each model judgment can trace a
small source region and its grounded dependencies. The coded scheduler fans units out with bounded
concurrency, records every success and failure, and accumulates findings monotonically. A unit call
never owns the coverage ledger or another unit's result.

The lifecycle has three review phases:

- **Map**: scaffold resolves the target and profile, extracts facts, and creates the coverage
  worklist.
- **Fan Out**: run sends each open unit through the selected review roles and preserves every
  successful candidate.
- **Aggregate**: run and finalize normalize, deduplicate, verify, and persist findings. Gate checks
  whether the recorded work is complete.

## Operator Lifecycle

Use one workspace root for every command. Each command resolves the project directory beneath that
root and checks `.cyberjury/workspace.json` before reusing prior state.

```bash
cyberjury review repository <target> --scaffold --workspace <workspace>
cyberjury review repository <target> --run --workspace <workspace>
cyberjury review repository <target> --finalize --workspace <workspace>
cyberjury review repository <target> --gate --workspace <workspace>
```

A changed target identity, profile, or source fingerprint requires `--fresh`. Do not copy reviewed
markers or findings into a workspace for different source.

## Phase 1: Map the Attack Surface

Scaffold performs deterministic preparation:

- resolves the selected profile and effective source tree
- extracts profile facts and fails if required grounding cannot run
- detects stack guides and writes `_stack.md`
- writes the source inventory and authorization model template
- builds bounded unit files with `Status: open`
- writes the selected vulnerability catalog, false positive traps, severity rubric, and this
  operator document

The seeded inventory is the coverage denominator for the coded run. Operators may inspect it, but
model reviewers do not add units or edit ownership. Generic unit planning and profile facts decide
the worklist.

## Phase 2: Fan Out

Run loads every open unit and sends its source, grounded facts, selected knowledge, severity rubric,
and shared repository context to the configured review roles. The surrounding prompt requires a
single JSON response. Code validates that response and owns all effects after the call.

For each unit, the engine:

- runs the selected standard or adversarial role schedule
- records model failures as failed review steps
- accumulates findings without deleting earlier candidates on an assumption
- checkpoints the finding union after each pass
- marks the unit `Status: reviewed` only after its required judgments complete
- leaves failed or unconverged units open

A blank, malformed, rate limited, or failed call does not become an empty finding list. Re-run the
same command to resume open work after the provider or usage limit recovers.

## Phase 3: Aggregate

Run canonicalizes categories, deduplicates candidates, applies configured verification, and writes
the current findings and run status. Finalize applies the same deterministic postprocessing to the
workspace candidate or union state. It is safe to resume because settled verification is
checkpointed.

Verification may refute a candidate only with a controlling fact it can read. A failed verifier
preserves the candidate and records incomplete verification. Confirmed findings retain their source
location, exploit path, severity, and surviving evidence.

## Proof of Concept Evidence

A proof of concept is optional evidence, not a completion requirement. The engine records and
reconciles files already present under `pocs/`, but a missing proof does not delete a traced finding.
Only run a proof in an approved sandbox or development environment. Runtime credentials, test data,
and any stateful action require operator approval.

When proof cannot run safely, keep the finding and record the exact runtime fact needed. Never use
production systems, real credentials, or destructive actions without explicit approval.

## Completeness Gate

Gate reads the workspace bookkeeping. It does not perform review judgment. It fails when a unit is
still open, coverage is incomplete, a candidate lacks a calibrated risk, or required run state is
missing. A failed gate is an incomplete review, not a clean result.

Report completion only after the gate passes. Findings remain valid even when the gate also reports
unreviewed work elsewhere.

## Accumulate Across Runs

The workspace carries settled work across runs. Reviewed units are skipped only when their union
checkpoint is present and the workspace identity still matches. Open or failed units run again.
Verified findings are reused, while new candidates extend the existing union.

Use `--fresh` only when intentionally starting over. It clears prior run artifacts after the CLI
confirms the workspace belongs to the resolved target.
