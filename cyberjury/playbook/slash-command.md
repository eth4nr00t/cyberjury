---
description: Run a Cyberjury security review of a diff or a whole repository
argument-hint: <target> [--coded] [--domain auto|web|evm] [--mode standard|adversarial] [--rounds <n>] [--concurrency <n>] [--workspace <path>]
---
# Security Review

Run a Cyberjury security review of: $ARGUMENTS

## Parse the Request First

`$ARGUMENTS` holds a target plus optional flags. Settle them before running anything.

- Take the first non-flag token as the target: a unified diff file such as a `.diff` or `.patch`, a
  git range such as `origin/main...HEAD`, or a repository directory.
- Read `--coded` as one switch that decides the engine and the model backend together:
  - absent, the default: model calls run on your Claude Code subscription with
    `--executor subscription`, so **your `.env` provider config is not used**. A repository is
    reviewed by the agent fan-out you orchestrate.
  - present: every Cyberjury model call runs with `--executor api`, so **your `.env` provider
    config is used**. A repository is reviewed by Cyberjury's own coded engine with `--run`.
- Let `EXEC` be `api` when `--coded` is present, else `subscription`.
- Pass these flags through to Cyberjury, each routed to the step that reads it. `--coded` is for
  you, never pass it to Cyberjury, and never pass `--executor`, `--coded` already sets it:
  - `--domain auto|web|evm`, the review domain, `auto` detects from the target. Pass it to every
    step so they agree. Omit to let Cyberjury detect.
  - `--mode standard|adversarial`, the review mode, append to diff review and repository `--run`.
  - `--rounds <n>`, adversarial rounds, append to diff review and repository `--run`.
  - `--concurrency <n>`, diff verification or repository fan-out parallelism, append to diff
    review, repository `--run`, and repository `--finalize`.
  - `--workspace <path>`, the review workspace, append to every step so they share one.
- Announce the choice on the first line before running anything, so it is never a guess:
  `Engine: agent fan-out | model: Claude Code subscription | .env: not used`, or
  `Engine: coded --run | model: api | .env: used`.

Then pick the path by the target. Diff and whole-repository are different tools, do not mix them.

- **Diff Review** when the target is a diff file or a git range. Fully coded, you run one command
  and relay its report, there is no fan-out and no workspace.
- **Repository Review** when the target is a directory. `--coded` chooses the coded engine, its
  absence chooses the fan-out you orchestrate.

If `cyberjury` is not on PATH it is a pip-installed console script, so activate the project venv
first, for example `. .venv/bin/activate`, or run `python -m cyberjury`.

## Diff Review

Run the coded engine and relay its report. There is nothing for you to judge, the engine chunks
the diff, runs its passes, filters, and prints the findings.

```bash
cyberjury review diff --file <the diff file> --executor $EXEC
```

For a git range instead of a file, use `--git-range <range>` in place of `--file`, adding
`--repository <path>` if the range lives in another repository. A failed, rate-limited, blank, or
error-exited run is a failed review, not a clean pass, surface the error and never report zero
findings from a broken run. A non-zero exit means the audit degraded or the command failed, say
which. Then stop, diff review does not use the units, the workspace, or the gate below.

## Repository Review

The skeleton is the same either way: scaffold, find, finalize, gate. The `--coded` switch changes
only the find step. Scaffold, finalize, and gate are always the coded commands below. Thread the
parsed `--domain` and `--workspace` through every step, `--mode` plus `--rounds` through run, and
`--concurrency` through run and finalize.

### Scaffold, Always First

Build the workspace, the deterministic worklist you do not invent:

```bash
cyberjury review repository <target> --scaffold
```

The workspace defaults to a user-private directory under `XDG_STATE_HOME` or `~/.local/state`,
the same path for every step, so they share one workspace.

If it reports a previous review's output, ask me whether to clear it, and if I say yes, re-run with
`--fresh`.

**Resuming**. If a previous run was interrupted, re-run without clearing, answer no when it asks to
clear. It resumes: a unit already `- Status: reviewed` is skipped, and `--finalize` does not
re-verify a settled finding. Keep resuming in new sessions until the gate passes.

### Find, Coded Path, When `--coded` Is Set

You are a command runner here, not the reviewer. The coded engine finds through your `.env`,
deterministic and resumable. Run it, then go to Finalize. In adversarial mode it runs
role rounds until convergence or the round cap:

```bash
cyberjury review repository <target> --run --executor api
```

A failed, rate-limited, or error-exited run is a failed step, not zero findings. Re-run to resume.

### Find, Fan-Out Path, the Default When `--coded` Is Absent

You are the orchestrator, not the reviewer. Recall comes from fanning out: the tool gives you a
deterministic unit worklist, you run one focused sub-review per unit in parallel, union their
findings across diverse passes, verify, and stop on a gate. The deep reading happens inside each
sub-review, never in this main context.

1. **Map**. Make the worklist complete. Enumerate every attacker-influenced entrypoint into
   `inventory/_surface.md`, and fill `inventory/_auth_model.md` with the access model and trust
   boundaries. For anything the seeded units miss, add a unit file by copying the mandate from a
   seeded one. Cover non-HTTP sources such as deserializers, queues, and file parsers. Every
   entrypoint in the surface must be owned by some unit.

2. **Fan Out**. This step is mechanical, not a matter of judgment. For every unit in `units/` with
   `- Status: open`, launch one sub-review per unit as a separate subagent or task, in parallel.
   One per unit, no unit skipped, no two merged to save calls. Give each only its unit file, which
   carries the mandate and the files to own, plus the shared `_stack.md`,
   `inventory/_auth_model.md`, `inventory/_severity.md`, and `_vulnerabilities.md`. Each sub-review
   reads its files, traces into what they call, hunts the high-impact classes, verifies each control
   on the code it reads, refutes its own candidates, grades every real finding by the rubric
   CRITICAL through LOW, writes each to
   `candidates/<name>.md` with its PoC at `pocs/<name>.<ext>`, and flips its unit to reviewed.

   Do not review units in this main context, only orchestrate. After the first pass, run more
   role rounds over the same units, adding only findings not already in `candidates/`. Stop when
   two consecutive passes add no new issue.

### Finalize, Always

In code, do not dedup or verify in prose. Once the find step has covered the surface, run finalize
on the same `EXEC` you announced:

```bash
cyberjury review repository <target> --finalize --executor $EXEC
```

It dedups by location and class, adversarially verifies each survivor, drops the refuted into
`_refuted.md`, and writes the ranked `findings.json`. Re-run to resume, settled findings are
skipped. On `--executor api` the challenger seat reads your `.env`, so a distinct effective seat
can give cross-model verification. A finding is dropped only when the skeptic refutes it and every
independent confirmer upholds that refutation. With no distinct effective confirmer, verification
drops nothing, the recall-safe default.

### Gate, Always

Let Cyberjury, not your judgment, decide whether the review may stop:

```bash
cyberjury review repository <target> --gate
```

If it exits non-zero it lists what is unmet: the surface not enumerated, a unit not reviewed, or a
finding with no calibrated severity. Address each, then re-check. Only report complete once it
passes. It is a floor, not proof of recall, so keep accumulating diverse passes.

## PoC and the Operator

Write a runnable PoC per finding, suited to the stack, a request by id or a replayed signed request
for a web target, a Foundry proof for a contract. Run a PoC only when it needs no input from me, and
never against production, a live deployment, or mainnet. A stateful PoC must run against an
environment that models production, not a stand-in with no locking. When only a runtime fact I hold
can settle a finding, mark it `blocked` with the exact `Needs:` and grade it on the conservative
assumption. Gather every such need into one list for a follow-up run I start later, do not pause to
ask me mid-run.

End with one report and then stop: confirmed findings as a table of title, class, `file:line`,
severity, and status, the blocked findings each with its `Needs:`, the consolidated
verification-needs list, and the coverage, units reviewed over units in the inventory. Do not ask me
to continue, just finish and report.
