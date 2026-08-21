# Detection Quality Backtest

Use this runbook to score repository review recall across the committed public benchmark set.
It defines the target order, resume behavior, and failure rules required to run the batch from
the repository without private data. Every target and answer key is committed under
`evals/benchmarks/`.

Read this with [Run](../evals/README.md#run), which explains how to score one target and
distinguishes the two review paths. This runbook extends that procedure to the full batch.

## What This Measures

This backtest measures Repository Review recall over real third-party code at vulnerable
versions. The denominator is the findings checks in each `answer-key.yaml`. The score records
whether the methodology surfaced each real issue in its source context. It is not a synthetic
probe.

## Prerequisites

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
```

Set `CYBERJURY_BACKTEST_DIR` to a root outside the repository tree. Clones, workspaces, and scores
all live under it, so nothing large lands in the repository and there is no gitignore to maintain.
There is no default. If it is unset, stop and ask the operator for one before starting. Do not
fall back to a temporary path. The batch spans several sessions and resumes from the scores under
this root, so a directory wiped on reboot such as `/tmp` loses the progress and forces a rerun.
Pick a persistent location, a data volume or a home subdirectory.

Create the working directories once before preparing any target:

```bash
mkdir -p "$CYBERJURY_BACKTEST_DIR"/{repositories,workspaces,results}
```

## Targets and Order

Do not hardcode a target list. Derive it from the registry:

```bash
python -m evals list
```

The targets are every repository benchmark the registry exposes. The shipped source is a project
task under the `benchmarks/` taxonomy groups. For each target, read its pointer from the manifest,
a git `source.identity.url` with `source.identity.commit` or a local
`source.identity.repository_path`, the source `path`, and the answer key for the task's findings
check count and categories.

Order targets with this stable key:

1. Sort by findings check count in descending order.
2. Break a tie by distinct canonical vulnerability count in descending order.
3. Break the remaining tie by benchmark name in ascending order.

This order puts dense and broad targets first without depending on source layout or answer key
locations. Record the resulting target names with the run so a later session uses the same order.

## Run Each Target

Working top-down through that order:

1. Skip the target if `<root>/results/<name>.json` exists. It is already scored.
2. Prepare the source at the pinned commit under `<root>/repositories/<name>`. For a Solidity
   target, run `python -m evals prepare --only <name>`. The command clones or fetches the source,
   installs the declared build inputs, compiles it, and verifies that Slither can ground the
   review. For a non-Solidity git target, reuse or create the clone, fetch the exact commit at
   depth 1, and check out `FETCH_HEAD` in detached mode. Fall back to a filtered full clone plus
   checkout when a server will not serve a bare commit.
3. Review the scope with the coded engine. Scaffold with
   `cyberjury review repository <root>/repositories/<name>/<path> --scaffold --workspace <root>/workspaces/<name>`,
   then run with `cyberjury review repository <same dir> --workspace <same workspace> --run`.
4. Score the run output with
   `python -m evals repository <name> --workspace <root>/workspaces/<name> --json <root>/results/<name>.json`.
5. Report the target recall as `X/Y` found, then move to the next target.

The coded run path verifies and writes `findings.json`. Use `--finalize` only for a workspace
whose candidates were produced separately, then score that finalized output.

## Repository Batch Resume Rules

These rules apply only to the single configuration repository batch. They preserve the integrity
of the score under invariant 4 while allowing unfinished targets to resume across sessions.

- A workspace is never wiped. Its reviewed units and verified findings preserve the resume state.
  Scaffolding over an existing workspace warns and continues.
- Missing `findings.json`, a nonzero review command, or `_run.json` with incomplete state means
  the coded review did not finish. The target remains for retry and is never scored or written as
  a clean zero. The `_finalize.json` file is required only when the standalone finalize path was
  used. An empty `findings.json` from a complete run is a real `0/Y` recall result and must be
  scored.
- A provider limit stops the batch. No result is written for the blocked target. The limit and
  reset time are reported, then the batch runs again after the budget resets. Finished targets
  are skipped and unfinished targets resume.
- Concurrency remains at a small cap, for example five targets. A provider limit then leaves at
  most a handful of resumable workspaces and no data is lost.

## Comparing Two Configurations

The batch above scores one configuration. Judging a change requires two arms, one baseline and
one changed configuration. The comparison is valid only when the arms follow the same procedure.

**Both arms must be identical except the change.** Same target and pinned ref, same review scope,
same `--mode`, same `--rounds`, same concurrency, same verification behavior, same model. A
half-finished arm must not be resumed and compared. The `--run` command resumes from the workspace,
so a resumed arm has run a different number of passes than its baseline. Keep that workspace for
diagnostics, start the arm again in a new clean workspace, and compare only the fresh run.

**Choose targets without reading answer key locations.** Derive relevance from the change
hypothesis and the manifest's profile, stack, and knowledge only. A target used to derive the
change can sanity check it, but cannot prove it. Include at least one relevant real target that
did not inform the change. Read the answer key only after target selection, when scoring requires
it. A target whose baseline already scores every findings check can still expose a regression,
but it cannot demonstrate a recall gain.

**Size the arms before starting.** Model calls per arm are roughly `units x role calls x rounds`,
so scaffold first and read the unit count from the workspace. Scaffolding costs no model call. A
scope that slices into hundreds of units is not a two-arm target.

## What to Record

Do not transcribe these by hand. The result and workspace artifacts contain the source data, so
one command reads both arms, derives completeness, and prints the record:

```bash
python -m evals compare <root>/results/<name>-A.json <root>/results/<name>-B.json \
    --before-workspace <root>/workspaces/<name>-A --after-workspace <root>/workspaces/<name>-B
```

It prints the quality flips, each arm's cost, and the ratios between them. It also checks whether
the workspace records show that both arms completed cleanly. It exits 1 when either arm did not
run clean, so a disqualified pair fails rather than being read as a result. The command does not
verify that the result files and workspaces belong together or that the target, model, mode,
rounds, concurrency, and verification behavior match. Confirm those controls before accepting
the comparison. Manual transcription can produce an incorrect value that still appears measured.

Every arm records all three groups. Quality alone cannot judge a change. A change that preserves
recall while multiplying cost requires a different decision from one that preserves both.

Quality, from `python -m evals repository`:

- `recall`, plus the findings check ids in `found` and `missed`, which identify each issue that
  moved.
- `n_reports` and `precision_known`, which show noise next to recall.

Completeness, from `_run.json` and `_finalize.json`:

- `run_incomplete`, derived by `compare` from `complete: false` in `_run.json`. It covers a coded
  run that stopped before completion, including an adversarial run that was still adding findings
  when its round cap stopped it.
- `errors`, the failed unit reviews, and `verify_errors`.
- `incomplete` and `unlocatable`, the findings kept because verification could not finish. Both are
  tracked separately from `confirmed`, so either nonzero value marks findings outside that total
  and disqualifies the arm.

**A nonzero value in this group disqualifies the arm from comparison.** A run whose reviews or
verifications failed did not fully run, so its score is not evidence about the change, invariant 4.
Re-run it rather than reading it as a result.

Cost, from `_run.json` and `_finalize.json`:

- Under `usage` in both records: `model_requests`, `total_input_tokens`, `uncached_input_tokens`,
  `cache_read_tokens`, `cache_write_tokens`, and `output_tokens`.
- Under `usage` in `_run.json` only: `unit_review_calls`, the denominator for spend per review.
  Finalize verifies findings rather than reviewing units, so it records no such count.
- Beside `usage` rather than inside it: `timing.total_seconds`.

Read `total_input_tokens` first. The uncached count alone understates the prompt, so comparing two
arms on it reads a cache hit as a saving the request never made.

There is no cost threshold that rejects a change on its own. Cost is reported, not gated, because
the ceiling on spend is a usage layer choice such as `--rounds` while recall is a red line. Cost
must still be measured. The workspace records `usage` so the comparison does not depend on
captured stderr.

## How to Judge a Change

Read the arms against these in order. The first that applies decides. Use the per-check flips with
the aggregate metrics so an equal score cannot hide one newly missed issue.

1. **Recall down or any check newly missed, reject.** No cost saving or newly found check outweighs
   a missed real issue, invariant 2.
2. **Recall up with no newly missed check, accept.** Report precision, `n_reports`, and cost so the
   operator can judge the added noise and trade spend away with `--rounds` or a narrower scope.
3. **Recall equal and report noise worse, the change does not earn the default.** A lower
   `precision_known` or higher `n_reports` is a regression after verification, not a gain.
4. **Recall equal and report noise better, accept.** Report cost alongside the precision gain.
5. **Recall and report noise equal with cost down, accept.**
6. **Recall, report noise, and cost equal, the backtest shows no measured gain.** Do not default the
   change on this evidence alone.
7. **Recall and report noise equal with cost up, the change does not earn the default.** Ship it
   behind a flag that is off, or not at all.

## When to Repeat a Run

A single run per arm is the default. Generation is probabilistic, so repeat the pair when the
decision rests on a margin thin enough to be noise:

- The conclusion rests on one target, or on a difference of one or two findings.
- An arm is about to be rejected or made the default on a result that is close.
- A target's two arms disagree with the rest of the benchmark set.

Repetition is not needed when the result is unambiguous, such as recall down on several targets or
a clear gain repeated across them. When a pair is repeated, report each run rather than an average,
so the spread is visible instead of smoothed away.

## Output

- Scores live at `<root>/results/<name>.json`. They are inputs to `python -m evals compare` and
  `python -m evals gate`.
- The operator passes `<root>/workspaces/<name>` as the workspace root. Comparison arms use
  `<name>-A` and `<name>-B` instead.
- The repository evaluator resolves the generated target leaf beneath the workspace root. That
  leaf contains the findings, candidates, and inventory.
