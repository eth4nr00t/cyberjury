# Detection Quality Backtest

A self-contained runbook for scoring whole-repository recall across the committed public suite. A
fresh session reads this file and drives the whole batch, no extra explanation. It reproduces
on any machine from the repository alone, no private data, since every target and its answer key are
committed under `evals/benchmarks/`.

Read this together with the `Run` section of `README.md`, which scores one target and states
the two product paths. This file is the batch layer over that, the order, the resume, and the
failure rules.

## What This Measures

Whole repository recall of the Repository Review methodology over real third-party code at real vulnerable
versions. The denominator is the planted issues in each `answer-key.yaml`, so the score is
"did the methodology surface the real bug buried in a real surface", not a synthetic probe.

## Prerequisites

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
```

Set `CYBERJURY_BACKTEST_DIR` to a root outside the repository tree. Clones, workspaces, and scores all
live under it, so nothing large lands in the repository and there is no gitignore to maintain. There
is no default. If it is unset, stop and ask the operator for one before starting, do not fall
back to a temporary path. The batch spans several sessions and resumes from the scores under
this root, so a directory wiped on reboot such as `/tmp` loses the progress and forces a rerun.
Pick a persistent location, a data volume or a home subdirectory.

## Targets and Order

Do not hardcode a target list, derive it from the registry:

```bash
python -m evals list
```

The targets are every repository benchmark the registry exposes. The shipped source is a project
task under the `benchmarks/` taxonomy groups. For each target, read its pointer from the manifest,
a git `target.url` with `ref` and `path` or an explorer `target.chain` and `address`, the review
scope, and read the answer key for the task's `planted` count and categories.

Order by information value over token cost, the same rule each run so the order is reproducible
from the data:

1. Density first. A review that scores several planted findings pays back more per run, so
   multi-planted targets lead.
2. Unique class next. Count each vulnerability category once, run one representative before a
   second target of a class already covered.
3. Cost last. The engine walks files under the scope only, so a narrow scope is cheap and a
   large scope with one buried needle is the expensive deep-recall test, run it after the cheap
   breadth targets. A duplicate class on a large scope sits at the very end.

## Run Each Target

Working top-down through that order:

1. Skip if `<root>/results/<name>.json` exists, it is already scored.
2. Clone at the pinned ref into `<root>/repositories/<name>`, reuse an existing clone. Fetch the
   exact `ref` at depth 1, fall back to a filtered full clone plus checkout for a server that
   will not serve a bare sha.
3. Review the scope with the coded engine. Scaffold with
   `cyberjury review repository <root>/repositories/<name>/<path> --scaffold --workspace <root>/workspaces/<name>`,
   then run with `cyberjury review repository <same dir> --workspace <same workspace> --run`.
4. Score the run output with
   `python -m evals repository <name> --workspace <root>/workspaces/<name> --json <root>/results/<name>.json`.
5. Report the recall for the target, `X/Y` found, then move to the next.

The coded run path verifies and writes `findings.json`. Use `--finalize` only for a workspace
whose candidates were produced separately, then score that finalized output.

## Rules

These are the failure and resume rules, they carry the honesty of the score, see invariant 4.

- Never wipe a workspace. Resume rides on it, the reviewed units and verified findings live
  there. A scaffold over an existing workspace warns and continues.
- Missing `findings.json`, a nonzero review command, or `_run.json` with incomplete state means
  the coded review did not finish. It is a failure left for retry, never scored, never written as
  a clean zero. Require `_finalize.json` only when the standalone finalize path was used. An empty
  `findings.json` from a complete run is a real `0/Y` recall result and must be scored.
- A provider limit stops the whole batch. Write no result for the blocked target, report the
  limit and the reset time, and re-invoke after the budget resets. Finished targets skip,
  half-finished ones resume.
- Run a few targets concurrently up to a small cap, for example five, so a limit leaves at most a
  handful of resumable workspaces and no data is lost.

## Comparing Two Configurations

The batch above scores one configuration. Judging a change means scoring two, a baseline arm and a
changed arm, and the comparison is only worth as much as its discipline.

**Both arms must be identical except the change.** Same target and pinned ref, same review scope,
same `--mode`, same `--rounds`, same concurrency, same verification behavior, same model. A half-finished
arm is not resumed and compared: `--run` resumes from the workspace, so a resumed arm has run a
different number of passes than its baseline. Delete that workspace and run it again.

**Pick targets that can show a gain.** A target whose baseline already scores every planted issue
can only show a regression, never an improvement, so a suite of those measures nothing about
whether a change helps. Include targets whose planted `file` is not an entrypoint file, where the
issue sits below the entrypoint in a service, dao, util, or lib. Read the `file` in each
`answer-key.yaml` against the scope's entrypoints before choosing.

**Size the arms before starting.** Model calls per arm are roughly `units x role calls x rounds`,
so scaffold first and read the unit count from the workspace. Scaffolding costs no model call. A
scope that slices into hundreds of units is not a two-arm target.

## What To Record

Do not transcribe these by hand. Every number below is already written by the run, so one command
reads both arms and prints the record:

```bash
python -m evals compare <root>/results/<name>-A.json <root>/results/<name>-B.json \
    --before-workspace <root>/workspaces/<name>-A --after-workspace <root>/workspaces/<name>-B
```

It prints the quality flips, then each arm's cost with the ratios between them, then whether the
pair is comparable at all. It exits 1 when either arm did not run clean, so a disqualified pair
fails rather than being read as a result. Hand-copying invites a wrong number that reads exactly
like a measured one.

Every arm records all three groups. Quality alone cannot judge a change, since a change that holds
recall while multiplying cost is a different decision than one that holds both.

Quality, from `python -m evals repository`:

- `recall`, and `found` and `missed` by planted id, so a changed arm names which issue moved.
- `n_reports` and `precision_known`, so noise is visible next to recall.

Completeness, from `_run.json` and `_finalize.json`:

- `run_incomplete`, a coded run that stopped before it completed, including an adversarial run
  that was still adding findings when its round cap stopped it.
- `errors`, the failed unit reviews, and `verify_errors`.
- `incomplete` and `unlocatable`, the findings kept because verification could not finish. Both are
  counted inside `confirmed`, so a non-zero value marks findings already in that total rather than
  additional ones.

**A non-zero value in this group disqualifies the arm from comparison.** A run whose reviews or
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
the ceiling on spend is a usage-layer choice such as `--rounds` while recall is a red line. What is
not allowed is leaving cost unmeasured: `usage` is written to the workspace precisely so a
comparison does not depend on whoever captured stderr at the time.

## How To Judge A Change

Read the arms against these in order. The first that applies decides.

1. **Recall down on any target, reject.** No cost saving outweighs a missed real issue, invariant 2.
2. **Recall equal and cost up, the change does not earn the default.** Ship it behind a flag that
   is off, or not at all, unless some other target in the suite shows recall up.
3. **Recall up and cost up, accept.** Report the cost so the operator can trade it away with
   `--rounds` or a narrower scope.
4. **Recall up and cost flat or down, accept.**

Report `n_reports` alongside. Rising reports at equal recall is a precision risk rather than a
gain, and precision is judged after verification, not on the raw union.

## When To Repeat A Run

A single run per arm is the default. Generation is probabilistic, so repeat the pair when the
decision rests on a margin thin enough to be noise:

- The whole conclusion rests on one target, or on a difference of one or two findings.
- An arm is about to be rejected or made the default on a result that is close.
- A target's two arms disagree with the rest of the suite.

Repetition is not needed when the result is unambiguous, such as recall down on several targets or
a clear gain repeated across them. When a pair is repeated, report each run rather than an average,
so the spread is visible instead of smoothed away.

## Expectation

A provider budget may not finish the suite in one window. The batch can span several sessions
across days. Re-invoke this runbook after each budget reset, the scored targets skip and the run
picks up where it stopped.

## Output

- Scores, `<root>/results/<name>.json`, the input to `python -m evals compare` and `gate`.
- Intermediates, `<root>/workspaces/<name>/<leaf>/`, the findings, candidates, and inventory.
