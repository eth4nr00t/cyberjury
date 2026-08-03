# Batch Recall Backtest

A self-contained runbook for scoring whole-repository recall across the committed public suite. A
fresh session reads this file and drives the whole batch, no extra explanation. It reproduces
on any machine from the repository alone, no private data, since every target and its answer key are
committed under `evals/benchmarks/`.

Read this together with the `Run` section of `README.md`, which scores one target and states
the two product paths. This file is the batch layer over that, the order, the resume, and the
failure rules.

## What This Measures

Whole-repository recall of the Repository Review methodology over real third-party code at real vulnerable
versions. The denominator is the planted issues in each `answer-key.yaml`, so the score is
"did the methodology surface the real bug buried in a real surface", not a synthetic probe.

## Prerequisites

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
cyberjury install-slash-command
```

Set `CYBERJURY_BACKTEST_DIR` to a root outside the repository tree. Clones, workspaces, and scores all
live under it, so nothing large lands in the repository and there is no gitignore to maintain. There
is no default. If it is unset, stop and ask the operator for one before starting, do not fall
back to a temporary path. The batch spans several sessions and resumes from the scores under
this root, so a directory wiped on reboot such as `/tmp` loses the progress and forces a rerun.
Pick a persistent location, a data volume or a home subdirectory.

## Targets and Order

Do not hardcode a target list, derive it. The targets are every `benchmark.yaml` under
`benchmarks/repository/`. For each, read its pointer, a git `target.url` with `ref` and `path`
or an explorer `target.chain` and `address`, the review scope, and read the sibling
`answer-key.yaml` for the `planted` count and the categories.

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
3. Review the scope with the `/cyberjury-review` methodology. Scaffold with
   `cyberjury review repository <root>/repositories/<name>/<path> --scaffold --workspace <root>/workspaces/<name>`,
   then follow the workspace `METHODOLOGY.md`, fan out one sub-review per `Status: open` unit
   across diverse passes, write candidates, then
   `cyberjury review repository <same dir> --workspace <same workspace> --finalize --executor auto`.
4. Score. Locate the findings with `find <root>/workspaces/<name> -name findings.json`, then
   `python -m evals repository <name> --findings-json <that path> --json <root>/results/<name>.json`.
5. Report the recall for the target, `X/Y` found, then move to the next.

The coded path is the alternative that writes the same findings.json without an agent, one
`cyberjury review repository <dir> --workspace <ws> --run --executor auto`, prefer it for a scope with
detectable entrypoints. Score whichever path wrote the findings.

## Rules

These are the failure and resume rules, they carry the honesty of the score, see invariant 4.

- Never wipe a workspace and never pass `--fresh`. Resume rides on it, the reviewed units and
  verified findings live there. A scaffold over an existing workspace warns and continues.
- Empty candidates means the review did not run. It is a failure left for retry, never scored,
  never written as a clean zero.
- A subscription session limit stops the whole batch. Write no result for the blocked target,
  report the limit and the reset time, and re-invoke after the budget resets. Finished targets
  skip, half-finished ones resume.
- Run a few targets concurrently up to a small cap, for example five, so a limit leaves at most a
  handful of resumable workspaces and no data is lost.

## Expectation

A subscription budget does not finish the suite in one window. The batch spans several sessions
across days. Re-invoke this runbook after each budget reset, the scored targets skip and the run
picks up where it stopped.

## Output

- Scores, `<root>/results/<name>.json`, the input to `python -m evals compare` and `gate`.
- Intermediates, `<root>/workspaces/<name>/<leaf>/`, the findings, candidates, and inventory.
