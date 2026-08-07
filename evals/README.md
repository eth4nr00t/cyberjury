# The Detection-Quality Ruler

The gate only checks structural completeness, surface enumerated, units reviewed, findings
graded. Green does not mean the review found real bugs. This is the ruler that does: a
change to the knowledge, prompts, or methodology is judged by recall and precision moving
on real targets, not by the gate.

The engine ships here. The data does not have to. Public OSS benchmarks live in
`benchmarks/`. Private benchmarks stay wherever they already are and plug in through a
local, uncommitted config, so nothing private enters the repository.

## What "Better" Means

A single score cannot tell an improvement from noise, the review is not deterministic. The
standard is a move that holds up under repetition:

1. Control variables. Same target at the same commit, same model, same mode. Vary only the
   code under test.
2. Run several times per version and read the spread, not one number. A change counts only
   when the distributions separate beyond the noise band across runs.
3. Judge recall and precision together across the whole suite, not one target. A change
   that lifts recall by flooding false positives is not an improvement.
4. Read the per-issue flips, which planted issues went missed to found or found to missed,
   they carry more signal than the aggregate. `compare` prints them.

Two tiers, kept honest:

- Public benchmarks here are reproducible regression and smoke checks. They carry a
  leakage caveat, the model may have seen the CVE, so they measure "did not regress" more
  than true recall.
- Private, unseen targets are the real recall signal. They never enter this repository.

## Layout

```text
evals/
  schema.py        answer key, key entry, and the normalized report shape
  results.py       the score of one review, and N runs folded by frequency
  scorers/
    match.py       endpoint and category matching
    parse.py       read findings markdown and json into reports
    score.py       match reports against a key and tally the result
  runners/
    repository.py        score a whole-repository review's findings output
    diff.py        run the diff benchmark tasks and score
  diff_cases.py    load the shipped diff benchmark tasks, engine-free so the matrix can read them
  registry.py      discover benchmarks across public and private sources
  coverage.py      scan the knowledge tree, build the coverage matrix
  suites.py        a named tag selection over diff tasks and benchmarks
  compare.py       diff two results, the per-issue flips, deltas, and by-axis grouping
  gate.py          the regression policy, a yes or no on landing a change
  suites/<name>.yaml             a tag selection, public-smoke and knowledge-coverage
  benchmarks/
    <group>/<name>/benchmark.yaml     a shared project manifest with one or more tasks
    <group>/<name>/answer-key.yaml    planted issues and safe lookalikes scoped by task
```

Project benchmarks are the canonical shape for real targets. They group under the same three
buckets the knowledge guides use, `languages/`, `frameworks/`, and `protocols/`, so the eval tree
mirrors the knowledge taxonomy. A project manifest starts with `schema_version: 1`, has the shared
repo pointer, stack, knowledge, tags, and a `tasks` list. A task has a stable `id` and may add
stack or knowledge entries when one project has several security scenarios. A repository task pins
the vulnerable ref and scope. A diff task pins `base` and `ref` for the real introducing or fixing
commit. The shared answer key scopes entries with `applies_to`, so the repository and diff task can
measure the same project without copying target metadata.

Repository scoring still resolves a benchmark name. When a project has one repository task, the
name is the project id. When it has several repository tasks, the name is
`<project-id>:<task-id>`. Diff scoring discovers every diff task as
`<project-id>:<task-id>` and derives the patch from the pinned git target.

The shipped real target benchmarks live directly under the taxonomy groups. Diff review
evidence comes from real project diff tasks, not standalone patches.

A `benchmark.yaml` is the manifest, a git or explorer pointer, never vendored code, plus the
stack and the knowledge the target exercises, so the coverage matrix can attribute it.

An `answer-key.yaml` starts with `schema_version: 1` and has `planted` issues a complete review
must surface and `safe` lookalikes a report would be a false positive on. Entry anchors use
`files` and `symbols` lists, even when there is one value. Each entry may name the knowledge it
exercises. The review under test never reads the key.

## Knowledge Coverage

Knowledge is data and the engine is generic, so a vulnerability class or a guide with no
eval is a gap that should be visible, not silent. `python -m evals coverage` scans the
knowledge tree and crosses it against the registry, counting the positive and safe diff
benchmark tasks and the repository planted and safe entries that exercise each file, public and
private:

```bash
python -m evals coverage
```

It names the uncovered files and reports the gate problems: a vulnerability with no
whole-repository target, a benchmark reference that resolves to no real knowledge file, and an
answer key entry that names no knowledge. An unresolved reference is broken benchmark data, so the
command exits nonzero on it, while a missing benchmark is a known gap and exits zero.

## Private Benchmarks, Not Committed

Create a local `evals/local.yaml`, gitignored, or point `CYBERJURY_EVAL_CONFIG` at one:

```yaml
benchmark_sources:
  # read in place, nothing is copied or committed
  - path: /abs/path/to/your/private/benchmarks
  - repository: git@github.com:you/private-benchmarks.git
    ref: main
```

A source root uses the root taxonomy layout for real targets. Benchmark names resolve across
the public root and every source.

A private source should provide real targets under
`<group>/<name>/benchmark.yaml` plus `answer-key.yaml`. The manifest may point at a git
`target.path` or `target.url`. Repository tasks add `ref` and `path`. Diff tasks add `base` and
`ref`, so the run derives the patch and facts context from the target checkout. The answer key
states which entries apply to each task through `applies_to`. Use this for private real patch
evidence that cannot ship in the public benchmark library. Diff benchmarks score returned
findings against the answer key anchors, so a different finding in the same patch does not
credit a planted issue.

## Run

The repository path does not run the review, the agent or a coded run does that, this scores the
output it wrote. To score the whole public suite in one sweep rather than one target, see
`BACKTEST.md`, the batch runbook that derives the targets and order from the committed
benchmarks and drives the agent path end to end.

```bash
# clone the target named by its benchmark.yaml
git clone --depth 1 --branch v0.3.8 https://github.com/open-webui/open-webui /tmp/owui

# run the coded engine, the preferred path for regression checks
# --executor auto uses an API key when present, otherwise keyless Anthropic subscription
cyberjury review repository /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui --run --executor auto

# score the produced findings.json
python -m evals repository open-webui --findings-json /tmp/cj-owui/webui/findings.json --json after.json

# compare two result files
python -m evals compare before.json after.json

# group compare output by vulnerability class
python -m evals compare before.json after.json --by vulnerability

# gate a change against a baseline and precision floor
python -m evals gate after.json --baseline before.json --precision-floor 0.8

# repeat the diff suite so findings need a strict majority of runs
python -m evals diff --mode standard --executor subscription --model <id> --runs 3

# run one diff case through the API executor
python -m evals diff --cases /path/to/diff/case --executor api --model <id>

# run a tagged suite
python -m evals run public-smoke --executor subscription --model <id> --runs 3

# list benchmarks and suites in registry order
python -m evals list
```

Repeated runs are how a change is judged honestly, the review is not deterministic. A single
run is one `Result`, `--runs N` folds N runs into a frequency verdict, found by strict
majority, so one lucky or unlucky run does not move the score and the spread is visible. The
repository path stays score-only, aggregate N agent runs by scoring each and reading the flips.

The `gate` is the policy that blocks a regression in CI. It fails loud on a failed review
step, a planted issue caught at baseline now missing, a new false positive on a safe
lookalike, precision below a floor, and unsound benchmark data such as a knowledge reference
that resolves to no file or an unlocatable key entry. An extra unkeyed report alone never
fails the gate, the key cannot say whether it is a real bug.

A benchmark grows by adding more planted issues and lookalikes to a project answer key, or by
adding a new `<group>/<name>/` directory with a shared manifest and task scoped answer key
entries. A diff benchmark grows by adding a diff task to that project manifest and scoping the
answer key entries with `applies_to`. A task outside the web default carries a `domain`, for
example a Solidity task sets `domain: evm` so it scores against the EVM knowledge and prompt. A
suite grows by adding `suites/<name>.yaml` naming the tags it selects, no second list of cases to
keep in sync. Keep public benchmarks public and non-proprietary, this repository ships to PyPI and
GitHub.
