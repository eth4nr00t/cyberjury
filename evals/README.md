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
  __main__.py          eval CLI for listing, scoring, comparing, and gates
  prepare.py           target preparation helpers for Solidity benchmark scopes
  schema.py            answer keys, key entries, and normalized report schemas
  results.py           single review scores and repeated run frequency summaries
  scorers/
    match.py           endpoint and category matching
    parse.py           markdown and json findings parsing
    score.py           report to answer key matching and tallying
  runners/
    repository.py      review repository findings scoring
    diff.py            diff benchmark running and scoring
  diff_cases.py        shipped diff task loading for the matrix
  registry.py          benchmark discovery across public and private sources
  coverage.py          knowledge tree scan and coverage matrix generation
  suites.py            named tag selections over diff tasks and benchmarks
  compare.py           result diffs, issue flips, deltas, and axis grouping
  gate.py              regression policy for landing a change
  suites/
    <name>.yaml        tag selections such as public-smoke and knowledge-coverage
  benchmarks/
    <group>/<name>/
      benchmark.yaml   shared project manifest with one or more tasks
      answer-key.yaml  planted issues and safe lookalikes scoped by task
```

Project benchmarks are the canonical shape for real targets. They group under the same three
buckets the knowledge guides use, `languages/`, `frameworks/`, and `protocols/`, so the eval tree
mirrors the knowledge taxonomy. A project manifest starts with `schema_version: 1`, has the shared
repo pointer, stack, knowledge, tags, and a `tasks` list. A task has a stable `id` and may add
stack or knowledge entries when one project has several security scenarios. A repository task pins
the vulnerable ref and scope. A diff task pins `base` and `ref` for the real commit and declares
`expectation: findings` when the patch introduces reportable risk, or `expectation: clean` when
the patch fixes or preserves safety. The shared answer key scopes entries with `applies_to`, so the
repository and diff task can measure the same project without copying target metadata.

Repository scoring still resolves a benchmark name. When a project has one repository task, the
name is the project id. When it has several repository tasks, the name is
`<project-id>:<task-id>`. Diff scoring discovers every diff task as
`<project-id>:<task-id>` and derives the patch from the pinned git target.

The shipped real target benchmarks live directly under the taxonomy groups. Diff review
evidence comes from real project diff tasks, not standalone patches.

A `benchmark.yaml` is the manifest, a git or explorer pointer, never vendored code, plus the
stack and the knowledge the target exercises, so the coverage matrix can attribute it.
Solidity targets may add `target.prepare.npm_pins` for package versions that the pinned
source ref needs but the upstream package range no longer reproduces. The prepare command installs
those pins with `--no-save` and `--no-package-lock`, so it writes only local dependency artifacts
and does not alter the checked out target source.

An `answer-key.yaml` starts with `schema_version: 1` and has `planted` issues a complete review
must surface and `safe` lookalikes a report would be a false positive on. Entry anchors use
`files` and `symbols` lists, even when there is one value. Each entry may name the knowledge it
exercises. For a clean diff task, the loader treats that task's matching planted entries as safe
anchors, so a fix commit is scored as clean while still catching reports that claim the fixed bug
remains. The review under test never reads the key.

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
`target.path` or `target.url`. Repository tasks add `ref` and `path`. Diff tasks add `base`,
`ref` and `expectation`. The run derives the patch from the target checkout and knows whether the
correct outcome is a finding or a clean review. A task may add a `review` block when an experiment
has established a minimum context or mode.

```yaml
tasks:
  - id: diff-introduce-command-injection-cafe123
    kind: diff
    expectation: findings
    review:
      context: repository
      mode: standard
    base: abc123
    ref: cafe123
```

`review.context` records the least context that consistently succeeds when the same case runs with
only the patch and with repository context. Use `diff` when the patch alone consistently contains
the evidence. Use `repository` when the review must trace code outside the patch. `review.mode`
records the least mode that consistently succeeds when the same case runs in standard and
adversarial modes. Use `standard` when that mode is sufficient. Use `adversarial` only when the
finder, challenger, and judge roles are required. Omit `review` until the case has this evidence.
An omitted block runs with the default `repository` context and `standard` mode without claiming
they are proven minima.

The answer key states which entries apply to each task through `applies_to`. It contains expected
findings and safe anchors, never run settings. One finding id may appear more than once when code
moved between commits, but those entries must have disjoint `applies_to` lists. This gives each
task the correct file and symbol anchors without counting one finding twice. Diff benchmarks score
returned findings against these anchors, so a different finding in the same patch does not credit
a planted issue.

Keep the physical names `benchmark.yaml` and `answer-key.yaml`. Name the repository task
`repository-vulnerable`. Name a positive diff task
`diff-introduce-<issue-or-scope>-<short-sha>`. Name a clean diff task
`diff-fix-<issue-or-scope>-<short-sha>`. File scoped `diff_path` and `diff_paths` fields are
rejected because they reveal which changed file matters instead of reviewing the target commit.

## Run

The repository path does not run the review, it scores the output a run already wrote. To score
the whole public suite in one sweep rather than one target, see `docs/detection-quality-backtest.md`,
the batch runbook that derives the targets and order from the committed benchmarks.

```bash
# clone the target named by its benchmark.yaml
git clone --depth 1 --branch v0.3.8 https://github.com/open-webui/open-webui /tmp/owui

# run the coded engine, the preferred path for regression checks
cyberjury review repository /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui --run

# score the produced findings.json
python -m evals repository open-webui --findings-json /tmp/cj-owui/webui/findings.json --json after.json

# compare two result files
python -m evals compare before.json after.json

# group compare output by vulnerability class
python -m evals compare before.json after.json --by vulnerability

# gate a change against a baseline and precision floor
python -m evals gate after.json --baseline before.json --precision-floor 0.8

# override every case to standard mode and require a strict majority of runs
python -m evals diff --mode standard --model <id> --runs 3

# run one diff case
python -m evals diff --cases /path/to/diff/case --model <id>

# run a tagged suite
python -m evals run public-smoke --model <id> --runs 3

# list benchmarks and suites in registry order
python -m evals list
```

Repeated runs are how a change is judged honestly, the review is not deterministic. A single
run is one `Result`, `--runs N` folds N runs into a frequency verdict, found by strict
majority, so one lucky or unlucky run does not move the score and the spread is visible. The
repository path stays score-only, aggregate N runs by scoring each and reading the flips.

Without `--mode`, each diff task uses its declared `review.mode`. Passing `--mode standard` or
`--mode adversarial` overrides every selected task for a controlled comparison. There is no
separate benchmark mode.

The `gate` is the policy that blocks a regression in CI. It fails loud on a failed review
step, a planted issue caught at baseline now missing, a new false positive on a safe
lookalike, precision below a floor, and unsound benchmark data such as a knowledge reference
that resolves to no file or an unlocatable key entry. An extra unkeyed report alone never
fails the gate, the key cannot say whether it is a real bug.

A benchmark grows by adding more planted issues and lookalikes to a project answer key, or by
adding a new `<group>/<name>/` directory with a shared manifest and task scoped answer key
entries. A diff benchmark grows by adding a diff task to that project manifest and scoping the
answer key entries with `applies_to`. A task outside the web default carries a `profile`, for
example a Solidity task sets `profile: evm` so it scores against the EVM knowledge and prompt. A
suite grows by adding `suites/<name>.yaml` naming the tags it selects, no second list of cases to
keep in sync. Keep public benchmarks public and non-proprietary, this repository ships to PyPI and
GitHub.
