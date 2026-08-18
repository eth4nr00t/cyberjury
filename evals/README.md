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
3. Judge recall and precision together across the benchmark set, not one target. A change
   that lifts recall by flooding false positives is not an improvement.
4. Read the per-issue flips, which findings checks went missed to found or found to missed,
   they carry more signal than the aggregate. `compare` prints them.

Two tiers, kept honest:

- Public benchmarks here are reproducible regression and smoke checks. They carry a
  leakage caveat, the model may have seen the CVE, so they measure "did not regress" more
  than true recall.
- Private, unseen targets are the real recall signal. They never enter this repository.

## Layout

```text
evals/
  __main__.py          module entry point
  cli.py               arguments, command dispatch, and terminal output
  benchmarks/
    contract.py        versioned answer key contract and loading
    cases.py           repository and diff task materialization
    registry.py        public and private project discovery
    validate.py        schema and cross-file validation
    coverage.py        knowledge coverage matrix
    prepare.py         Solidity benchmark target preparation
    schemas/           versioned benchmark and answer-key JSON Schemas
    languages/<language>/<project>/
      benchmark.yaml   shared project manifest with one or more tasks
      answer-key.yaml  findings and clean checks scoped by task
    frameworks/<language>/<framework>/<project>/
      benchmark.yaml   shared project manifest with one or more tasks
      answer-key.yaml  findings and clean checks scoped by task
    protocols/<protocol>/<project>/
      benchmark.yaml   shared project manifest with one or more tasks
      answer-key.yaml  findings and clean checks scoped by task
  review/
    diff.py            execute and score Diff Review benchmarks
    repository.py      load and score Repository Review output
  score/
    report.py          normalized reports and stored finding readers
    result.py          single and repeated score results
    match.py           endpoint and category matching
    location.py        source symbol and line localization
    engine.py          deterministic scoring
  backtest/
    compare.py         result flips and quality deltas
    metrics.py         workspace completeness, cost, and timing
    gate.py            regression acceptance policy
```

Benchmark manifests and answer keys use the versioned contract in
[`benchmark-contract.md`](docs/benchmark-contract.md).
`benchmarks/validate.py` is the contract boundary. It applies the versioned JSON Schemas first, then checks
cross-file identity, task source and scope, check knowledge, answer-check scopes, and clean-task
coverage. The review adapters and score engine consume benchmark data only after discovery and validation.

Public benchmarks live under the taxonomy groups in `benchmarks/`. Private benchmark sources use
the same physical layout from a gitignored `evals/local.yaml`, so the registry can discover them
without copying private targets into this repository.

## Knowledge Coverage

Knowledge is data and the engine is generic, so a vulnerability class or a guide with no
eval is a gap that should be visible, not silent. `python -m evals coverage` scans the
knowledge tree and crosses it against the registry, counting the positive and clean diff
benchmark tasks and the repository findings and clean checks that exercise each file, public and
private:

```bash
python -m evals coverage
```

It names the uncovered files and reports the gate problems: a vulnerability with no
repository target, a benchmark reference that resolves to no real knowledge file, and an
answer key check that names no knowledge. An unresolved reference is broken benchmark data, so the
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

A private source must provide the same manifest and answer-key files as the versioned contract.
Validate a project before using it in a measurement. The review under test never receives the
answer key or source-only ground truth fields.

Keep the physical names `benchmark.yaml` and `answer-key.yaml`. Name the repository task
`repository-<commit prefix>`, where the prefix is seven lowercase commit characters for git
sources or seven lowercase address characters for explorer sources. Name each diff task
`diff-<commit prefix>-<sequence>`, where the prefix is seven lowercase commit characters and the
sequence starts at `1` within the manifest. File scoped
`diff_path` and `diff_paths` fields are rejected because they reveal which changed file matters
instead of reviewing the target commit.

## Run

The repository path does not run the review, it scores the output a run already wrote. To score
the public benchmark set in one sweep rather than one target, see `docs/backtest.md`,
the batch runbook that derives the targets and order from the committed benchmarks.

```bash
# clone and check out the immutable target named by its benchmark.yaml
git clone https://github.com/open-webui/open-webui /tmp/owui
git -C /tmp/owui checkout 9bcd4ce5c0a01af68c0d2aa44554a68bb741c61b

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

# list benchmarks in registry order
python -m evals list

# validate a versioned benchmark contract
python -m evals validate evals/benchmarks/<group>/<project>
```

Repeated runs are how a change is judged honestly, the review is not deterministic. A single
run is one `Result`, `--runs N` folds N runs into a frequency verdict, found by strict
majority, so one lucky or unlucky run does not move the score and the spread is visible. The
repository path stays score-only, aggregate N runs by scoring each and reading the flips.

Without `--mode`, each diff task uses its declared `review.mode`. Passing `--mode standard` or
`--mode adversarial` overrides every selected task for a controlled comparison. There is no
separate benchmark mode.

The `gate` is the policy that blocks a regression in CI. It fails loud on a failed review
step, a findings check caught at baseline now missing, a new false positive on a clean
lookalike, precision below a floor, and unsound benchmark data such as a knowledge reference
that resolves to no file or an unlocatable answer check. An extra unkeyed report alone never
fails the gate, the key cannot say whether it is a real bug.

A benchmark grows by adding more findings and clean checks to a project answer key, or by
adding a new `<group>/<name>/` directory with a shared manifest and task scoped answer key
checks. A diff benchmark grows by adding a diff task to that project manifest and scoping the
answer key checks with `applies_to`. A task outside the web default sets the manifest `profile`, for
example a Solidity benchmark sets `profile: evm` so it scores against the EVM knowledge and prompt.
Keep public benchmarks public and non-proprietary, this repository ships to PyPI and GitHub.
