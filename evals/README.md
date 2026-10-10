# Detection Quality Evaluation

The Repository Review completeness gate checks workspace structure and review coverage. It does
not measure whether the review found real vulnerabilities. The eval suite measures detection
quality through recall and precision on real targets.

Evaluation code and public OSS benchmarks ship in this repository. Private benchmarks remain in
their existing location and plug in through local, uncommitted configuration, so no private data
enters the repository.

## What "Better" Means

The [Detection Quality Backtest](../docs/detection-quality-backtest.md) owns comparison controls,
repeat conditions, recorded metrics, and the decision policy. This README provides the evaluation
entry points and commands.

Two tiers, kept honest:

- Public benchmarks here are reproducible regression and smoke checks. They carry a
  leakage caveat, the model may have seen the CVE, so they measure "did not regress" more
  than true recall.
- Private, unseen targets are the real recall signal. They never enter this repository.

## Directory Layout

```text
evals/
  __main__.py
  cli.py
  benchmarks/
    contract.py
    cases.py
    registry.py
    validate.py
    coverage.py
    prepare.py
    schemas/
  projects/
    <project-id>/
      benchmark.yaml
      answer-key.yaml
  review/
    failures.py
    source.py
    diff/
      execution.py
      targets.py
      progress.py
      results.py
    repository/
      execution.py
      targets.py
      progress.py
      results.py
  score/
    report.py
    result.py
    match.py
    location.py
    assignment.py
    engine.py
  backtest/
    compare.py
    metrics.py
    gate.py
```

The Diff Review and Repository Review adapters use the same four stages. `execution.py` calls the
product review boundary, `targets.py` materializes benchmark source, `progress.py` reports case
events, and `results.py` translates product output into the shared scorer.

Benchmark manifests and answer keys use the versioned
[Benchmark Contract](../docs/benchmark-contract.md). Use the
[Benchmark Change Checklist](../docs/benchmark-change-checklist.md) for benchmark data changes and
the [Detection Quality Backtest](../docs/detection-quality-backtest.md) for two arm measurements.
`benchmarks/validate.py` is the contract boundary. It applies the versioned JSON Schemas first,
then checks cross-file identity, task source and scope, check knowledge, answer-check scopes, and
clean-task coverage. The review adapters and score engine consume benchmark data only after
discovery and validation.

Public project data lives under `projects/<project-id>/`, separate from the benchmark contract and
runner code. Stack, profile, and knowledge taxonomy remain manifest data rather than directory
names. Private benchmark sources require an explicit `CYBERJURY_EVAL_CONFIG`, so the default
registry remains reproducible and never depends on uncommitted local state.

## Knowledge Coverage

Knowledge is data and the engine is generic, so a security category or a guide with no
eval is a gap that should be visible, not silent. `python -m evals coverage` scans the
knowledge tree and crosses it against the registry, counting the positive and clean diff
benchmark tasks and the repository findings and clean checks that exercise each file, public and
private:

```bash
python -m evals coverage
```

It names uncovered items and reports known coverage gaps, including a category with no
repository target. Invalid profile or knowledge references and answer checks without required
knowledge fail contract validation during registry discovery, before the matrix is rendered.
Validation exits nonzero for invalid benchmark data. A missing repository benchmark is a known
gap and exits zero.

## Private Benchmarks, Not Committed

Create a local config, such as the gitignored `evals/local.yaml`, and select it explicitly:

```yaml
benchmark_sources:
  - path: /abs/path/to/your/private/projects
  - repository: git@github.com:you/private-benchmarks.git
    ref: main
```

```bash
export CYBERJURY_EVAL_CONFIG="$PWD/evals/local.yaml"
```

The committed public root contains one immediate child directory per project, and the directory
name equals the manifest `benchmark_id`. External private roots may retain their own grouping
directories. Their manifest `benchmark_id` remains authoritative. Benchmark names resolve across
the public root and every configured source.

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

The `python -m evals repository` command does not run the review. It scores output a run already
wrote. To score the public benchmark set in one sweep rather than one target, see
[Detection Quality Backtest](../docs/detection-quality-backtest.md), which derives the targets and
order from the committed benchmarks.

Materialize an immutable target and run Repository Review:

```bash
git clone https://github.com/paperless-ngx/paperless-ngx /tmp/paperless-ngx
git -C /tmp/paperless-ngx checkout 6f3451bce0d0bd4b97199ca057002be34c2705bf
cyberjury review repository /tmp/paperless-ngx --workspace /tmp/cj-paperless --run
```

Score the resulting findings, then compare two result files:

```bash
python -m evals repository paperless-ngx --findings-json /path/to/findings.json --json after.json
python -m evals compare before.json after.json
python -m evals compare before.json after.json --by vulnerability
```

A repository score's `extra` reports are unclassified. When a separate source assessment ledger
exists, check every candidate against the pinned source and inspect disagreements with automatic
location scoring:

```bash
python -m evals adjudicate paperless-ngx --findings-json /path/to/findings.json \
  --ledger /path/to/adjudication.json --source /path/to/pinned/source \
  --require-introductions --json adjudication-summary.json
```

The ledger binds every candidate id to the exact findings file hash and checked out commit. Each
record has `candidate_id`, `verdict`, `canonical_id`, `check_id`, `reason`, `proof_gap`, and one or more
`evidence` file and line locations. Verdicts are `supported`, `not_actionable`, `duplicate`, and
`needs_review`. A supported finding can name one known repository check, or remain a separately
supported new issue. The command exits nonzero while assessments are pending or location scoring
assigns a check to a different candidate. With `--require-introductions`, it also fails when a
repository answer check has no findings diff. Static support is not a runtime PoC or an independent
verification vote. The original score and answer key are not rewritten by this command.
With `--require-introductions`, a separately supported issue outside the answer key is also an
unpaired coverage gap until an independently validated introduction case is added.
Pass `--run-status` with the adjacent `_run.json` to compare machine `confirmed`
labels with completed independent verification votes. A legacy output that labels all retained
candidates confirmed while reporting zero verified votes fails this check without rewriting it.

For a repository score, `gate` can require this source assessment alongside its existing recall
checks. It rechecks the ledger against the original findings and fails when reports remain pending,
location scoring credits a different issue, or an introduction diff is missing or later than the
repository snapshot:

```bash
python -m evals gate after.json --adjudication-ledger /path/to/adjudication.json \
  --findings-json /path/to/findings.json --source /path/to/pinned/source \
  --require-introductions
```

`precision_known` measures only reports matched to answer-key checks. When `extra` is nonempty,
overall report precision is unknown until the full source assessment is complete. With a complete
ledger, `report_precision` counts independently supported issue reports over all reports, treating
duplicates as report noise rather than additional vulnerabilities. It is a static source assessment,
not a runtime exploitation claim.
When `gate` receives an adjudication ledger, its regression decision uses the ledger's known
finding identities. Raw location assignment differences remain visible as diagnostic notes. A
two-arm gate requires `--baseline-adjudication-ledger` and `--baseline-findings-json` so both arms
use the same source-assessed scoring policy. The baseline may also pass `--baseline-run-status`.

Apply the eval regression gate against a baseline and precision floor:

```bash
python -m evals gate after.json --baseline before.json --precision-floor 0.8
```

Run the diff benchmark set or one selected case:

```bash
python -m evals diff --mode standard --model <id> --runs 3
python -m evals diff --cases /path/to/diff/case --model <id>
python -m evals diff --cases /path/to/benchmark.yaml --mode standard --runs 3 \
  --certify-findings --json certification.json
```

Inspect the benchmarks the registry sees and validate one contract:

```bash
python -m evals list
python -m evals validate evals/projects/paperless-ngx
```

A single diff run produces one `Result`. When repetition is required, `--runs N` folds N runs
into a frequency verdict, found by strict majority. For Repository Review, score each repeated
arm separately and report every result so the spread remains visible.

`--certify-findings` is stricter than the frequency verdict. It requires exactly three fresh runs,
selects findings cases only, and passes a case only when all of that case's expected findings occur
in the same complete run. Every case must pass at least two runs, and all three attempts must be
error free. Findings from different runs never combine into one case pass. The JSON result includes
the per case and per run `case_gate` receipt, and the command exits nonzero when any case misses the
threshold.

## Scoring Policy

The scorer assigns reports to checks one to one. A check that uses the structured list form of
`locations` requires the security category and one complete source alternative. Each alternative
contains an exact repository relative file and either an exact line or a source symbol. A symbol
match requires the reported line to fall inside that definition. Report prose and basename matching
do not substitute for structured source identity.

Checks that still use the object form retain the existing matching behavior for that form while projects are
converted separately. An endpoint can establish route identity. A grouped symbol can match report
prose or a cited source span, and an unambiguous basename can match a grouped file.

A diff check also requires one exact old or new line from `changes`. This line establishes the
changed identity while `locations` establishes where the issue is observable. Repository checks
use the same location contract without `changes`. Reports that match no check remain extra for
human review because an answer key cannot establish whether an unkeyed report is a real issue.

Without `--mode`, each diff task uses its declared `review.mode`. Passing `--mode standard` or
`--mode adversarial` overrides every selected task for a controlled comparison. There is no
separate benchmark mode.

The eval regression gate is the policy that blocks a regression in CI. It fails loud on a failed
review step, a findings check caught at baseline now missing, a new false positive on a clean
lookalike, precision below a floor, and unsound benchmark data such as a knowledge reference that
resolves to no file or an unlocatable answer check. An extra unkeyed report alone never fails the
gate, the key cannot say whether it is a real bug.

A benchmark grows by adding more findings and clean checks to a project answer key, or by
adding a new `projects/<project-id>/` directory with a shared manifest and task scoped answer key
checks. A diff benchmark grows by adding a diff task to that project manifest and scoping the
answer key checks with `applies_to`. A task outside the web default sets the manifest `profile`, for
example a Solidity benchmark sets `profile: evm` so it scores against the EVM knowledge and prompt.
Keep public benchmarks public and non-proprietary, this repository ships to PyPI and GitHub.
