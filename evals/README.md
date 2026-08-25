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
    languages/<language>/<project>/
      benchmark.yaml
      answer-key.yaml
    frameworks/<language>/<framework>/<project>/
      benchmark.yaml
      answer-key.yaml
    protocols/<protocol>/<project>/
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

It names uncovered files and reports known coverage gaps, including a vulnerability with no
repository target. Invalid profile or knowledge references and answer checks without required
knowledge fail contract validation during registry discovery, before the matrix is rendered.
Validation exits nonzero for invalid benchmark data. A missing repository benchmark is a known
gap and exits zero.

## Private Benchmarks, Not Committed

Create a local `evals/local.yaml`, gitignored, or point `CYBERJURY_EVAL_CONFIG` at one:

```yaml
benchmark_sources:
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

The `python -m evals repository` command does not run the review. It scores output a run already
wrote. To score the public benchmark set in one sweep rather than one target, see
[Detection Quality Backtest](../docs/detection-quality-backtest.md), which derives the targets and
order from the committed benchmarks.

Materialize an immutable target and run Repository Review:

```bash
git clone https://github.com/open-webui/open-webui /tmp/owui
git -C /tmp/owui checkout 9bcd4ce5c0a01af68c0d2aa44554a68bb741c61b
cyberjury review repository /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui --run
```

Score the resulting findings, then compare two result files:

```bash
python -m evals repository open-webui --findings-json /tmp/cj-owui/webui/findings.json --json after.json
python -m evals compare before.json after.json
python -m evals compare before.json after.json --by vulnerability
```

Apply the eval regression gate against a baseline and precision floor:

```bash
python -m evals gate after.json --baseline before.json --precision-floor 0.8
```

Run the diff benchmark set or one selected case:

```bash
python -m evals diff --mode standard --model <id> --runs 3
python -m evals diff --cases /path/to/diff/case --model <id>
```

Inspect the benchmarks the registry sees and validate one contract:

```bash
python -m evals list
python -m evals validate evals/benchmarks/<group>/<project>
```

A single diff run produces one `Result`. When repetition is required, `--runs N` folds N runs
into a frequency verdict, found by strict majority. For Repository Review, score each repeated
arm separately and report every result so the spread remains visible.

## Scoring Policy

The scorer assigns reports to checks one to one. A check that uses the structured list form of
`locations` requires the vulnerability class and one complete source alternative. Each alternative
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
adding a new `<group>/<name>/` directory with a shared manifest and task scoped answer key
checks. A diff benchmark grows by adding a diff task to that project manifest and scoping the
answer key checks with `applies_to`. A task outside the web default sets the manifest `profile`, for
example a Solidity benchmark sets `profile: evm` so it scores against the EVM knowledge and prompt.
Keep public benchmarks public and non-proprietary, this repository ships to PyPI and GitHub.
