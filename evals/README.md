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
    diff.py        run the diff capability probe and score
  diff_cases.py    load the shipped diff cases, engine-free so the matrix can read them
  registry.py      discover benchmarks across public and private sources
  coverage.py      scan the knowledge tree, build the coverage matrix
  suites.py        a named tag selection over the cases and benchmarks
  compare.py       diff two results, the per-issue flips, deltas, and by-axis grouping
  gate.py          the regression policy, a yes or no on landing a change
  suites/<name>.yaml             a tag selection, public-smoke and knowledge-coverage
  benchmarks/
    diff/languages/<language>/cases.yaml   the shipped small diff probes, each with knowledge
    diff/protocols/<protocol>/cases.yaml   protocol cases such as OAuth, independent of language
    diff/<group>/<name>/benchmark.yaml     a real commit diff pointer plus the stack and knowledge
    diff/<group>/<name>/answer-key.yaml    planted issues and safe lookalikes for that commit diff
    repository/frameworks/<language>/<framework>/<name>/benchmark.yaml   a git pointer plus the stack and knowledge it exercises
    repository/frameworks/<language>/<framework>/<name>/answer-key.yaml  planted issues and safe lookalikes
```

Benchmarks group under the same three buckets the knowledge guides use, `languages/`,
`frameworks/`, and `protocols/`, so the eval tree mirrors the knowledge taxonomy. A repository
target sits at `repository/frameworks/<language>/<framework>/<name>`, for example
`repository/frameworks/python/flask/pyload` and `repository/frameworks/go/gin/answer`. A target may
also sit flat at `repository/<name>`, the id is the leaf directory name either way, so the grouping
path never renames a benchmark.

A diff target may also sit at `diff/<group>/<name>` with `benchmark.yaml` and `answer-key.yaml`.
Prefer this shape for real recall evidence. The manifest pins a public repo URL or local repo path
plus `base` and `ref`, so the run reviews the real commit diff and uses the checked out `ref` for
context and verification. The older `cases.yaml` files stay useful as fast probes and coverage
fillers, but they are not the main evidence for cross file or commit context behavior.

A `benchmark.yaml` is the manifest, a git or explorer pointer, never vendored code, plus the
stack and the knowledge the target exercises, so the coverage matrix can attribute it. The
legacy `target.yaml` carrying only the pointer is still read, so a private benchmark need
not be reshaped.

An `answer-key.yaml` has `planted` issues a complete review must surface and `safe`
lookalikes a report would be a false positive on. Each entry may name the knowledge it
exercises. The legacy `issues` key is accepted as an alias, and the legacy file name
`answer_key.yaml` is still read, so a private benchmark need not be reshaped. The review
under test never reads the key.

## Knowledge Coverage

Knowledge is data and the engine is generic, so a vulnerability class or a guide with no
eval is a gap that should be visible, not silent. `python -m evals coverage` scans the
knowledge tree and crosses it against the registry, counting the positive and safe diff
cases and the repository planted and safe entries that exercise each file, public and private:

```bash
python -m evals coverage
```

It names the uncovered files, the worklist for the case library, and reports the gate
problems: a vulnerability with no positive or no safe diff case, a benchmark reference that
resolves to no real knowledge file, and an answer key entry that names no knowledge. An
unresolved reference is broken benchmark data, so the command exits nonzero on it, while a
missing case is a known gap and exits zero.

## Private Benchmarks, Not Committed

Create a local `evals/local.yaml`, gitignored, or point `CYBERJURY_EVAL_CONFIG` at one:

```yaml
benchmark_sources:
  - path: /abs/path/to/your/private/benchmarks   # read in place, nothing is copied or committed
  - repository: git@github.com:you/private-benchmarks.git
    ref: main
```

A source root may use the per-benchmark `repository/<name>/answer-key.yaml` layout, optionally
grouped under a `repository/frameworks/<language>/<framework>/<name>` path, or the legacy
`groundtruth/<name>.yaml`, so existing private data scores without being reshaped. Benchmark
names resolve across the public root and every source.

A private source may also provide diff benchmarks under
`diff/<group>/<name>/benchmark.yaml` plus `answer-key.yaml`. The manifest may point at
a git `target.path` or `target.url` with `base` and `ref`, so the run derives the diff and facts
context from the target checkout. It may also point at sibling `diff_file` and `context_file`
artifacts for a fully frozen input. The answer key states whether the case is planted or a safe
lookalike. Use this for private real patch evidence that cannot ship in the public case library.
The older `diff/**/cases.yaml` batch format still works for small probe cases. Diff benchmarks
score returned findings against the answer key anchors, so a different finding in the same patch
does not credit a planted issue.

## Run

The repository path does not run the review, the agent or a coded run does that, this scores the
output it wrote. To score the whole public suite in one sweep rather than one target, see
`BACKTEST.md`, the batch runbook that derives the targets and order from the committed
benchmarks and drives the agent path end to end.

```bash
# 1. review a cloned target, see its benchmark.yaml for the pointer
git clone --depth 1 --branch v0.3.8 https://github.com/open-webui/open-webui /tmp/owui
#    the coded engine, deterministic and reproducible, the path to prefer for a regression.
#    --run scaffolds, fans out one sub-review per unit over diverse passes, verifies, and
#    writes findings.json, all in one command, no separate finalize. --executor auto calls
#    the provider API when a key is reachable, and an Anthropic seat with no key falls back to
#    the Claude Code subscription, so a Claude run needs no extra setup. A keyless non-Anthropic
#    seat fails loud instead. Pass --executor api to require a key and fail loud when there is
#    none, the deterministic path to prefer in CI:
cyberjury review repository /tmp/owui/backend/apps/webui --workspace /tmp/cj-owui --run --executor auto
#    or scaffold only and let an agent follow METHODOLOGY.md, the /cyberjury-review slash
#    command, then finalize, the same methodology run by an agent instead of code:
# cyberjury review repository /tmp/owui/backend/apps/webui --scaffold --workspace /tmp/cj-owui
#    Both are product paths and should agree, score whichever wrote findings. Do not invent a
#    third orchestration, a custom harness drifts from the product and the score stops meaning
#    anything. --run needs detectable entrypoints, a no-entrypoint scope such as a plain library
#    or a frontend-template-only directory must take the agent path, which enumerates them by reading.

# 2. score it, prefer --findings-json for the ranked list, findings/ names each file by
#    candidate and category so two classes on one endpoint stay distinct, not collapsed
python -m evals repository open-webui --findings-json /tmp/cj-owui/webui/findings.json --json after.json

# 3. compare two versions, --by groups the flips by an axis to see where a move landed
python -m evals compare before.json after.json
python -m evals compare before.json after.json --by vulnerability

# 4. gate a change in CI, fail loud on a regression against a baseline
python -m evals gate after.json --baseline before.json --precision-floor 0.8

# diff capability probe, needs provider creds in the environment. --runs N repeats and
# folds by frequency, so a planted issue counts as caught only by a strict majority of runs.
# The probe spans every domain, a Solidity row carrying domain: evm scores against the EVM
# knowledge and prompt, a row with no domain runs under the web default
python -m evals diff --mode standard --executor subscription --model <id> --runs 3
# diff benchmarks that provide a source root through benchmark.yaml verify findings by default
python -m evals diff --cases /path/to/diff/case --executor api --model <id>

# a suite is a tag selection over the library, public-smoke is a fast subset
python -m evals run public-smoke --executor subscription --model <id> --runs 3

# what the registry sees, benchmarks and suites with the cases each selects
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

A benchmark grows by adding more planted issues and lookalikes, or a new
`repository/frameworks/<language>/<framework>/<name>/` directory with its `benchmark.yaml` and
`answer-key.yaml`. The diff probe grows by adding a
row to the `benchmarks/diff/languages/<language>/cases.yaml` for its language, or to
`diff/protocols/<protocol>/cases.yaml` for a protocol case, a positive with a category or a safe
lookalike without one, each naming the knowledge it exercises so
`coverage` attributes it. A row outside the web default carries a `domain`, for example a
Solidity case sets `domain: evm` so it scores against the EVM knowledge and prompt. A suite grows by
adding `suites/<name>.yaml` naming the tags it selects, no second list of cases
to keep in sync. Keep public benchmarks public and non-proprietary, this repository ships to PyPI
and GitHub.
