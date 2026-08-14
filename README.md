# Cyberjury

AI-assisted security review for code diffs and whole repositories.

The tool has two review paths:

- **Diff Review** audits a pull request or unified diff in one command.
- **Repository Review** fans out across a whole repository, reviews focused units, deduplicates
  candidates, verifies findings, and checks coverage with a gate.

Diff Review is fast and reads only the change, so it catches what is visible in the diff.
Cross-file business logic and invariants that span files need context from across the
repository, which is Repository Review's job, so a clean Diff Review does not by itself clear the
repository.

Security knowledge is data. Vulnerability classes, language guides, framework guides, and
protocol guides live in markdown under each review profile's `knowledge/` directory, for
example `cyberjury/profiles/web/knowledge/`, so adding a stack or class is usually a data
change rather than a Python code change. The `web` profile covers Web Application Security
and is the default. The `evm` profile covers EVM Application Security for Solidity smart
contracts. Select one with `--profile` or let the tool detect it automatically.

## When to Use This Tool

Direct model review is often best for a small, one off check.

Use **Diff Review** for pull requests, release branches, and CI gates. It asks whether a
code change introduced a reportable security issue.

Use **Repository Review** for full repository audits, release reviews, high risk systems,
authorization boundaries, business invariants, and smart contracts. It asks whether a
repository was reviewed through a tracked worklist and which findings survived
verification.

Both review paths wrap the model in a repeatable harness: scoped inputs, profile guidance,
verification, fail loud behavior, structured output, and gates. Repository Review adds review
state, so a run resumes and finalizes later.

For the detailed decision matrix, see the
[direct model review decision matrix](docs/direct-model-review-vs-diff-and-repository-review.md).

## Install

```bash
pip install cyberjury
cyberjury install-slash-command
```

That is the whole setup. `pip install cyberjury` pulls everything a normal review needs, the
Anthropic and OpenAI API backends, and both profiles' facts toolchains, with no extras to choose.
`cyberjury install-slash-command` drops the
`/cyberjury-review` command into both the Claude Code and Codex command directories, so it works in
either agent: run it on a repository directory for a whole-repository review, or on a diff file or
git range for a diff review.

## Configure a Model Backend

Set provider defaults. The default provider order is OpenAI first, then Anthropic. With an OpenAI
key, the default is OpenAI. Without an OpenAI key, the default provider is Anthropic. Every review
path uses provider APIs and requires a reachable key. The OpenAI default model is `gpt-5.6`, and
the Anthropic fallback model is `claude-opus-5`:

```bash
export CYBERJURY_PROVIDER=openai
export CYBERJURY_MODEL=gpt-5.6
export CYBERJURY_API_KEY=...

# optional gateway or proxy
export CYBERJURY_API_BASE=...
export CYBERJURY_WIRE_API=...

# optional retry tuning
export CYBERJURY_RETRIES=2
export CYBERJURY_TIMEOUT=240
```

OpenAI wire selection is automatic when `CYBERJURY_WIRE_API` and `--wire-api` are unset. GPT-5 and
OpenAI reasoning model names use the Responses API, and other OpenAI model names use Chat
Completions. Set `CYBERJURY_WIRE_API=chat|responses` or pass `--wire-api` only to force the wire
API, for example when a proxy endpoint needs one path.

The CLI loads a `.env` from the working directory at startup, so a project can set its provider
config once instead of exporting it every session. A value already exported in the shell wins
over the file, and a missing file is fine. The auto-load is a CLI convenience, so importing the
library directly does not read `.env`. For the complete operator template, including SDK keys and
source fetch keys, see `.env.example`.

Useful flags:

- `--provider openai|anthropic`
- `--model <model>`
- `--api-key <key>`
- `--api-base <url>`
- `--wire-api chat|responses`
- `--retries <n>`
- `--timeout <seconds>`

### Cross-Model Review

A single-model run needs only the setup above. For stronger verification, both review paths name
three model roles, finder, challenger, and judge. The finder finds, the challenger refutes, and an
independent confirmer must approve before a deletion. The judge is the usual confirmer. A seat that
surfaced a finding is skipped for that finding, because it is not an independent read. Each role
defaults to the base `--model`. Put a different vendor in any seat for cross-model review, where
uncorrelated blind spots catch what one model misses. With no confirmer distinct from the
challenger, nothing is refuted, the recall-safe default.

Each role takes a full backend, the same five fields as the base, every one unset by default:
`CYBERJURY_<ROLE>_PROVIDER`, `_MODEL`, `_API_KEY`, `_API_BASE`, `_WIRE_API`, with `<ROLE>` one of
`FINDER`, `CHALLENGER`, `JUDGE`, and the matching `--<role>-provider`, `--<role>-model`,
`--<role>-api-key`, `--<role>-api-base`, `--<role>-wire-api` flags. An unset provider inherits the
base provider. Model, API key, API base, and wire API inherit only while the role stays on the same
provider. A role that switches provider uses that provider's default model unless you set a role
model, and it brings its own key since the base key belongs to the base provider. For example an
OpenAI base finder challenged by Claude and confirmed by a distinct OpenAI judge:

```bash
export CYBERJURY_CHALLENGER_PROVIDER=anthropic
export CYBERJURY_CHALLENGER_MODEL=claude-opus-5
export CYBERJURY_CHALLENGER_API_KEY="$ANTHROPIC_API_KEY"

# keep the judge distinct from the finder and challenger
export CYBERJURY_JUDGE_MODEL=...
```

The same `CYBERJURY_FINDER_*` / `CYBERJURY_CHALLENGER_*` / `CYBERJURY_JUDGE_*` and the matching
`--finder-* / --challenger-* / --judge-*` flags work on both `review diff` and `review repository`.
Note that `review repository --run` finds with one model, the finder.

## Diff Review

Diff Review is the fast coded path. It audits a unified diff with either standard Finder
judgments or adversarial Finder, Challenger, and Judge passes.

```text
cyberjury review diff [--file <file> | --git-range <range>] [--mode standard|adversarial]
  [--rounds <n>] [--concurrency <n>] [options]
```

```bash
# review a diff file
cyberjury review diff --file changes.diff

# review a git range
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD

# review stdin
git diff HEAD~1 | cyberjury review diff

# use adversarial mode for extra recall on subtle logic across files
cyberjury review diff --file changes.diff --mode adversarial

# emit SARIF
cyberjury review diff --file changes.diff --format sarif

# run adversarial mode with a Claude finder and judge, plus an OpenAI challenger
cyberjury review diff --file changes.diff --mode adversarial \
  --provider anthropic --api-key "$ANTHROPIC_API_KEY" \
  --challenger-provider openai --challenger-api-key "$OPENAI_API_KEY"
```

When a repository source root is available, through `--git-range` or `--repository`, diff review
grounds the prompt with facts from that checkout. The selected profile's facts backend extracts call
and import structure, then the prompt receives current source around each changed hunk, same file
helper definitions found through the facts graph, and a short source prefix for each changed source
file. A backend failure is a failed review step. `--file` and stdin without `--repository` keep
their original behavior and review only the supplied diff.

When source-backed verification runs, diff review uses the same verifier route as Repository
Review before reporting findings. The challenger tries to refute, and only an independent confirmer
can approve a drop. With no distinct confirmer, verification keeps every refuted candidate.
Verification failure keeps the candidate and marks the review degraded. `--concurrency` controls
verification fan-out, defaulting to 8.

`cyberjury review diff --dry-run` uses a mock provider and a built-in demo diff, so it needs
no API key.

## Repository Review

Repository Review is the recall-first path for whole repositories. A whole codebase is too large
for one useful model call, so the tool creates a workspace, builds a unit worklist, and
reviews focused units instead of doing one shallow pass.

```text
cyberjury review repository <repository> (--scaffold | --run | --finalize | --gate) [options]
```

### From an Agent

In Claude Code or Codex, one command runs the whole review, scaffold, run, finalize, and gate:

```text
/cyberjury-review <target> [--profile auto|web|evm]
  [--mode standard|adversarial] [--rounds <n>] [--concurrency <n>] [--workspace <path>]
```

The slash command is a command runner. It uses the same provider API configuration as the CLI, so
`.env` is used throughout. PoCs run only against sandbox or dev environments, never production.

### From the CLI

The slash command runs these four steps for you. Run them yourself for a headless or CI review:

```bash
# build the workspace and unit worklist
cyberjury review repository /path/to/repository --scaffold

# run the coded review
cyberjury review repository /path/to/repository --run

# deduplicate candidates, verify them, and write findings
cyberjury review repository /path/to/repository --finalize

# check coverage, exits nonzero until it is met
cyberjury review repository /path/to/repository --gate
```

`--run` reviews every unit, verifies inline, and writes the confirmed `findings/`, so on the coded
path `--finalize` is optional. Standard mode runs one finder pass. Adversarial mode runs role
rounds until convergence or the round cap. See Review Strategy for how each unit is reviewed.
`--finalize` deduplicates and verifies existing candidates in the workspace. It records refuted
candidates in `_refuted.md`, writes PoC
reconciliation in `_pocs.md`, and writes the confirmed `findings/` and the ranked `findings.json`.
`--gate` fails until the workspace has an enumerated surface, reviewed units, and calibrated
candidates. It notes source files that no unit owns, so the operator can decide whether to add
more units before reporting the review complete. Finalize writes a PoC for each confirmed finding
when the selected profile supports it, then reconciles PoC artifacts into `_pocs.md`. PoCs only add
evidence, so a finding is kept whether or not its PoC reproduces.

### The Workspace

The workspace is private and holds everything the review read, wrote, and can be resumed from:

```text
inventory/                attack surface, authorization model, seeded entrypoints, severity rubric
units/                    one review unit per candidate entrypoint
candidates/               candidate write-ups before final confirmation
findings/                 confirmed findings, written by --run or finalize
pocs/                     runnable PoCs, when available
findings.json             ranked machine-readable findings
METHODOLOGY.md            full review process
_stack.md                 detected stack notes
_vulnerabilities.md       all categories and complete vulnerability class library
_false_positive_traps.md  how a static read misjudges, both over-reporting and wrongly refuting
_refuted.md               refuted candidates and why
_pocs.md                  PoC reconciliation, planned versus delivered
_run.json                 the coded run's coverage, failure state, completion, convergence, and spend
_finalize.json            what finalize did, its completeness counts and spend
_union.json               the candidate pool a resumed --run reads instead of reviewing again
_verified.json            the verdicts a resumed verification skips, an unfinished one left out
_timeline.json            elapsed per pipeline stage, across the separate commands
.cyberjury-workspace      the marker that stops --fresh clearing a directory it did not create
```

A review grounded by a facts backend adds `_facts.md`, `_facts_by_file.json`, and whichever of
`_facts_units.json` and `_facts_graph.json` its backend emits. If extraction fails,
`_facts_error.txt` records the failure before the review step fails. A review carrying
fetched-source provenance adds `_target.md`.

`_run.json` and `_finalize.json` are what the gate reads to decide whether a review finished, and
what a two-arm backtest reads to compare cost, so treat them as results rather than as debug output.

### Review Strategy

A `--run` reviews each unit through provider APIs. Every finder, challenger, judge, verifier, and
PoC generation seat requires a reachable key, either through the seat's explicit key, the base
`CYBERJURY_API_KEY`, or the provider SDK key such as `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

Facts grounding is not a choice. A profile that binds a facts backend replaces the path-name guess
about a file's downstream with a tool-extracted graph: Slither gives the evm profile its call graph,
storage layout, and read and write sets, and a tree-sitter backend recovers call and import edges
from syntax for Python, JavaScript, TypeScript, and Go, then expands each entrypoint along its real
import edges. Both profiles read the same way, on for every review mode, with no flag
to turn it off. So a backend that cannot run, or a Solidity target that does not compile, fails the
review rather than quietly producing one without cross-function units, since a review that covers
less without saying so is a reduced review reported as a whole one. A single file tree-sitter cannot
parse is still skipped on its own, because that costs one file rather than the whole graph.

Diff Review and Repository Review share the same review strategy. The target shape differs, a patch
for diff review and a source tree for whole-repository review, but mode names, role names, verifier
behavior, and failure semantics mean the same thing.

#### Shared Engine Model

- The finder proposes exploitable findings.
- The challenger tries to refute finder findings on controlling facts, and in adversarial mode it
  also scans for missed findings.
- The judge is the usual confirmer seat. In adversarial mode it also rules on candidates before they
  enter the coded union.
- Code owns orchestration, provenance, convergence, verification, and reporting. Model calls provide
  per target judgment.
- A failed, blank, malformed, or rate limited call is incomplete work, not a clean pass.
- `cyberjury/review/engine.py` owns validated review plans, role execution, response contracts,
  recall safe fallback, monotonic union, round scheduling, convergence, pending work, and completion
  state for both paths.
- `cyberjury/review/verification.py` owns the one verification route both paths use.
- Shared knowledge, provenance, and failure records also live under `cyberjury/review/`. Diff Review
  and Repository Review keep only target shaping, prompt construction, location policy, and
  lifecycle code.
- Vulnerability knowledge is selected at the judgment unit. A diff chunk selects from its patch
  and grounded repository context. A repository unit selects from its source and extracted facts.
  Both paths keep every class whose selection hints match and use the same relevance ordering.
  Ordering guides attention and never drops a matched class. Standard mode partitions selected
  knowledge into bounded packs, runs one Finder judgment per pack, and monotonically merges their
  findings. The evidence prefix stays identical across pack calls, so providers can cache it. A
  judgment owns its assigned classes and leaves other selected classes to their assigned
  judgments. It may still report a compelling class the selector did not choose.

Each target adapter uses the same stage names and the same function boundary:

| Stage | Shared Goal | Diff Adapter | Repository Adapter |
|---|---|---|---|
| `model.py` | Build bounded review units | Patch file batches | Source and call path units |
| `context.py` | Ground one unit with related source and facts | Changed code context | Unit source and facts artifacts |
| `prompts.py` | Express target evidence in the shared role contracts | Unified diff prompts | Repository unit prompts |
| `reviewer.py` | Call providers and parse role results | `Finding` results | `Candidate` results |
| `runner.py` | Adapt the target worklist to shared fan out | Diff batches | Repository units |
| `union.py` | Define target finding identity and evidence folding | File, line, and category | Symbol, endpoint, location, and category |
| `verify.py` | Adapt target findings to shared verification | Diff result mapping | Workspace checkpoint mapping |
| `engine.py` | Compose target stages without duplicating shared mechanics | One command lifecycle | Scaffold, resume, finalize, and report lifecycle |

Both runners call `run_review_units`. Both reviewers use the shared role result and response
contracts. Both unions configure `FindingAccumulator`. Both verify adapters call
`verify_findings`. The target files define data shape and lifecycle differences, while role order,
fan out, accumulation, convergence, failure accounting, and verification votes have one
implementation under `cyberjury/review/`.

#### Standard Mode

`--mode standard` runs one finder pass.

- Diff Review packs the diff into context sized chunks. Each chunk gets one or more bounded Finder
  judgments when its selected knowledge does not fit one pack.
- Repository Review builds repository units from the scaffolded worklist. Each unit follows the
  same bounded Finder judgment policy, with unit fan-out controlled by `--concurrency`.
- Successful sibling judgments are merged. Any failed judgment leaves the review incomplete and
  cannot erase findings returned by the others.
- Both paths verify findings when source is available. Diff review can verify only when
  `--repository` or `--git-range` gives it a source root. Repository Review already has a source
  root.

#### Adversarial Mode

`--mode adversarial` runs Finder, Challenger, and Judge rounds.

- The finder scans the current target and receives the prior union on later rounds.
- The challenger refutes only on facts visible in the target, and also reports missed findings.
- The judge keeps candidates supported by the target and can lower severity.
- The coded loop unions kept candidates across rounds. A later omission does not delete an earlier
  candidate.
- The loop converges only after two clean rounds add nothing new. `--rounds` is the cap, not a
  promise that convergence happened.

#### Verification And Deletion

Verification is asymmetric for recall.

- The challenger is the skeptic. It tries to prove a candidate is safe.
- A candidate is dropped only when every applicable independent confirmer upholds the refutation.
- A seat that found a candidate cannot confirm deleting that candidate. Both paths track `found_by`
  for this.
- With no distinct confirmer, verification keeps the candidate.
- Verification failure keeps the candidate and marks the review degraded or incomplete.

#### Convergence And Failure

- Standard mode does not need convergence. Completion means the finder covered the intended target.
- Adversarial mode is complete only when convergence happens before the round cap.
- Unresolved or investigation work remains pending and prevents completion in either path.
- Diff Review surfaces non convergence as a degraded review and exits nonzero.
- Repository Review writes `_run.json` with `complete: false` and exits nonzero.

#### Intentional Differences

These differences stay because the reviewed object is different.

- Diff review reviews a patch. It excludes configured noise and test files before judgment, then
  normalizes reported locations against changed lines.
- Whole-repository review reviews a source tree. It does not require findings to land on changed
  lines.
- Diff review is one command with no workspace lifecycle.
- Repository Review has `--scaffold`, `--run`, `--finalize`, `--gate`, `--fresh`, resume state,
  workspace artifacts, and PoC output.
- Diff review uses `--concurrency` for verification fan-out when source is available. Repository
  Review uses it for unit review fan-out and verification.

## Data Boundary

The tool sends code-derived content to the model provider you configure, so know what
leaves the machine before reviewing a proprietary repository:

- Diff Review sends the unified diff under review. When a repository root is available for
  grounding, it also sends bounded source context around changed code.
- Repository Review sends bounded source snippets, the detected stack notes, the selected
  vulnerability guidance, and the findings.
- Verification sends the cited source file and the finding details.

A custom `--api-base` proxy becomes part of the trust boundary, so the data above also reaches that
gateway. Prefer the `CYBERJURY_API_KEY` environment variable over
`--api-key`, since a flag can leak through shell history and process listings. The review
workspace and the generated reports hold exploit paths, sensitive file locations, and
PoCs, so treat them as sensitive. The workspace is created private, mode `0700`.

## Fetch Verified Source

Review a deployed contract by first pulling its verified source from a block explorer, then
running Repository Review on the local tree:

```text
cyberjury fetch source --address <address> --out <dir> [options]
```

```bash
cyberjury fetch source --chain eth --address 0x... --out ./target
cyberjury review repository ./target --profile evm --run
```

`fetch source` queries the Etherscan V2 API, which serves every supported chain from one
endpoint with one key, so a single `CYBERJURY_ETHERSCAN_API_KEY` covers `arbitrum`, `bsc`,
`eth`, and `polygon`, chosen with `--chain`. Pass the key with `--api-key` or that
environment variable.
It writes the reconstructed source tree and a `cyberjury-source.json` recording the chain,
address, compiler, and source URL, and it fails loud on an unverified or malformed response.
It never runs a review on its own. Review the written source tree with `--profile evm`.

## Supported Knowledge

The tool selects a review profile with `--profile`, `auto` by default. The `web` profile
covers Web Application Security and is the default. The `evm` profile covers EVM Application
Security for Solidity smart contracts, including reentrancy, access control, oracle
manipulation, accounting precision, and signature replay.

Current guide coverage in the web profile includes:

- Python: Django, Flask, FastAPI, Celery
- Go: Gin, Echo
- JavaScript and TypeScript: Express, NestJS
- Protocols: OAuth, OIDC, GraphQL, and MCP

The evm profile ships a Solidity guide and the smart contract vulnerability classes above.
Unguided stacks still work, but the model relies more on general methodology and model knowledge.

## Findings

Every reportable finding should have:

- file and line
- severity
- category
- description
- exploit scenario
- recommendation
- confidence or verification status

The tool is intentionally scoped to real exploitable application security issues. It should
not report dependency CVEs, style notes, generic best practices, speculation, or risks that
only matter if production configuration leaks.

## Model and Mode Guidance

Detection quality is dominated by model quality first, then mode.

- Use standard mode with a strong model by default.
- Use adversarial mode when you want extra recall on subtle cross-file logic.
- Do not use adversarial mode as a false-positive reducer. False positives are controlled
  by the do-not-report guidance, deterministic filtering, and verification.

## GitHub Actions

Use the example workflow:

```bash
cp examples/cyberjury-pr-review.yml .github/workflows/cyberjury-pr-review.yml
```

Add `CYBERJURY_API_KEY` as a repository secret. The workflow reviews the pull request diff,
uploads SARIF to code scanning, and fails on HIGH or CRITICAL findings.

## Extend the Knowledge

Add security knowledge as markdown:

- Vulnerability class:
  `cyberjury/profiles/<profile>/knowledge/vulnerabilities/<id>.md`
- Language guide:
  `cyberjury/profiles/<profile>/knowledge/guides/languages/<language>.md`
- Framework guide:
  `cyberjury/profiles/<profile>/knowledge/guides/frameworks/<language>/<framework>.md`
- Protocol guide:
  `cyberjury/profiles/<profile>/knowledge/guides/protocols/<protocol>.md`

Keep frontmatter and detection signals data-driven. Avoid adding language, framework, or
vulnerability-specific detection logic to Python unless the engine itself needs a generic
capability.

### Knowledge Schema

Vulnerability classes share one frontmatter schema across profiles:

| Field | Required | Purpose |
| --- | --- | --- |
| `id` | yes | Canonical finding category and file stem. |
| `title` | yes | Readable class name in prompts and docs. |
| `impact` | yes | Default class impact used to rank prompt selection. |
| `tags` | yes | External taxonomy anchors and coarse grouping, such as CWE, OWASP, and SWC identifiers. |
| `selection_hints` | yes | Advisory text fragments used to choose likely classes for a target. |
| `aliases` | no | Category variants from model output that fold back to the canonical `id`. |

Guide files share one frontmatter schema across languages, frameworks, and protocols:

| Field | Required | Purpose |
| --- | --- | --- |
| `id` | yes | Stable guide id and file stem. |
| `title` | yes | Readable guide name in stack notes. |
| `kind` | yes | One of `language`, `framework`, or `protocol`. |
| `language` | frameworks only | The language guide a framework inherits generic routing from. |
| `detect` | yes | Selection signals with `files`, `manifest_hints`, `imports`, and `content` lists. |
| `entrypoint_files` | yes | File globs that seed likely application entrypoints. |
| `entrypoint_markers` | yes | Source markers that seed entrypoints when filenames are not enough. |
| `logic_layer_files` | yes | File globs for downstream business logic reached from entrypoints. |
| `public_api_patterns` | yes | Regexes that seed library public surfaces when no application entrypoint exists. |

Use an empty list when a guide intentionally has no signal for a required routing field.
Framework guide metadata stores only framework specific routing. At load time it inherits
the declared language guide's routing so the data stays small without losing coverage.

## Development

Run tests in a virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```
