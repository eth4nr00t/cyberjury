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
protocol guides live in markdown under each review domain's `knowledge/` directory, for
example `cyberjury/domains/web/knowledge/`, so adding a stack or class is usually a data
change rather than a Python code change. The `web` domain is the default and `evm` reviews
Solidity smart contracts, selected with `--domain` or detected automatically.

## When to Use This Tool

Direct model review is often best for a small, one off check.

Use **Diff Review** for pull requests, release branches, and CI gates. It asks whether a
code change introduced a reportable security issue.

Use **Repository Review** for full repository audits, release reviews, high risk systems,
authorization boundaries, business invariants, and smart contracts. It asks whether a
repository was reviewed through a tracked worklist and which findings survived
verification.

Both review paths wrap the model in a repeatable harness: scoped inputs, domain guidance,
verification, fail loud behavior, structured output, and gates. Repository Review adds review
state, so a run resumes and finalizes later.

For the detailed decision matrix, see
[`docs/direct-model-review-vs-diff-and-repository-review.md`](docs/direct-model-review-vs-diff-and-repository-review.md).

## Install

```bash
pip install cyberjury
cyberjury install-slash-command
```

That is the whole setup. `pip install cyberjury` pulls everything a normal review needs, the
Anthropic and OpenAI backends, the Claude Code subscription transport, and both domains' facts
toolchains, with no extras to choose. `cyberjury install-slash-command` drops the `/cyberjury-review` command into both the
Claude Code and Codex command directories, so it works in either agent: run it on a repository
directory for a whole-repository review, or on a diff file or git range for a diff review.

## Configure a Model Backend

Set a provider key, or run keyless on your Claude Code subscription with `--executor subscription`:

```bash
export CYBERJURY_MODEL=claude-opus-4-8
export CYBERJURY_API_KEY=...
export CYBERJURY_API_BASE=...   # optional gateway or proxy
export CYBERJURY_WIRE_API=chat  # set responses for a GPT-5 reasoning model, see below
```

An OpenAI GPT-5 reasoning model answers on the Responses API, not Chat Completions, so set
`CYBERJURY_WIRE_API=responses` or pass `--wire-api responses` for the base model, otherwise the
call comes back blank and the review fails loud. Chat is the default and fits the other models.

The CLI loads a `.env` from the working directory at startup, so a project can set its provider
config once instead of exporting it every session. A value already exported in the shell wins
over the file, and a missing file is fine. The auto-load is a CLI convenience, so importing the
library directly does not read `.env`.

Useful flags:

- `--provider anthropic|openai|litellm`
- `--model <model>`
- `--api-key <key>`
- `--api-base <url>`
- `--wire-api chat|responses`
- `--retries <n>`
- `--timeout <seconds>`

### Cross-Model Review

A single-model run needs only the setup above. For stronger verification, both review paths name
three model roles, finder, challenger, and judge. The finder finds, the challenger refutes, the
judge confirms before a deletion. Each role defaults to the base `--model`. Put a different vendor
in any seat for cross-model review, where uncorrelated blind spots catch what one model misses, and
a deletion needs the judge to be a distinct model from the challenger so no lone skeptic drops a
real finding. With the judge not distinct, nothing is refuted, the recall-safe default.

Each role takes a full backend, the same five fields as the base, every one unset by default:
`CYBERJURY_<ROLE>_PROVIDER`, `_MODEL`, `_API_KEY`, `_API_BASE`, `_WIRE_API`, with `<ROLE>` one of
`FINDER`, `CHALLENGER`, `JUDGE`, and the matching `--<role>-provider`, `--<role>-model`,
`--<role>-api-key`, `--<role>-api-base`, `--<role>-wire-api` flags. An unset field inherits the
base, so override only the seat you want to change, and a role that switches vendor brings its own
key since the base key belongs to the base vendor. For example a Claude base finder challenged by
GPT and confirmed by Claude:

```bash
export CYBERJURY_CHALLENGER_PROVIDER=openai
export CYBERJURY_CHALLENGER_MODEL=...             # a GPT model, the skeptic
export CYBERJURY_CHALLENGER_API_KEY=...
export CYBERJURY_CHALLENGER_WIRE_API=responses    # the GPT-5 reasoning models speak Responses
export CYBERJURY_JUDGE_MODEL=...                  # a Claude model, the confirmer, distinct from the challenger
```

The same `CYBERJURY_FINDER_*` / `CYBERJURY_CHALLENGER_*` / `CYBERJURY_JUDGE_*` and the matching
`--finder-* / --challenger-* / --judge-*` flags work on both `review diff` and `review repository`.
Note that `review repository --run` finds with one model, the finder, and a seat that runs on the
subscription supplies its own review, so it ignores that seat's backend flags while the others
still apply.

## Diff Review

Diff Review is the fast coded path. It audits a unified diff with either a standard
single model call or an adversarial Finder, Challenger, and Judge pass.

```text
cyberjury review diff [--file <file> | --git-range <range>] [options]
```

```bash
# review a diff file
cyberjury review diff --file changes.diff

# review a git range
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD

# review stdin
git diff HEAD~1 | cyberjury review diff

# use adversarial mode for extra recall on subtle cross-file logic
cyberjury review diff --file changes.diff --mode adversarial

# emit SARIF and fail on HIGH or CRITICAL findings
cyberjury review diff --file changes.diff --format sarif --fail-on high

# review with no provider key, riding your Claude Code subscription
cyberjury review diff --file changes.diff --executor subscription

# carry fetched source provenance into the report, see Fetch Verified Source
cyberjury review diff --file changes.diff --source-meta target/cyberjury-source.json

# run adversarial mode with a keyless Claude finder and judge plus an OpenAI challenger on its own key
cyberjury review diff --file changes.diff --mode adversarial \
  --challenger-provider openai --challenger-api-key "$OPENAI_API_KEY"
```

Diff Review takes the same `--executor auto|api|subscription` as Repository Review, see Review
Strategy. The default `auto` calls the provider when a seat has a key and falls back to your
Claude Code subscription for a keyless Anthropic seat. Unlike the repository agent, the diff agent
answers from the prompt and does not browse files on its own.

When a repository source root is available, through `--git-range` or `--repository`, diff review
grounds the prompt with facts from that checkout. The selected domain's facts backend extracts call
and import structure, then the prompt receives current source around each changed hunk, same file
helper definitions found through the facts graph, and a short source prefix for each changed source
file. A backend failure is a failed review step. `--file` and stdin without `--repository` keep
their original behavior and review only the supplied diff.
Repository backed diff review also runs candidate findings through the same source grounded
verifier used by whole-repository review before reporting them. Verification failure keeps the
candidate and marks the review degraded.

`cyberjury review diff --dry-run` uses a mock provider and a built-in demo diff, so it needs
no API key.

## Repository Review

Repository Review is the recall-first path for whole repositories. A whole codebase is too large
for one useful model call, so the tool creates a workspace, builds a unit worklist, and
reviews focused units instead of doing one shallow pass.

```text
cyberjury review repository <repository> (--scaffold | --run | --finalize | --gate) [--invariants <file>] [options]
```

### From an Agent

In Claude Code or Codex, one command runs the whole review, scaffold, fan-out, finalize, and gate:

```text
/cyberjury-review <target> [--coded] [--domain auto|web|evm] [--effort low|medium|high] [--invariants <file>] [--workspace <path>]
```

`--coded` picks the engine and the model backend together. Without it, the default, a
repository is reviewed by the agent fan-out on your Claude Code subscription, so your `.env`
provider config is not used. With it, Cyberjury's own coded engine reviews the repository through `--run` on
`--executor api`, so your `.env` provider config is used throughout. The slash command
announces the choice on its first line, so which backend ran is never a guess. In the default
fan-out mode the agent maps the attack surface, fills the authorization model, runs one focused
sub-review per unit, records findings, and leaves deterministic post-processing to code. PoCs
run only against sandbox or dev environments, never production.

### From the CLI

The slash command runs these four steps for you. Only the second, the find step, changes: `--run`
drives the coded engine below, or an agent fans out over the units, the default when the slash
command runs it. Scaffold, finalize, and gate are the same either way. Run them yourself for a
headless or CI review, or to drive the coded engine without an agent:

```bash
cyberjury review repository /path/to/repository --scaffold     # build the workspace and unit worklist
cyberjury review repository /path/to/repository --run          # coded multi-pass review to convergence
cyberjury review repository /path/to/repository --finalize     # dedup candidates, verify, write findings
cyberjury review repository /path/to/repository --gate         # check coverage, non-zero until it is met
```

`--run` reviews every unit each pass, cycles lenses until convergence, verifies inline, and writes
the confirmed `findings/`, so on the coded path `--finalize` is optional. See Review Strategy for
how each unit is reviewed. `--finalize` deduplicates and verifies the candidates an agent fan-out
proposed, the step the agent path needs, records refuted candidates in `_refuted.md` and PoC
reconciliation in `_pocs.md`, and writes the confirmed `findings/` and the ranked `findings.json`. `--gate` fails until the workspace has an enumerated
surface, reviewed units, and calibrated candidates. Add `--strict-coverage` to also fail when a
source file is owned by no unit, instead of noting it. Add `--poc` on finalize to write a runnable
PoC for each confirmed finding when the domain binds a PoC backend. Where the domain runs safely and
locally it also runs the PoC, such as the EVM Foundry reproducer, which compiles and runs the test
with no fork, no broadcast, and no key. A web PoC is written for a human to run against a sandbox or
dev host, never automatically, since it needs a live server and credentials. It is off by default
since it calls a model per finding, and for EVM also compiles and runs one. When the run toolchain
is absent the PoC is written but not run, with a note on how to run it by hand, rather than failing.
It only adds evidence, so a finding is kept whether or not its PoC reproduces.

### The Workspace

The workspace is private and holds everything the review read, wrote, and can be resumed from:

```text
inventory/                attack surface, authorization model, seeded entrypoints, severity rubric
units/                    one review unit per candidate entrypoint
candidates/               agent proposals, one write-up per candidate finding
findings/                 confirmed findings, written by --run or finalize
pocs/                     runnable PoCs, when available
findings.json             ranked machine-readable findings
METHODOLOGY.md            full review process
_stack.md                 detected stack notes
_vulnerabilities.md       the vulnerability classes this review was given
_false_positive_traps.md  how a static read misjudges, both over-reporting and wrongly refuting
_refuted.md               refuted candidates and why
_pocs.md                  PoC reconciliation, planned versus delivered
_run.json                 the coded run's coverage, failure state, convergence, and spend
_finalize.json            what finalize did, its completeness counts and spend
_union.json               the candidate pool a resumed --run reads instead of reviewing again
_verified.json            the verdicts a resumed verification skips, an unfinished one left out
_timeline.json            elapsed per pipeline stage, across the separate commands
.cyberjury-workspace      the marker that stops --fresh clearing a directory it did not create
```

A review grounded by a facts backend adds `_facts.md`, `_facts_by_file.json`, and whichever of
`_facts_units.json` and `_facts_graph.json` its backend emits, plus `_facts_error.txt` when
extraction fails rather than failing the run. A review carrying fetched-source provenance adds
`_target.md`.

`_run.json` and `_finalize.json` are what the gate reads to decide whether a review finished, and
what a two-arm backtest reads to compare cost, so treat them as results rather than as debug output.

To seed intent invariants, the business rules only you know that a static read cannot infer, keep
an invariants file with the repository and pass `--invariants <path>` to scaffold. It imports the
file into `inventory/_invariants.md` and never overwrites an edited one, so clear the workspace
with `--fresh` to replace it. Write one rule per line as `only <who> may <operation> <asset>,
under <condition>`. Leave it out to seed nothing.

### Review Strategy

A `--run` chooses how each unit is reviewed:

- `--executor auto` is the default. Each seat, the finder and the skeptic, calls the
  provider when it has a reachable key and falls back to a headless `claude -p`
  subscription agent for a keyless Anthropic seat, so a keyless run works with no provider
  key. A keyless non-Anthropic seat, such as an OpenAI finder with no key, is a loud error,
  it has no subscription to fall back to. This is what lets a Claude finder ride your
  subscription while an OpenAI challenger uses its own key.
- `--executor api` makes one model call per unit and requires a key, a missing key is a loud
  startup error, the same point as auto.
- `--executor subscription` always runs each unit and its verification as a headless
  `claude -p` agent that reads and traces the files itself with read-only tools, using your
  Claude Code access and no provider key. Use it when you want a tool-using agent rather
  than a single grounded call even where a key is present.

Facts grounding is not a choice. A domain that binds a facts backend replaces the path-name guess
about a file's downstream with a tool-extracted graph: Slither gives the EVM domain its call graph,
storage layout, and read and write sets, and a tree-sitter backend recovers call and import edges
from syntax for Python, JavaScript, TypeScript, and Go, then expands each entrypoint along its real
import edges. Both domains read the same way, on for every review at every effort tier, with no flag
to turn it off. So a backend that cannot run, or an EVM target that does not compile, fails the
review rather than quietly producing one without cross-function units, since a review that covers
less without saying so is a reduced review reported as a whole one. A single file tree-sitter cannot
parse is still skipped on its own, because that costs one file rather than the whole graph.

The subscription backend runs one `claude -p` per call by default, since it spends fewer input
tokens than holding a session open. Every call repeats the same Claude Code preamble, so the
prompt cache serves it at a tenth of the input price. A new Claude Agent SDK session instead pays
a quarter above the full input price to write that preamble again, and every later turn in a
session also pays to read the turns before it. Set `CYBERJURY_CLAUDE_TRANSPORT=sdk` for a
persistent session, which trades that cost for one Claude Code startup per session instead of per
call. The SDK ships in the base install either way. An unknown transport value fails at startup
rather than silently falling back.

`--effort low|medium|high` is the one depth dial, each level fixing two things at once:

| `--effort` | Shots per lens | Skeptics to drop a candidate |
|:---|:---|:---|
| `low` | 1 | 1 |
| `medium` (default) | 2 | 1 |
| `high` | 3 | 2 |

`--min-lens-shots` and `--votes` override either column.

On the subscription backend the concurrency within a pass defaults to 2 so a wide fan-out does not
trip the shared rate cap, and to 6 on an API key, override it with `--concurrency`.

Set a distinct `--judge-model`, the confirmer, from the challenger to enable cross-model
verification. The challenger refutes a finding and the judge must agree before it is dropped,
so a deletion needs two models. With the judge not distinct from the challenger, the verify
stage refutes nothing, the recall-safe default.

## Data Boundary

The tool sends code-derived content to the model provider you configure, so know what
leaves the machine before reviewing a proprietary repository:

- Diff Review on the `api` row sends the unified diff under review. On the `subscription`
  row it sends the diff in the `claude -p` prompt through your Claude Code account, and the
  diff agent uses no file tools, so only the diff text leaves the machine, not local files.
- Under the default `--executor auto`, each seat follows the `api` row when it has a key
  and the `subscription` row when it falls back to your Claude Code subscription, so what
  leaves the machine is decided per seat by whether that seat has a key.
- Repository Review with `--executor api` sends bounded source snippets, the detected stack
  notes, the vulnerability guidance, and the findings.
- Verification with `--executor api` sends the cited source file and the finding
  details. On the `subscription` row, Claude Code receives the finding details and reads
  the code itself through its read-only tools.
- A repository seat on the `subscription` row does not use the configured provider key. It runs
  Claude Code with read-only file tools, and Claude Code may send prompts and the code it
  reads through your Claude Code account, so the code does not stay local. The diff agent is
  narrower, it reads no files and sees only the diff in the prompt.

A custom `--api-base` or a LiteLLM proxy becomes part of the trust boundary, so the data
above also reaches that gateway. Prefer the `CYBERJURY_API_KEY` environment variable over
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
cyberjury review repository ./target --domain evm --run
```

`fetch source` queries the Etherscan V2 API, which serves every supported chain from one
endpoint with one key, so a single `CYBERJURY_ETHERSCAN_API_KEY` covers `arbitrum`, `bsc`,
`eth`, and `polygon`, chosen with `--chain`. Pass the key with `--api-key` or that
environment variable.
It writes the reconstructed source tree and a `cyberjury-source.json` recording the chain,
address, compiler, and source URL, and it fails loud on an unverified or malformed response.
It never runs a review on its own. Point Diff Review at that metadata file with
`--source-meta` to carry the provenance into the report.

## Supported Knowledge

The tool selects a review domain with `--domain`, `auto` by default. The `web` domain is
the default for application code. The `evm` domain reviews Solidity smart contracts for
classes such as reentrancy, access control, oracle manipulation, accounting precision, and
signature replay.

Current guide coverage in the web domain includes:

- Python: Django, Flask, FastAPI, Celery
- Go: Gin, Echo
- JavaScript and TypeScript: Express, NestJS
- Protocols: OAuth, OIDC, GraphQL, and MCP

The evm domain ships a Solidity guide and the smart contract vulnerability classes above.
Unguided stacks still work, but the agent relies more on general methodology and model
knowledge.

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
  `cyberjury/domains/<domain>/knowledge/vulnerabilities/<id>.md`
- Language guide:
  `cyberjury/domains/<domain>/knowledge/guides/languages/<language>.md`
- Framework guide:
  `cyberjury/domains/<domain>/knowledge/guides/frameworks/<language>/<framework>.md`
- Protocol guide:
  `cyberjury/domains/<domain>/knowledge/guides/protocols/<protocol>.md`

Keep frontmatter and detection signals data-driven. Avoid adding language, framework, or
vulnerability-specific detection logic to Python unless the engine itself needs a generic
capability.

## Development

Run tests in a virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest
```
