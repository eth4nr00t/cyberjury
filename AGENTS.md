# AGENTS.md

Project instructions for coding agents. Codex reads `AGENTS.md` directly. Claude Code
reads it through the `@AGENTS.md` import in `CLAUDE.md`.

An AI-assisted security review tool for code diffs and whole repositories. Diff Review
is the coded path. Repository Review is the fan-out path where code owns the deterministic
orchestration and agents or model calls provide per-unit judgment.

## Non-Negotiable Invariants

1. **Knowledge is data, the engine is generic.** Security knowledge belongs in each
   domain's `knowledge/` markdown under `cyberjury/domains/<domain>/` and in prompts that
   reference it. Do not hardcode language, framework, or vulnerability-specific detection
   logic in Python. Adding a stack or vulnerability class should usually be a data change.
2. **Recall is the first red line.** The priority order is recall, then false-positive
   rate, then blind-run stability. A missed real, exploitable issue is the worst
   outcome. A stage after the finder, such as dedup or verification, deletes a candidate
   only on a controlling fact it can read, never on an assumed off-file control.
3. **Findings are real, evidenced, and scoped.** Report only exploitable,
   high-confidence issues with a concrete file location and exploit scenario. No
   location means not reportable. Prioritize high-impact classes such as business
   logic, authorization, IDOR, signature flaws, replay, authentication bypass,
   injection, and mass assignment. Do not report dependency CVEs, style notes, generic
   best practices, speculation, or config-leak-only risks.
4. **Fail loud, never report failure as clean.** A failed, rate-limited, blank,
   malformed, or unparsable model call is a failed review step, not zero findings.
   Diff Review must surface the error. Repository Review must count failed unit reviews,
   preserve candidates when verification cannot complete, and avoid marking incomplete
   work as complete.
5. **Improve the general case, never fit the benchmark.** A change to knowledge,
   prompts, or code earns its place only if it would be written without having seen the
   answer key. Do not encode a benchmark's specific findings, sink names, case
   variables, or fix shapes. Validate a change on a target it was not derived from, the
   benchmark it came from can only sanity-check, never prove. Never adjust a scorer or
   an answer key to raise a score.
6. **PoC verification is safe and human-in-the-loop.** Repository Review PoCs run only
   against sandbox or dev environments. Ask the operator for credentials and test data.
   Never use production systems, real credentials, or destructive actions without
   explicit approval.
7. **English only.** Repository code, comments, docs, prompts, and data are English only.
8. **No proprietary content.** The project is public on GitHub and PyPI. Do not add
   internal, confidential, or proprietary code or data.

## Detection Quality

- A change to the engine, the knowledge, or the prompts is measured before it is defaulted on.
  That covers orchestration, unit slicing and packing, verification logic, vulnerability classes,
  guides, `detection.yaml`, the mandate, the rubric, the lens list, reviewer or verifier behavior,
  and any change of a default.
- Observability fields, report formatting, and a new flag that leaves the default behavior alone
  do not require this measurement.
- Judge such a change by a two arm backtest, baseline against changed, following
  `evals/BACKTEST.md` under Comparing Two Configurations. Recall is the red line and decides
  first. Cost has no threshold that rejects a change on its own, but it is always recorded.
- State plainly which numbers were measured and which were not. An unmeasured claim about recall
  or cost is worse than saying the measurement is missing, because it reads like a result.
- Measure detection quality on real targets, not synthetic golden sets, and never fit the
  benchmark, see invariant 5.
- Model quality dominates and mode comes second, so put the strongest model in first. See the
  README under Model and Mode Guidance for picking the mode.
- Keep false positives down with the do-not-report guidance, deterministic filters, and
  verification, not by weakening the finding criteria.

## Architecture Map

### Domains

- A domain bundles one body of security knowledge under its own content root,
  `cyberjury/domains/<name>/`, holding `knowledge/`, `playbook/`, and `detection.yaml`.
- `domains/base.py` defines `Domain`, the `ContentPaths` layout resolver, and the
  optional `FactsBackend` and `SourceLoader` seams. It imports nothing from `cyberjury`,
  so leaf modules depend on it with no import cycle.
- `domains/registry.py` is the one place that lists the domains. `web` is the default,
  `evm` reviews Solidity smart contracts. `resolve_domain` maps a `--domain` choice or
  `auto` detection to a `Domain`.
- The engine reads knowledge, pass lenses, and the diff prompt blocks from the selected
  domain, so a new domain is a content directory plus a registry entry, not an engine
  change.
- `cyberjury/resources.py` exposes the web domain's paths as the default constants the
  Diff Review path reads when no domain is selected.

### Knowledge and Detection

- Vulnerability classes live in `cyberjury/domains/<domain>/knowledge/vulnerabilities/`.
- Language, framework, and protocol guides live in
  `cyberjury/domains/<domain>/knowledge/guides/`.
- Framework guides belong under their language, for example
  `domains/web/knowledge/guides/frameworks/python/django.md`, and declare `language:` in
  frontmatter.
- Source extensions, manifests, noise directories, and test conventions live in each
  domain's `detection.yaml`, for example `cyberjury/domains/web/detection.yaml`.
- The web domain adds its own `facts/` package, a tree-sitter call and import graph. The
  per-language queries live in `domains/web/facts/queries.yaml`, so adding a language is a row
  there plus a grammar package, not a code change. tree-sitter and the grammars ship in the base
  install, the same as Slither, since a backend that grounds by default has to be present by
  default. They are lazy-imported, so the evm path never loads them.
- The evm domain adds a `facts/` package, a Slither call-graph backend and a Forge PoC seam.
  Slither and web3 ship in the base install, and both are lazy-imported so the web path never
  loads them.
- Facts behave the same in every domain: binding a backend is what turns grounding on, every effort
  tier grounds, and no flag turns it off. A backend that cannot run, or a target that does not
  compile, fails the review rather than quietly dropping cross-function coverage, since a review
  that covers less without saying so is a reduced review reported as a whole one, invariant 4. A
  domain is never the exception here, since grounding meaning one thing for web and another for evm
  is not readable.

### Diff Review

- Lives under `cyberjury/review/diff/`.
- `audit_diff` chunks large diffs, runs the selected engine, normalizes categories, and
  applies the deterministic false-positive filter.
- `AuditRunner` is the standard single-call engine.
- `AdversarialAuditRunner` runs Finder, Challenger, and Judge passes for higher recall.
- Findings use `cyberjury/finding.py` and render through `cyberjury/report.py`.

### Repository Review

- Lives under `cyberjury/review/repository/` with playbook assets in each domain's `playbook/`.
- `scaffold.py` builds the workspace, stack notes, candidate files, unit files, and
  methodology assets.
- `model.py` builds a language-agnostic repository file map from data-driven detection
  config and guide globs.
- `engine.py`, `pass_loop.py`, `union.py`, and `verifier.py` own the coded `--run`,
  `--finalize`, resume, dedup, verification, and gate-facing output.
- Agents or model-backed reviewers provide per-unit security judgment. Code owns
  determinism, coverage bookkeeping, and failure accounting.

### Providers and Integrations

- Providers live in `cyberjury/providers/`: Anthropic, OpenAI, LiteLLM, mock, retry, and the
  `claude_agent` subscription transport. `claude_agent` holds the shared `claude -p` runner and
  `ClaudeAgentProvider`, the keyless backend both review paths use, see invariant 6 and the
  `--executor` seat resolution in the CLI.
- JSON extraction lives in `cyberjury/json_parse.py`.
- The CLI entry point is `cyberjury.cli:main`.
- `install-slash-command` copies one domain-agnostic `cyberjury/playbook/slash-command.md`
  into both the Claude Code and Codex command directories. The command threads `--domain`
  through, so a single install drives web and evm.

## Agent Workflow

- Read nearby code and tests before changing behavior.
- Keep changes scoped to the requested behavior and the surrounding module boundaries.
- Prefer existing helper APIs and local patterns over new abstractions.
- When changing model-call handling, preserve fail-loud semantics.
- When changing Repository Review, think through scaffold, run, resume, finalize,
  verification, gate, and tests as one workflow.
- When changing output formats, keep text, markdown, JSON, SARIF, and severity gates in
  sync.
- Do not move security knowledge from markdown data into Python logic.
- Do not delete or overwrite user changes. If the worktree is dirty, work around
  unrelated changes and mention relevant conflicts.

## Commands

### Development

- Run tests in a virtual environment:

  ```bash
  python -m venv .venv
  . .venv/bin/activate
  pip install -e ".[dev]"
  pytest
  ```

- Lint and format with Ruff, the configured line length and rule set live in `pyproject.toml`:

  ```bash
  ruff check .
  ruff format .
  ```

- Enable the commit hook once per clone, so a commit formats and lints before CI checks it:

  ```bash
  pre-commit install
  ```

- Install slash command:
  `cyberjury install-slash-command`

### Review Commands

- Review a diff:
  `cyberjury review diff --file changes.diff`
- Scaffold Repository Review:
  `cyberjury review repository <dir> --scaffold`
- Run Repository Review:
  `cyberjury review repository <dir> --run`
- Finalize Repository Review:
  `cyberjury review repository <dir> --finalize`
- Check Repository Review gate:
  `cyberjury review repository <dir> --gate`

### Review Options

- Choose the backend, running it yourself is cheapest on the keyless subscription, which
  auto lowers concurrency so a wide fan-out does not trip its rate cap:
  `cyberjury review repository <dir> --run --executor subscription`
- Set the review depth, low is one lens shot, medium is the default two, high is three
  shots plus a stricter majority of two skeptics to drop a candidate:
  `cyberjury review repository <dir> --run --effort high`
- Write a runnable PoC per confirmed finding on finalize, off by default since it calls a model
  per finding. The evm domain compiles and runs it locally under Foundry, the web domain writes it
  for a human to run against a sandbox:
  `cyberjury review repository <dir> --finalize --poc`

## Provider Configuration

- Provider configuration comes from flags or environment, and the CLI loads a
  working directory `.env` at startup so a project can set it once. A value already
  exported in the shell wins over the file:
  `CYBERJURY_PROVIDER`, `CYBERJURY_MODEL`, `CYBERJURY_API_KEY`, `CYBERJURY_API_BASE`,
  `CYBERJURY_WIRE_API`, `CYBERJURY_RETRIES`, and `CYBERJURY_TIMEOUT`.
- Use `CYBERJURY_FINDER_*`, `CYBERJURY_CHALLENGER_*`, and `CYBERJURY_JUDGE_*` for
  role specific backend overrides. See the README for the full model role guidance.
- Keep `.env.example` as the complete operator environment template. It also documents SDK
  provider keys, Claude Code transport settings, and `CYBERJURY_ETHERSCAN_API_KEY`.

## Contributing Rules

- Add a vulnerability class by adding
  `domains/<domain>/knowledge/vulnerabilities/<id>.md` with frontmatter for title,
  impact, tags, and triggers, plus vulnerable and secure examples.
- Add a language, framework, or protocol guide under
  `domains/<domain>/knowledge/guides/` with detection signals, entrypoint markers,
  logic-layer globs, and review guidance.
- Add or update tests when behavior changes, especially for failure handling, parsing,
  filtering, gates, and report formats.
- Release by bumping `pyproject.toml`, creating a GitHub Release `vX.Y.Z`, and relying
  on OIDC Trusted Publishing to push to PyPI.

## Style Guide

Match the maintainer's prose and code checklist.

### Prose

- No em dash, neither the Unicode em dash nor a spaced double hyphen. Use two sentences, a
  comma, or a colon.
- No semicolons. Use a period or a comma.
- No parentheses. Reword the aside with "such as", "for example", or a comma.
- Few hyphenated words. Keep the hyphen only where it is part of an identifier, a CLI flag
  like `--git-range`, a rule id like `sql-injection`, or a file path.
- The brand is `Cyberjury` in prose and `cyberjury` in an identifier, and a sentence may open
  with it.
- Keep the capitalized brand to markdown, a prompt, and the places that must tell a consumer
  which tool spoke. Examples are the SARIF driver name and a copy and paste workflow.
- Do not name it inside the code it describes. In this repository a comment, a docstring, or a
  message is already self evident. Say "this process" or "here" instead of the product.
- An identifier stays lowercase: the package, a module path, an import, the CLI command, a path,
  a generated file name, and any literal a reader types. `pip install cyberjury` and
  `python -m cyberjury` do not change.
- `CYBERJURY_` is the environment variable prefix and appears nowhere else.
- Write `Cyberjury` in a host language identifier only where that language wants an initial
  capital, such as `CyberjuryPoC.t.sol` in Solidity.
- Title Case headings. Name the two paths "Diff Review" and "Repository Review" in headings.
  Use lowercase "diff review" and "whole-repository review" in running text.
- English only, no CJK, see invariant 7.
- Semicolons and parentheses stay where they are code, not prose: code fences, inline code, rule
  trigger tokens, a method reference like `complete()`, and the prompt strings sent to the model.

### Code

- One statement per line, no `;` separator.
- No linter or type checker suppression comments. Fix the cause instead, narrow a type with
  `isinstance` or turn an unreachable line into a real guard.
- A comment earns its place only as the why or an invariant. Delete one that restates the code or
  narrates history.
- A docstring states the why in one line. It does not narrate what the next line of code plainly
  does.
- A test needs no comment that repeats its own name.
- Module names are plural for a collection and singular for one concept, a single word where one
  reads cleanly.

### Commit Messages

Commit messages are a single `type: summary` line in the present tense, with few
parentheses. No body and no trailers, so no `Co-Authored-By` or other trailer line.
