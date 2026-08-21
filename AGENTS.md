# AGENTS.md

Project instructions for coding agents. Codex reads `AGENTS.md` directly. Claude Code
reads it through the `@AGENTS.md` import in `CLAUDE.md`.

An AI-assisted security review tool for code diffs and repositories. Diff Review
is the coded path. Repository Review is the fan-out path where code owns the deterministic
orchestration and agents or model calls provide per-unit judgment.

## Non-Negotiable Invariants

1. **Knowledge is data, the engine is generic.** Security knowledge belongs in each
   profile's `knowledge/` markdown under `cyberjury/profiles/<profile>/` and in prompts that
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
  guides, `detection.yaml`, the mandate, the rubric, role rounds, reviewer or verifier behavior,
  and any change of a default.
- Observability fields, report formatting, and a new flag that leaves the default behavior alone
  do not require this measurement.
- Judge such a change by a two arm backtest, baseline against changed, following
  `evals/docs/detection-quality-backtest.md` under Comparing Two Configurations. Recall is the red
  line and decides first. Cost has no threshold that rejects a change on its own, but it is always
  recorded.
- State plainly which numbers were measured and which were not. An unmeasured claim about recall
  or cost is worse than saying the measurement is missing, because it reads like a result.
- Measure detection quality on real targets, not synthetic golden sets, and never fit the
  benchmark, see invariant 5.
- Model quality dominates and mode comes second, so put the strongest model in first. See the
  README under Model and Mode Guidance for picking the mode.
- Keep false positives down with the do-not-report guidance, deterministic filters, and
  verification, not by weakening the finding criteria.

## Architecture

### Profiles

- A profile bundles one body of security knowledge under its own content root,
  `cyberjury/profiles/<name>/`, holding `knowledge/`, `playbook/`, and `detection.yaml`.
- `profiles/base.py` defines `ReviewProfile`, the `ContentPaths` layout resolver, and the shared PoC
  backend and factory contracts. The shared facts contract and extraction failure semantics live in
  `cyberjury/review/facts.py`.
  Definition graph validation and unit planning live in `cyberjury/review/definitions.py`.
  Repository facts artifact persistence lives in `cyberjury/review/storage.py`.
  Verified source acquisition lives in `cyberjury/sources/` and the CLI, outside the review engine.
- `profiles/registry.py` is the one place that lists the profiles. `web` covers Web
  Application Security and is the default. `evm` covers EVM Application Security for
  Solidity smart contracts. `resolve_profile` maps a `--profile` choice or `auto`
  detection to a `ReviewProfile`.
- The engine reads knowledge and the diff prompt blocks from the selected
  profile, so a new profile is a content directory plus a registry entry, not an engine
  change.
- Vulnerability class selection happens for each judgment unit. Diff batches select from the
  patch and grounded repository context. Repository units select from their source and extracted
  facts. Both paths use the shared selector and keep every class with a matching selection hint.
  Relevance ordering controls reading order, never inclusion.
- `cyberjury/resources.py` exposes the web profile's paths as the default constants the
  Diff Review path reads when no profile is selected.

### Knowledge and Detection

- Vulnerability classes live in `cyberjury/profiles/<profile>/knowledge/vulnerabilities/`.
- Language, framework, and protocol guides live in
  `cyberjury/profiles/<profile>/knowledge/guides/`.
- Framework guides belong under their language, for example
  `profiles/web/knowledge/guides/frameworks/python/django.md`, and declare `language:` in
  frontmatter.
- Source extensions, manifests, noise directories, and test conventions live in each
  profile's `detection.yaml`, for example `cyberjury/profiles/web/detection.yaml`.
- Every profile facts package uses the same four stages. `analyzer.py` owns the native tool
  boundary and normalizes native output into typed local analysis. `resolver.py` maps analyzed
  identities and references to repository paths, ranges, and exact dependencies. `graph.py` builds
  and renders the shared `Facts` shape.
  `backend.py` implements `FactsBackend` and coordinates the other three stages. Dependencies
  flow in that order and only the backend coordinates the complete pipeline.
- The web profile uses Tree-sitter to build a call, import, and reference graph. Each language's
  grammar, extensions, module entry conventions, and queries live in
  `profiles/web/facts/queries.yaml`. Adding a language to the Web facts backend is a row there plus
  a grammar package, not a Python facts change. Full profile support still needs detection metadata
  and guide content. Tree-sitter and the grammars ship in the base install, the same as Slither,
  since a backend that grounds by default has to be present by default. They are lazy-imported, so
  the evm path never loads them.
- The evm profile uses Slither for Solidity analysis and adds a Forge PoC seam.
  Slither and web3 ship in the base install, and both are lazy-imported so the web path never
  loads them.
- Both profile backends return the shared Facts shape. Web keeps its declarative Tree-sitter
  queries, while EVM may emit focused `unit_specs`. Repository Review consumes both through
  the generic unit builder rather than importing a domain-specific Unit type.
- `review/context.py` owns the shared grounding envelope. Diff and Repository adapters set
  the source boundary and file list, then convert the context to prompt text at their edge.
- Facts behave the same in every profile: binding a backend is what turns grounding on, every review
  mode grounds, and no flag turns it off. A backend that cannot run, or a target that does not
  compile, fails the review rather than quietly dropping cross-function coverage, since a review
  that covers less without saying so is a reduced review reported as complete, invariant 4. A
  profile is never the exception here, since grounding meaning one thing for web and another for evm
  is not readable.

### Diff Review

- Lives under `cyberjury/review/diff/`.
- `run_diff_review` delegates large diff units to the shared runner, then normalizes categories
  and changed line locations. `audit_diff` exposes the tuple adapter API.
- `diff/reviewer.py` adapts standard and adversarial role calls to diff findings.
- Findings use `cyberjury/finding.py` and render through `cyberjury/report.py`.

### Repository Review

- Lives under `cyberjury/review/repository/` with playbook assets in each profile's `playbook/`.
- `scaffold.py` builds the workspace, stack notes, candidate files, unit files, and
  methodology assets.
- `model.py` builds a language-agnostic repository file map from data-driven detection
  config and guide globs.
- `engine.py` owns the repository workflow. The common stage modules from `model.py` through
  `verify.py` adapt repository input and findings to the shared engine.
- Agents or model-backed reviewers provide per-unit security judgment. Code owns
  determinism, coverage bookkeeping, and failure accounting.

### Shared Review Engine

- `cyberjury/review/engine.py` owns validated review plans, role execution, response validation,
  failure fallback, monotonic accumulation, round scheduling, pending work, convergence, outcome
  extension, and completion semantics for both review paths.
- `cyberjury/review/verification.py` owns shared skeptic and confirmer orchestration.
- `cyberjury/review/vulnerabilities.py` owns the profile knowledge catalog, selection, and category
  normalization primitives.
- Diff and repository modules adapt target input, prompts, finding identity, location rules, and
  lifecycle. They do not reimplement shared judgment semantics.
- Both target directories contain `engine.py`, `model.py`, `context.py`, `prompts.py`,
  `reviewer.py`, `runner.py`, `union.py`, and `verify.py`. Repository Review alone adds
  `scaffold.py` and `gate.py` because only that path owns a persistent workspace.

### Providers and Integrations

- Providers live in `cyberjury/providers/`: Anthropic, OpenAI, mock, retry, and metering.
- JSON extraction lives in `cyberjury/json_parse.py`.
- The CLI entry point is `cyberjury.cli:main`.
- `install-slash-command` copies one profile-agnostic `cyberjury/commands/slash-command.md`
  into both the Claude Code and Codex command directories. The command threads `--profile`
  through, so a single install drives web and evm.

## Agent Workflow

- Read nearby code and tests before changing behavior.
- Keep changes scoped to the requested behavior and the surrounding module boundaries.
- Prefer existing helper APIs and local patterns over new abstractions.
- When changing model-call handling, preserve fail-loud semantics.
- When changing Repository Review, think through scaffold, run, resume, finalize,
  verification, gate, and tests as one workflow.
- When changing output formats, keep text, markdown, JSON, SARIF, and severity levels in sync.
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

### Review

Core workflow:

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

Common settings:

- Set the review depth with the same mode flags as Diff Review:
  `cyberjury review repository <dir> --run --mode adversarial --rounds 3`

## Provider Configuration

- Provider configuration comes from flags or environment, and the CLI loads a
  working directory `.env` at startup so a project can set it once. A value already
  exported in the shell wins over the file:
  `CYBERJURY_PROVIDER`, `CYBERJURY_MODEL`, `CYBERJURY_API_KEY`, `CYBERJURY_API_BASE`,
  `CYBERJURY_WIRE_API`, `CYBERJURY_RETRIES`, and `CYBERJURY_TIMEOUT`.
- Use `CYBERJURY_FINDER_*`, `CYBERJURY_CHALLENGER_*`, and `CYBERJURY_JUDGE_*` for
  role specific backend overrides. See the README for the full model role guidance.
- Keep `.env.example` as the complete operator environment template. It also documents SDK
  provider keys and `CYBERJURY_ETHERSCAN_API_KEY`.

## Contributing Rules

- Add a vulnerability class by adding
  `profiles/<profile>/knowledge/vulnerabilities/<id>.md` and following
  [Vulnerability Classes](docs/knowledge-design.md#vulnerability-classes).
- Add a language guide under `profiles/<profile>/knowledge/guides/languages/<language>.md`.
- Add a framework guide under
  `profiles/<profile>/knowledge/guides/frameworks/<language>/<framework>.md`.
- Add a protocol guide under `profiles/<profile>/knowledge/guides/protocols/<protocol>.md`.
- Follow [Knowledge Design](docs/knowledge-design.md) for guide bodies and example choices, then
  record acceptance evidence with the
  [Knowledge Change Checklist](docs/knowledge-change-checklist.md).
- Keep guide frontmatter, detection signals, entrypoint markers, logic-layer globs, and
  review guidance in the markdown file.
- Add or update tests when behavior changes, especially for failure handling, parsing,
  filtering, gates, and report formats.
- Keep tests under `tests/cyberjury/` or `tests/evals/` and mirror the production owner. Put a
  cross module workflow test with the module that owns its final behavior.
- Name the default test for `module.py` as `test_module.py`. A large module may use a same named
  test directory with files named for stable behaviors.
- Keep fixtures and directly called test factories in the narrowest directory that shares them.
  Use `conftest.py` only for pytest fixtures and hooks.
- Release by bumping `pyproject.toml`, creating a GitHub Release `vX.Y.Z`, and relying
  on OIDC Trusted Publishing to push to PyPI.

## Style Guide

Match the maintainer's prose and code checklist.

### Prose

- No em dash, neither the Unicode em dash nor a spaced double hyphen. Use two sentences, a
  comma, or a colon.
- No semicolons. Use a period or a comma.
- No parentheses. Reword the aside with "such as", "for example", or a comma.
- Few hyphenated words. Prefer open compounds where they read clearly. Keep a hyphen
  where it is part of an identifier, a CLI flag like `--git-range`, a rule id like
  `sql-injection`, a file path, or an established technical term that reads poorly as
  open words.
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
  Use lowercase "diff review" and "repository review" in running text.
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
