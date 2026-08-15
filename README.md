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
protocol guides live in Markdown under each review profile's `knowledge/` directory, for
example `cyberjury/profiles/web/knowledge/`, so adding a stack or class is usually a data
change rather than a Python code change. The `web` profile covers Web Application Security
and is the default. The `evm` profile covers EVM Application Security for Solidity smart
contracts. Select one with `--profile` or let the tool detect it automatically.

## Quick Review

```bash
cyberjury review diff --file changes.diff
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD
cyberjury review repository /path/to/repo --scaffold
cyberjury review repository /path/to/repo --run
cyberjury review repository /path/to/repo --finalize
cyberjury review repository /path/to/repo --gate
```

Use `--mode adversarial` for extra recall and `--profile auto` when you want the tool to select
between `web` and `evm`.

## Output and Exit Codes

`--format` accepts `text`, `markdown`, `json`, and `sarif`.
Review commands return a process style exit code. `0` means the requested action completed.
`1` means the run was degraded or incomplete.

## Install

Requires Python 3.12 or newer. The base install includes Slither, Web3, tree-sitter, and the
grammar packages.

```bash
pip install cyberjury
cyberjury install-slash-command
```

`cyberjury install-slash-command` installs `/cyberjury-review` for Claude Code and Codex.

## Configure

The CLI loads `.env` from the working directory. An exported shell value wins over the file.
Set the provider defaults you want, then add role overrides only when you need different seats.
See [.env.example](.env.example) for the full template, including provider keys and
`CYBERJURY_ETHERSCAN_API_KEY`.

```bash
export CYBERJURY_PROVIDER=openai
export CYBERJURY_MODEL=gpt-5.6
export CYBERJURY_RETRIES=2
export CYBERJURY_TIMEOUT=240
```

Role specific overrides use `CYBERJURY_FINDER_*`, `CYBERJURY_CHALLENGER_*`, and
`CYBERJURY_JUDGE_*`.

## Model and Mode Guidance

OpenAI is the default when `OPENAI_API_KEY` or `CYBERJURY_API_KEY` is set. Otherwise Anthropic
is the default, and the default model follows the selected provider. Put the strongest model on
the finder seat. The finder finds, the challenger refutes, and the judge confirms before a
deletion. Use `standard` for one pass through the work. Use `adversarial` when extra recall is
worth the extra role rounds. See [.env.example](.env.example) for the full role override matrix.

## Fetch Verified Source

```bash
cyberjury fetch source --chain eth --address 0x... --out ./target
cyberjury review repository ./target --profile evm --run
```

Use this flow for deployed contracts with verified source. The fetch command reconstructs a local
tree, then you review that tree with Repository Review. The default chain is `bsc`. Supported
chains are `arbitrum`, `bsc`, `eth`, and `polygon`. The fetch command requires an Etherscan API
key through `--api-key` or `CYBERJURY_ETHERSCAN_API_KEY`.

## Supported Knowledge

`web` is the default profile and covers Web Application Security. `evm` covers Solidity smart
contracts. The full knowledge layout and selection rules live in [Knowledge Design](docs/knowledge-design.md).

## Extend Knowledge

Add or change profile knowledge under:

- `cyberjury/profiles/<profile>/knowledge/vulnerabilities/<id>.md`
- `cyberjury/profiles/<profile>/knowledge/guides/languages/<language>.md`
- `cyberjury/profiles/<profile>/knowledge/guides/frameworks/<language>/<framework>.md`
- `cyberjury/profiles/<profile>/knowledge/guides/protocols/<protocol>.md`

Use [Knowledge Change Checklist](docs/knowledge-change-checklist.md) for the acceptance checks.
Use [Engine Design](docs/engine-design.md) for the review engine behavior that consumes the content.
