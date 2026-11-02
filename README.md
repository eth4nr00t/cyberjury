# Cyberjury

[![CI](https://github.com/eth4nr00t/cyberjury/actions/workflows/ci.yml/badge.svg)](https://github.com/eth4nr00t/cyberjury/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cyberjury)](https://pypi.org/project/cyberjury/)
[![Python](https://img.shields.io/pypi/pyversions/cyberjury)](https://pypi.org/project/cyberjury/)
[![License](https://img.shields.io/pypi/l/cyberjury)](https://github.com/eth4nr00t/cyberjury/blob/main/LICENSE)
[![Downloads](https://static.pepy.tech/badge/cyberjury)](https://pepy.tech/projects/cyberjury)

AI-assisted security review for code diffs and repositories.

- **Diff review** checks the changes in a Git range, with the repository as context, and anchors each finding to the changed line it concerns. It does not cover code outside the diff, so it is no substitute for a repository review.
- **Repository review** checks a whole repository.

Structural code analysis covers C, C++, Go, Java, JavaScript, Python, Rust, Solidity, TypeScript, and TSX. Files in other languages are still reviewed from their raw source.

## Install

```bash
pip install cyberjury
```

## Configure

All settings come from a `.env` file in the working directory, and an exported shell value overrides the file. Copy [.env.example](https://github.com/eth4nr00t/cyberjury/blob/main/.env.example) to `.env` and fill in `CYBERJURY_API_KEY`, because the example sets every other setting to its default. When you change `CYBERJURY_PROVIDER`, also change `CYBERJURY_BASE_URL` and `CYBERJURY_MODEL`. Clear `CYBERJURY_STATE_DIR` to follow `XDG_DATA_HOME`.

| Setting | Meaning |
| :--- | :--- |
| `CYBERJURY_PROVIDER` | Model provider, `openai` or `anthropic`, default `openai`. |
| `CYBERJURY_API_KEY` | Provider API key, required. |
| `CYBERJURY_BASE_URL` | Provider endpoint, default `https://api.openai.com/v1` for OpenAI and `https://api.anthropic.com` for Anthropic. |
| `CYBERJURY_MODEL` | Model name, default `gpt-6-astra` for OpenAI and `claude-fable-5-1` for Anthropic. |
| `CYBERJURY_CONCURRENCY` | Number of model requests run in parallel, default `8`. |
| `CYBERJURY_STATE_DIR` | Review state directory, default `~/.local/share/cyberjury`, or `$XDG_DATA_HOME/cyberjury` when `XDG_DATA_HOME` is set. |

## Review

```bash
cyberjury review diff origin/main...HEAD /path/to/app
cyberjury review repository /path/to/repo
```

A repository review of a Git work tree covers the tracked files and the untracked files Git does not ignore, but not the contents of Git submodules. A plain directory is covered completely. Running a repository review again resumes open work. Use `--fresh` to start a new review session.

## Output

A review stores its results in `reviews/<review-id>` under `CYBERJURY_STATE_DIR`. The findings of each attempt are in `attempts/<attempt>/findings.json`, which groups findings that one code change fixes into `issues`.

When a review ends, it prints its records to stdout as `cyberjury.record/v1` JSON, with the attempt record last. Each record has a `status` of `ok`, `incomplete`, `failed`, or `interrupted`. A `failed` or `incomplete` record also has an `error` whose `code` is `config`, `input`, `busy`, `model`, or `internal`.

| Exit code | Meaning |
| :--- | :--- |
| `0` | The review finished `ok`. |
| `1` | The review ended `incomplete` or failed with a `busy` or `model` error. Running it again can finish it. |
| `2` | The review failed with a `config` or `input` error, or its arguments were invalid. Running it again works only after the cause is fixed. |
| `3` | The review failed with an `internal` error. Running it again does not fix it. |
| `130` | The review was `interrupted` by SIGINT, such as Ctrl+C. |
| `143` | The review was `interrupted` by SIGTERM. |
