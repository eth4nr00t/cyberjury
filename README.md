# Cyberjury

AI-assisted security review for code diffs and repositories.

The tool has two review paths:

- **Diff Review** audits a git range against its repository in one command.
- **Repository Review** fans out across a repository, reviews focused units, and groups the
  findings into issues.

Diff Review is fast. It reports a finding at a changed line or at repository source the finding
cites, and every finding keeps the exact old or new changed line it is anchored to.
Repository Review covers the complete repository as focused units, so a clean Diff Review does not
by itself clear the repository.

Syntax facts cover C, C++, Go, Java, JavaScript, Python, Rust, Solidity, TypeScript, and TSX. Files
in other languages are still reviewed from their raw source.

A Repository Review of a Git work tree covers the tracked files and the untracked files Git does not
ignore, but not the contents of Git submodules. A plain directory is covered completely. Files that
are not UTF-8 text, binary, empty, or too large are listed as skipped in `plan/skipped-files.json`.

## Quick Review

```bash
cyberjury review diff origin/main...HEAD /path/to/app
cyberjury review repository /path/to/repo
```

Re-running a repository review resumes open work. Use `--fresh` to start a new review session.

## Output and Exit Codes

Each review runs the stages `config`, `target`, `session`, `source`, `facts`, `plan`, `grounding`,
`review`, `link`, and `result`. Every stage, every review unit and issue link judgment, and the
attempt itself is one `cyberjury.record/v1` record with the fields `schema`, `id`, `status`,
`started_at`, `duration_seconds`, `metrics`, `attributes`, `artifacts`, and `error`. The status is
`ok`, `incomplete`, `failed`, `interrupted`, or `running`. A `failed` or `incomplete` record has an
`error` with a `code` (`config`, `input`, `busy`, `model`, or `internal`) and a `message`. `busy`
means another attempt of the same review is running. An `interrupted` record names why in its `reason`
attribute: the operator's interrupt or SIGTERM.

Records are written under the review directory: the stages of an attempt in
`attempts/<attempt>/stages/<stage>.json`, the attempt in `attempts/<attempt>/record.json`, and the
review units and issue links in `review/items/` and `link/items/`. `artifacts` lists the files that
hold a record's output, relative to the review directory. The findings of an attempt are in
`attempts/<attempt>/findings.json`. Model usage metrics are `calls`, `input_tokens`, which includes
the `cached_tokens` read from and the `cache_write_tokens` written to the prompt cache, and
`output_tokens`. Stderr prints one line per record as it is written. A long stage also prints
`running` lines, which are not stored, with its total `items` and the number `finished` so far. When
the review ends, stdout prints the stage records and then the attempt record, each exactly as stored.
A review that fails before its review directory exists prints the same records without storing them.

| Exit code | Meaning |
| :--- | :--- |
| `0` | The review finished `ok`. |
| `1` | The review did not finish, and running it again can: it is `incomplete`, or it failed `busy`. |
| `2` | Invalid arguments, or the review failed with a `config` or `input` error, including a provider that rejects the key, permission, or model. Fix them before running again. |
| `3` | The review failed with an `internal` error, which running it again does not fix. |
| `130` | The operator interrupted the review. |
| `143` | SIGTERM stopped the review. |

`findings.json` also groups findings into `issues`: findings that one code change fixes. Grouping
never removes a finding, and each finding names its `issue_id`. Findings of one category at the same
file and line form one issue. Other findings form one issue only when their cited source traces the
other's location and the model answers that one code change fixes both.

Each finding's `id` changes when the model rewords it. Its `fingerprint` is built only from the file,
line, category, and change anchor, so it stays the same across runs while those stay the same, and
findings that one issue groups by location share it. `unit_complete` is `false` when only review
units that did not finish reported the finding.

## Install

Requires Python 3.12 or newer.

```bash
pip install cyberjury
```

## Configure

All settings come from a `.env` file in the working directory. An exported shell value wins
over the file. Copy [.env.example](.env.example) to `.env` and fill in what you use:

| Setting | Meaning |
| :--- | :--- |
| `OPENAI_API_KEY` | OpenAI key. When it is set the review uses OpenAI. |
| `ANTHROPIC_API_KEY` | Anthropic key, used when no OpenAI key is set. |
| `CYBERJURY_MODEL` | Model name, default `gpt-6-astra` for OpenAI and `claude-fable-5-1` for Anthropic. |
| `CYBERJURY_BASE_URL` | Gateway or proxy endpoint for the provider. |
| `CYBERJURY_CONCURRENCY` | Review units or issue link judgments to run in parallel, default `8`. |
| `CYBERJURY_STATE_DIR` | Directory that stores review sessions under `reviews/<review-id>`, default `$XDG_DATA_HOME/cyberjury`, or `~/.local/share/cyberjury` when it is unset. |

One model finds the issues and also answers the issue grouping question, so use the strongest
model you can.
