# Cyberjury

AI-assisted security review for code diffs and repositories.

- **Diff review** audits a Git range against its repository and anchors each finding to the changed line it concerns.
- **Repository review** reviews a repository in focused units and groups the findings into issues. A clean diff review does not clear the repository.

Structural code analysis covers C, C++, Go, Java, JavaScript, Python, Rust, Solidity, TypeScript, and TSX. Files in other languages are still reviewed from their raw source.

## Install

Requires Python 3.12 or newer.

```bash
pip install cyberjury
```

## Configure

All settings come from a `.env` file in the working directory. An exported shell value wins over the file. Copy [.env.example](.env.example) to `.env` and fill in what you use:

| Setting | Meaning |
| :--- | :--- |
| `OPENAI_API_KEY` | OpenAI key, used whenever it is set. |
| `ANTHROPIC_API_KEY` | Anthropic key, used when no OpenAI key is set. |
| `CYBERJURY_MODEL` | Model name, default `gpt-6-astra` for OpenAI and `claude-fable-5-1` for Anthropic. |
| `CYBERJURY_BASE_URL` | Gateway or proxy endpoint for the provider. |
| `CYBERJURY_CONCURRENCY` | Number of review units or issue link judgments run in parallel, default `8`. |
| `CYBERJURY_STATE_DIR` | Directory holding review sessions under `reviews/<review-id>`, default `$XDG_DATA_HOME/cyberjury` or `~/.local/share/cyberjury`. |

## Review

```bash
cyberjury review diff origin/main...HEAD /path/to/app
cyberjury review repository /path/to/repo
```

A repository review of a Git work tree covers the tracked files and the untracked files Git does not ignore, but not the contents of Git submodules. A plain directory is covered completely. Re-running a repository review resumes open work. Use `--fresh` to start a new review session.

## Output

Each review runs the stages `config`, `target`, `session`, `source`, `facts`, `plan`, `grounding`, `review`, `link`, and `result`. Every stage, every review unit and issue link judgment, and the attempt itself is one `cyberjury.record/v1` record with the fields `schema`, `id`, `status`, `started_at`, `duration_seconds`, `metrics`, `attributes`, `artifacts`, and `error`. The status is `ok`, `incomplete`, `failed`, `interrupted`, or `running`. A `failed` or `incomplete` record has an `error` with a `code` (`config`, `input`, `busy`, `model`, or `internal`) and a `message`. `busy` means another attempt of the same review is running. An `interrupted` record names why in its `reason` attribute: the operator's interrupt or SIGTERM.

Records are written under the review directory: the stages of an attempt in `attempts/<attempt>/stages/<stage>.json`, the attempt in `attempts/<attempt>/record.json`, and the review units and issue links in `review/items/` and `link/items/`. `artifacts` lists the files that hold a record's output, relative to the review directory. Files that are not UTF-8 text, binary, empty, or too large are listed as skipped in `plan/skipped-files.json`.

The findings of an attempt are in `attempts/<attempt>/findings.json`, which also groups them into `issues`: findings that one code change fixes. Grouping never removes a finding, and each finding names its `issue_id`. Findings of one category at the same file and line form one issue. Other findings form one issue only when their cited source traces the other's location and the model answers that one code change fixes both. A finding's `id` changes when the model rewords it. Its `fingerprint` comes only from the file, line, category, and change anchor, so it stays the same across runs, and findings that one issue groups by location share it. `unit_complete` is `false` when only review units that did not finish reported the finding.

Model usage metrics are `calls`, `input_tokens`, which includes the `cached_tokens` read from and the `cache_write_tokens` written to the prompt cache, and `output_tokens`.

The review prints one line per record to stderr as it is written. A long stage also prints `running` lines, which are not stored, with its total `items` and the number `finished` so far. When the review ends, it prints the stage records and then the attempt record to stdout, each exactly as stored. A review that fails before its review directory exists prints the same records without storing them.

| Exit Code | Meaning |
| :--- | :--- |
| `0` | The review finished `ok`. |
| `1` | The review ended `incomplete` or failed `busy`. Running it again can finish it. |
| `2` | The review failed with a `config` or `input` error, or its arguments were invalid. Fix the cause, such as a key, permission, or model the provider rejected, before running it again. |
| `3` | The review failed with an `internal` error. Running it again does not fix it. |
| `130` | The review was `interrupted` by the operator. |
| `143` | The review was `interrupted` by SIGTERM. |
