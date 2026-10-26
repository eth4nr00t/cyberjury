# Cyberjury

AI-assisted security review for code diffs and repositories.

The tool has two review paths:

- **Diff Review** audits a git range against its repository in one command.
- **Repository Review** fans out across a repository, reviews focused units, and groups the
  findings into issues.

Diff Review is fast and reports findings at post change lines shown in the patch. Every finding keeps
an exact old or new change anchor, so added behavior and removed controls use one scope contract. Each
diff unit is grounded with repository source context while its reportable boundary remains the patch.
Repository Review covers the complete repository as focused units, so a clean Diff Review does not
by itself clear the repository.

The review contract is data. One language-independent security reasoning kernel, one severity
rubric, and the file classification rules live in `src/cyberjury/review/contract/`. Language
support is one file per language in `src/cyberjury/review/contract/languages/`. A language
without a file is still reviewed from its raw source. Each review records a hash of these files
in `source/contract.json`.

A Repository Review of a Git work tree covers the tracked files and the untracked files Git does not
ignore, but not the contents of Git submodules. A plain directory is covered completely. Files that
are not UTF-8 text, binary, or empty are listed as skipped in `plan/skipped-files.json`.

## Quick Review

```bash
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD
cyberjury review repository /path/to/repo
```

Re-running a repository review resumes open work. Use `--fresh` to start a new review session.

## Output and Exit Codes

Each review runs the stages `config`, `target`, `session`, `source`, `facts`, `plan`, `grounding`,
`review`, `link`, and `result`. Every stage, every review unit and issue link judgment, and the
attempt itself is one `cyberjury.record/v1` record with the fields `schema`, `id`, `status`,
`started_at`, `duration_seconds`, `metrics`, `attributes`, `artifacts`, and `error`. The status is
`ok`, `incomplete`, `failed`, `skipped`, `interrupted`, or `running`. A `failed` or `incomplete`
record has an `error` with a `code` (`config`, `input`, `model`, or `internal`) and a `message`. A
`skipped` or `interrupted` record names why in its `reason` attribute.

Records are written under the review directory: the stages of an attempt in
`attempts/<attempt>/stages/<stage>.json`, the attempt in `attempts/<attempt>/record.json`, and the
review units and issue links in `review/items/` and `link/items/`. `artifacts` lists the files that
hold a record's output, relative to the review directory. The findings of an attempt are in
`attempts/<attempt>/findings.json`. Stderr prints one line per record as it is written. When the
review ends, stdout prints the stage records and then the attempt record, each exactly as stored. A
review that fails before its review directory exists prints the same records without storing them.

| Exit code | Meaning |
| :--- | :--- |
| `0` | The review finished `ok`. |
| `1` | The review is `incomplete`, or it failed with a `model` or `internal` error. |
| `2` | Invalid arguments, or the review failed with a `config` or `input` error. |
| `130` | The review was interrupted. |

Every finding the finder reports is kept, and the review does not run a second model to delete
findings.

`findings.json` also groups findings into `issues`: findings that one code change fixes. Grouping
never removes a finding, and each finding names its `issue_id`. Findings of one category at the same
file and line form one issue. Other findings form one issue only when their cited source traces the
other's location and the model answers that one code change fixes both.

## Install

Requires Python 3.12 or newer. The base install includes tree-sitter and the grammar packages.

```bash
pip install cyberjury
cyberjury install-slash-command
```

The `cyberjury install-slash-command` command installs `/cyberjury-review` for Claude Code and Codex.

## Configure

All model settings come from a `.env` file in the working directory. An exported shell value wins
over the file. Copy [.env.example](.env.example) to `.env` and fill in what you use:

| Setting | Meaning |
| :--- | :--- |
| `OPENAI_API_KEY` | OpenAI key. When it is set the review uses OpenAI. |
| `ANTHROPIC_API_KEY` | Anthropic key, used when no OpenAI key is set. |
| `CYBERJURY_MODEL` | Model name, default `gpt-5.6` for OpenAI and `claude-opus-5` for Anthropic. |
| `CYBERJURY_API_BASE` | Gateway or proxy endpoint for the provider. |

One model finds the issues and also answers the issue grouping question, so use the strongest
model you can.
