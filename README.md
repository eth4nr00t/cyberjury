# Cyberjury

AI-assisted security review for code diffs and repositories.

The tool has two review paths:

- **Diff Review** audits a git range against its repository in one command.
- **Repository Review** fans out across a repository, reviews focused units, and deduplicates
  candidates.

Diff Review is fast and reports findings at post change lines shown in the patch. Every finding keeps
an exact old or new change anchor, so added behavior and removed controls use one scope contract. Each
diff unit is grounded with repository source context while its reportable boundary remains the patch.
Repository Review covers the complete repository as focused units, so a clean Diff Review does not
by itself clear the repository.

The review contract is data. One language-independent security reasoning kernel, one severity
rubric, and the file classification rules live in `src/cyberjury/review/contract/`. Language
support is the Tree-sitter query data in `src/cyberjury/review/syntax/queries.yaml`. A language
without queries is still reviewed from its raw source. Each review records a hash of these files
in `contract.json`.

A Repository Review of a Git work tree covers the tracked files and the untracked files Git does not
ignore. A plain directory is covered completely. Files that are not UTF-8 text, binary, or empty are
listed as skipped in `outcome.json`.

## Quick Review

```bash
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD
cyberjury review repository /path/to/repo
```

Re-running a repository review resumes open work. Use `--fresh` to start a new review session.

## Output and Exit Codes

Review commands print a JSON result and return a process style exit code. `0` means the requested
action completed. Exit code `1` means the run was degraded or incomplete. Every finding the finder
reports is kept, and the review does not run a second model to delete findings.

Diff and repository reviews write `findings.json` and `outcome.json` in the review
attempt workspace.

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
|---|---|
| `OPENAI_API_KEY` | OpenAI key. When it is set the review uses OpenAI. |
| `ANTHROPIC_API_KEY` | Anthropic key, used when no OpenAI key is set. |
| `CYBERJURY_MODEL` | Model name, default `gpt-5.6` for OpenAI and `claude-opus-5` for Anthropic. |
| `CYBERJURY_API_BASE` | Gateway or proxy endpoint for the provider. |

One model finds the issues and also answers the issue grouping question, so use the strongest
model you can.
