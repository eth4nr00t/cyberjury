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
support is the Tree-sitter query data in `src/cyberjury/review/syntax/queries.yaml`; a language
without queries is still reviewed from its raw source. Each review records a hash of these files
in `contract.json`.

A Repository Review of a Git work tree covers the tracked files and the untracked files Git does not
ignore. A plain directory is covered completely. Files that are not UTF-8 text, binary, or empty are
listed as skipped in `outcome.json`.

## Quick Review

```bash
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD
cyberjury review repository /path/to/repo --scaffold
cyberjury review repository /path/to/repo --run
```

Re-running repository `--run` resumes open work. Use `--fresh` to start a new review session.

## Output and Exit Codes

Review commands print a JSON result and return a process style exit code. `0` means the requested
action completed. Exit code `1` means the run was degraded or incomplete. Every finding the finder
reports is kept; the review does not run a second model to delete findings.

Diff reviews and repository `--run` commands write `findings.json` and `outcome.json` in the review
attempt workspace.

`findings.json` also groups findings into `issues`: findings that one code change fixes. Grouping
never removes a finding, and each finding names its `issue_id`. Findings of one category at the same
file and line form one issue. Other findings form one issue only when their cited source traces the
other's location and the finder seat answers that one code change fixes both.

## Install

Requires Python 3.12 or newer. The base install includes tree-sitter and the grammar packages.

```bash
pip install cyberjury
cyberjury install-slash-command
```

The `cyberjury install-slash-command` command installs `/cyberjury-review` for Claude Code and Codex.

## Configure

The CLI loads `.env` from the working directory. An exported shell value wins over the file.
Set the provider defaults you want, then add role overrides only when you need different seats.
See [.env.example](.env.example) for the full template, including provider keys.

```bash
export CYBERJURY_PROVIDER=openai
export CYBERJURY_MODEL=gpt-5.6
export CYBERJURY_RETRIES=2
export CYBERJURY_TIMEOUT=240
```

Finder seat overrides use `CYBERJURY_FINDER_*`. API keys, API bases, and the finder seat are read
only from the environment, so no key appears on a command line. The `--provider`, `--model`, `--wire-api`, `--retries`, and
`--timeout` flags override the base seat for one command. OpenAI calls use the Responses API unless
`CYBERJURY_WIRE_API=chat` or `--wire-api chat` selects Chat Completions.

## Model Guidance

OpenAI is the default when `OPENAI_API_KEY` or `CYBERJURY_API_KEY` is set. Otherwise Anthropic
is the default, and the default model follows the selected provider. Put the strongest model on
the finder seat. The finder finds and also answers the issue grouping question. See
[.env.example](.env.example) for the finder seat overrides.
