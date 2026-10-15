# Cyberjury

AI-assisted security review for code diffs and repositories.

The tool has two review paths:

- **Diff Review** audits a git range against its repository in one command.
- **Repository Review** fans out across a repository, reviews focused units, deduplicates
  candidates, verifies findings, and checks the result with a gate.

Diff Review is fast and reports findings at post change lines shown in the patch. Every finding keeps
an exact old or new change anchor, so added behavior and removed controls use one scope contract. Each
diff unit is grounded with repository source context while its reportable boundary remains the patch.
Repository Review covers the complete repository as focused units, so a clean Diff Review does not
by itself clear the repository.

The review contract is data. Each review profile keeps its security reasoning kernel and severity
rubric under its content directory, for example `src/cyberjury/profiles/web/`. The `web` profile
covers Web Application Security and is the default. Select a profile with `--profile` or let the
tool detect it automatically.

## Quick Review

```bash
cyberjury review diff --repository /path/to/app --git-range origin/main...HEAD
cyberjury review repository /path/to/repo --scaffold
cyberjury review repository /path/to/repo --run
cyberjury review repository /path/to/repo --gate
```

Add `--poc` to repository `--run` only when local proof generation is required.
PoC generation is disabled by default.

Re-running repository `--run` resumes open work. Use `--fresh` to start a new review session.

## Output and Exit Codes

Review commands print a JSON result and return a process style exit code. `0` means the requested
action completed. Exit code `1` means the run was degraded or incomplete, or the gate is unmet.
In machine findings, `candidate` means a finding was retained without an independent verification
vote. `confirmed` requires a completed independent verification vote. A complete review can contain
retained candidates, so completion does not assert that every reported issue was independently
verified.

Diff reviews and repository `--run` commands write `findings.json` and `outcome.json` in the review
attempt workspace.

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

Role specific overrides use `CYBERJURY_FINDER_*`, `CYBERJURY_SKEPTIC_*`, and
`CYBERJURY_CONFIRMER_*`.

## Model Guidance

OpenAI is the default when `OPENAI_API_KEY` or `CYBERJURY_API_KEY` is set. Otherwise Anthropic
is the default, and the default model follows the selected provider. Put the strongest model on
the finder seat. The finder finds, the skeptic refutes, and an independent confirmer must approve a
deletion. Without a confirmer that differs from both the finder and the skeptic, no finding is
deleted. See [.env.example](.env.example) for the full role override matrix.
