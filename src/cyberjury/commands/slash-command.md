---
description: Run a Cyberjury security review of a diff or a repository
argument-hint: <target> [<git-range>] [--concurrency <n>] [--workspace <path>]
---
# Cyberjury Review

<input>
$ARGUMENTS
</input>

## Purpose

Run Cyberjury on the requested target and report the command result. Do not perform an independent
security review in this chat.

## Constraints

- Treat a failed, rate limited, blank, malformed, or nonzero command as a failed review step, not
  as zero findings.
- Use the provider API configuration loaded by the CLI from `.env` or the shell.
- Use only the parsed flags listed below unless the user explicitly requests another supported
  `cyberjury review` flag for the same command path.
- Do not judge, rewrite, suppress, or add findings yourself. Relay Cyberjury output and failure
  details.
- Keep one workspace per repository review and pass the same `--workspace` value to every
  repository step when supplied.

## Input Handling

1. Split `$ARGUMENTS` into positional tokens plus optional flags.
2. Resolve the target:
   - A git range is a positional token containing `..` or `...`, or the value of `--git-range`.
   - For Diff Review, the repository is the value of `--repository`, the other positional path,
     or the current directory when neither is present.
   - Without a git range, the first positional path is the Repository Review target.
3. Collect optional flags and pass each only to the commands that accept it:
   - Diff flags: `--repository <path>`, `--git-range <range>`, `--workspace`, and `--concurrency`.
   - Repository scaffold flags: `--workspace`.
   - Repository run flags: `--workspace` and `--concurrency`.

## Diff Review

Use one command.

For a git range:

```bash
cyberjury review diff --repository <repository> --git-range <range> [diff flags]
```

Diff Review always passes both `--repository` and `--git-range`, whether their values came from
positional tokens, explicit flags, or the current directory default.

After the command:

- Relay the report exactly enough for the user to act.
- If the command exits nonzero, state that the diff review failed or degraded and include the error
  details.

## Repository Review

Use one command.

```bash
cyberjury review repository <target> --run [repository run flags]
```

If this exits nonzero, state that the repository review failed or is incomplete and include the
error details. Do not call the review complete. Re-running `--run` on the same workspace resumes
open units.

Use `--scaffold` separately to inspect the unit plan before model review. Do not edit workspace
files; findings come only from `--run`.

## Response

Summarize the result in this order:

- Commands run.
- Exit status for each step.
- Findings location or printed findings.
- Any failures or degraded review warning.
