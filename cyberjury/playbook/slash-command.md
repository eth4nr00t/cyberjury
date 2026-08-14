---
description: Run a Cyberjury security review of a diff or a whole repository
argument-hint: <target> [--profile auto|web|evm] [--mode standard|adversarial] [--rounds <n>] [--concurrency <n>] [--workspace <path>]
---
# Security Review

<task>
Run Cyberjury on the requested target and report the command result. Do not perform an independent
security review in this chat.
</task>

<input>
$ARGUMENTS
</input>

## Operating Rules

- Treat a failed, rate limited, blank, malformed, or nonzero command as a failed review step, not
  as zero findings.
- Use the provider API configuration loaded by the CLI from `.env` or the shell.
- Use only the parsed flags listed below unless the user explicitly requests another CLI flag that
  exists in `cyberjury review`.
- Do not judge, rewrite, suppress, or add findings yourself. Relay Cyberjury output and failure
  details.
- Keep one workspace per repository review and pass the same `--workspace` value to every
  repository step when supplied.

## Parse

1. Split `$ARGUMENTS` into a target plus optional flags. The target is the first positional token
   that is not consumed as a flag value.
2. Classify the target:
   - Diff file: a path ending in `.diff` or `.patch`.
   - Git range: a token containing `..` or `...`.
   - Repository: an existing directory or any other path intended as a source tree.
3. Collect optional flags:
   - `--profile auto|web|evm`: pass to every Cyberjury command when present.
   - `--mode standard|adversarial`: pass to diff review and repository `--run`.
   - `--rounds <n>`: pass to diff review and repository `--run`.
   - `--concurrency <n>`: pass to diff review, repository `--run`, and repository `--finalize`.
   - `--workspace <path>`: pass to every repository command.
4. Build command-specific flag groups:
   - Diff flags: `--profile`, `--mode`, `--rounds`, and `--concurrency`.
   - Repository scaffold flags: `--profile` and `--workspace`.
   - Repository run flags: `--profile`, `--workspace`, `--mode`, `--rounds`, and `--concurrency`.
   - Repository finalize flags: `--profile`, `--workspace`, and `--concurrency`.
   - Repository gate flags: `--profile` and `--workspace`.
5. Announce the resolved path before running commands:
   `Engine: coded | model: provider API | target: <diff|git-range|repository>`.

## Diff Target

Run one command.

```bash
cyberjury review diff --file <diff-file> [diff flags]
```

For a git range, use:

```bash
cyberjury review diff --repository <repository> --git-range <range> [diff flags]
```

If the git range target did not include a repository path, use the current directory for
`--repository`.

After the command:

- Relay the report exactly enough for the user to act.
- If the command exits nonzero, state that the diff review failed or degraded and include the error
  details.

## Repository Target

Run these commands in order on the same workspace.

1. Scaffold:

```bash
cyberjury review repository <target> --scaffold [repository scaffold flags]
```

If scaffold reports previous output, ask before rerunning with `--fresh`.

2. Run:

```bash
cyberjury review repository <target> --run [repository run flags]
```

If this fails, stop and report the failure. Re-running resumes.

3. Finalize:

```bash
cyberjury review repository <target> --finalize [repository finalize flags]
```

If this fails, stop and report the failure. Re-running resumes settled verification.

4. Gate:

```bash
cyberjury review repository <target> --gate [repository gate flags]
```

If gate fails, report each unmet item. Do not call the review complete until gate passes.

## Response

Summarize:

- Commands run.
- Exit status for each step.
- Findings location or printed findings.
- Any failures, degraded review warning, or gate blocker.
