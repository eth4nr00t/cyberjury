---
description: Run a Cyberjury security review of a diff or a repository
argument-hint: <target> [<git-range>] [--profile auto|web|evm] [--mode standard|adversarial] [--rounds <n>] [--concurrency <n>] [--workspace <path>]
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
3. Collect optional flags:
   - `--repository <path>` and `--git-range <range>`: form an explicit Diff Review target.
   - `--profile auto|web|evm`: pass to every Cyberjury command when present.
   - `--mode standard|adversarial`: pass to diff review and repository `--run`.
   - `--rounds <n>`: pass to diff review and repository `--run`.
   - `--concurrency <n>`: pass to diff review, repository `--run`, and repository `--finalize`.
   - `--workspace <path>`: pass to every repository command.
4. Build command-specific flag groups:
   - Diff flags: `--repository`, `--git-range`, `--profile`, `--mode`, `--rounds`, and `--concurrency`.
   - Repository scaffold flags: `--profile` and `--workspace`.
   - Repository run flags: `--profile`, `--workspace`, `--mode`, `--rounds`, and `--concurrency`.
   - Repository finalize flags: `--profile`, `--workspace`, and `--concurrency`.
   - Repository gate flags: `--profile` and `--workspace`.
5. Announce the resolved path before running commands:
   `Engine: coded | model: provider API | target: <diff|git-range|repository>`.

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

Summarize the result in this order:

- Commands run.
- Exit status for each step.
- Findings location or printed findings.
- Any failures, degraded review warning, or gate blocker.
