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
| `CYBERJURY_BASE_URL` | Gateway or proxy endpoint for the provider, default the provider's own endpoint. |
| `CYBERJURY_CONCURRENCY` | Number of review units or issue link judgments run in parallel, default `8`. |
| `CYBERJURY_STATE_DIR` | Directory that stores each review under `reviews/<review-id>`, default `$XDG_DATA_HOME/cyberjury`, or `~/.local/share/cyberjury` without `XDG_DATA_HOME`. |

## Review

```bash
cyberjury review diff origin/main...HEAD /path/to/app
cyberjury review repository /path/to/repo
```

A repository review of a Git work tree covers the tracked files and the untracked files Git does not ignore, but not the contents of Git submodules. A plain directory is covered completely. Re-running a repository review resumes open work. Use `--fresh` to start a new review session.

## Output

A review stores its results in `reviews/<review-id>` under `CYBERJURY_STATE_DIR`. The findings of each attempt are in `attempts/<attempt>/findings.json`, grouped into `issues` of findings that one code change fixes.

Each stage, review unit, issue link judgment, and attempt produces a `cyberjury.record/v1` JSON record with a `status` (`ok`, `incomplete`, `failed`, `interrupted`, or `running`) and, when it is `failed` or `incomplete`, an `error` with a `code` (`config`, `input`, `busy`, `model`, or `internal`). The review prints progress to stderr as records are written, and prints the stage records and then the attempt record to stdout when it ends.

| Exit Code | Meaning |
| :--- | :--- |
| `0` | The review finished `ok`. |
| `1` | The review ended `incomplete` or failed `busy`. Running it again can finish it. |
| `2` | The review failed with a `config` or `input` error, or its arguments were invalid. Fix the cause, such as a key, permission, or model the provider rejected, before running it again. |
| `3` | The review failed with an `internal` error. Running it again does not fix it. |
| `130` | The review was `interrupted` by the operator. |
| `143` | The review was `interrupted` by SIGTERM. |
