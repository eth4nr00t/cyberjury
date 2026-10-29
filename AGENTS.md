# AGENTS.md

Codex reads `AGENTS.md` directly. Claude Code reads it through the `@AGENTS.md` import in `CLAUDE.md`.

## Development

- Write no comments, and write docstrings only where Ruff requires them, each on a single line.
- Improve the general case instead of fitting a benchmark, and change a benchmark or scorer only to make it correct, never to raise a score.
- Run `ruff check .`, `ruff format --check .`, and `pytest -q` before finishing a change.

## Commits

- Commit, push, amend, rebase, or force push only when the user explicitly requests that operation.
- Use a single Conventional Commit subject without a body or trailers.
- Write the subject as `type: concise description` without a parenthesized scope such as `feat(ui): ...`.
- Name the affected area or behavior in the description when it improves clarity.
