# AGENTS.md

Codex reads `AGENTS.md` directly. Claude Code reads it through the `@AGENTS.md` import in `CLAUDE.md`.

## Development

- Write no comments, and keep each docstring that Ruff requires to a single line.
- Keep persisted schema versions at v1 and change v1 in place.
- Test one supported behavior per test, and delete tests of removed or legacy behavior.
- Write Markdown with one line per paragraph.
- Run `ruff check .`, `ruff format --check .`, and `pytest -q` before finishing a change.

## Commits

- Commit, push, amend, rebase, or force push only when the user explicitly requests that operation.
- Use a single Conventional Commit subject without a body or trailers.
- Write the subject as `type: concise description`.
- Do not use parenthesized scopes such as `feat(ui): ...`.
- Name the affected area or behavior in the description when it improves clarity.
