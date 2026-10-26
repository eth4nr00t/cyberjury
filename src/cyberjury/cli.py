"""Command line argument parsing, command dispatch, and the exit code of each review outcome."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cyberjury import __version__
from cyberjury.record import Record
from cyberjury.review.command import ReviewCommand, run_review_command
from cyberjury.review.request import TargetInput
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS

SLASH_COMMAND_FILE = Path(__file__).parent / "commands" / "slash-command.md"
USAGE_EXIT = 2
INTERRUPTED_EXIT = 130


def positive_int(value: str) -> int:
    """Parse a concurrency limit."""
    try:
        parsed = int(value)
    except ValueError:
        parsed = 0
    if parsed < 1:
        raise ValueError("must be a positive integer")
    return parsed


def _default_workspace() -> str:
    return str(Path.home() / ".cyberjury")


def _add_workspace_arg(target) -> None:
    target.add_argument(
        "--workspace",
        default=_default_workspace(),
        help="state root, review sessions are stored under reviews/<review-id>",
    )


def _add_concurrency_arg(target, work: str) -> None:
    target.add_argument(
        "--concurrency",
        type=positive_int,
        default=None,
        help=f"{work} to run in parallel, default {DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency}",
    )


def _add_diff_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True, help="repository containing the reviewed git range")
    parser.add_argument("--git-range", required=True, help="git range to diff, e.g. origin/main...HEAD")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="run the repository-grounded engine with a mock provider and no key",
    )
    _add_concurrency_arg(parser, "diff unit reviews or issue link calls")
    _add_workspace_arg(parser)


def _add_repository_args(repository: argparse.ArgumentParser) -> None:
    repository.add_argument("directory", help="target repository to review")
    repository.add_argument(
        "--fresh", action="store_true", help="start a new review session instead of resuming the active one"
    )
    repository.add_argument(
        "--dry-run",
        action="store_true",
        help="drive the engine with a mock provider and no key, to smoke test the pipeline",
    )
    _add_concurrency_arg(repository, "unit reviews or issue link calls")
    _add_workspace_arg(repository)


def _add_install_args(inst: argparse.ArgumentParser) -> None:
    inst.add_argument(
        "--dir", default=None, help="install into this one directory instead of the agent command directories"
    )
    inst.add_argument(
        "--force", action="store_true", help="overwrite an existing cyberjury-review.md at the destination"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberjury", allow_abbrev=False)
    parser.add_argument("--version", action="version", version=f"cyberjury {__version__}")
    sub = parser.add_subparsers(dest="command")
    review = sub.add_parser("review", help="review code for security findings", allow_abbrev=False)
    review_subcommands = review.add_subparsers(dest="scope", metavar="{diff,repository}", required=True)
    _add_diff_args(
        review_subcommands.add_parser("diff", help="review a git range against its repository", allow_abbrev=False)
    )
    repository = review_subcommands.add_parser(
        "repository",
        help="review a whole repository and resume open work when re-run",
        allow_abbrev=False,
    )
    _add_repository_args(repository)
    inst = sub.add_parser(
        "install-slash-command",
        help="install the /cyberjury-review slash command for Claude Code and Codex",
        allow_abbrev=False,
    )
    _add_install_args(inst)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return USAGE_EXIT
    if args.command == "install-slash-command":
        try:
            return _cmd_install_slash_command(args)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return _review(args)


def _review_command(args: argparse.Namespace) -> ReviewCommand:
    target = (
        TargetInput(
            kind="diff",
            repository=str(Path(args.repository).expanduser().resolve()),
            git_range=args.git_range,
        )
        if args.scope == "diff"
        else TargetInput(kind="repository", repository=str(Path(args.directory).expanduser().resolve()))
    )
    return ReviewCommand(
        target=target,
        workspace=args.workspace,
        dry_run=args.dry_run,
        fresh=args.fresh if args.scope == "repository" else None,
        concurrency=args.concurrency,
    )


def _exit_code(record: Record) -> int:
    if record.status == "ok":
        return 0
    if record.status == "interrupted":
        return INTERRUPTED_EXIT
    if record.status == "failed" and record.error is not None and record.error.code in {"config", "input"}:
        return USAGE_EXIT
    return 1


def _review(args: argparse.Namespace) -> int:
    return _exit_code(run_review_command(_review_command(args), stdout=sys.stdout, stderr=sys.stderr))


def _cmd_install_slash_command(args) -> int:
    content = SLASH_COMMAND_FILE.read_text(encoding="utf-8")
    if args.dir:
        targets = [Path(args.dir)]
    else:
        targets = [Path.home() / ".claude" / "commands", Path.home() / ".codex" / "prompts"]
    installed = 0
    for target_dir in targets:
        dst = target_dir / "cyberjury-review.md"
        if dst.exists() and not args.force:
            print(f"{dst} already exists, keeping it. Re-run with --force to overwrite.", file=sys.stderr)
            continue
        target_dir.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")
        print(f"Installed slash command to {dst}")
        installed += 1
    if installed == 0:
        return 1
    print("Run it with: /cyberjury-review <repository or diff>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
