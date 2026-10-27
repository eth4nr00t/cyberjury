"""Command line argument parsing, command dispatch, and the exit code of each review outcome."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import cyberjury
from cyberjury.record import Record
from cyberjury.review.command import ReviewCommand, run_review_command
from cyberjury.review.recorder import TERMINATED
from cyberjury.review.request import TargetInput

UNFINISHED_EXIT = 1
USAGE_EXIT = 2
INTERNAL_EXIT = 3
INTERRUPTED_EXIT = 130
TERMINATED_EXIT = 143


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberjury", description=cyberjury.__doc__, allow_abbrev=False)
    parser.add_argument("--version", action="version", version=f"cyberjury {cyberjury.__version__}")
    sub = parser.add_subparsers(dest="command")
    review = sub.add_parser("review", help="review code for security findings", allow_abbrev=False)
    review_subcommands = review.add_subparsers(dest="scope", metavar="{diff,repository}", required=True)
    diff = review_subcommands.add_parser(
        "diff", help="review the changes in a git range, with its repository as context", allow_abbrev=False
    )
    diff.add_argument("range", help="git range to review, A..B or A...B, e.g. origin/main...HEAD")
    diff.add_argument(
        "path", nargs="?", default=".", help="path inside the git repository, default the current directory"
    )
    repository = review_subcommands.add_parser(
        "repository",
        help="review a whole repository, resuming open work when run again",
        allow_abbrev=False,
    )
    repository.add_argument("path", nargs="?", default=".", help="directory to review, default the current directory")
    repository.add_argument(
        "--fresh", action="store_true", help="start a new review session instead of resuming the active one"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return USAGE_EXIT
    return _exit_code(run_review_command(_review_command(args), stdout=sys.stdout, stderr=sys.stderr))


def _review_command(args: argparse.Namespace) -> ReviewCommand:
    path = str(Path(args.path).expanduser().resolve())
    target = (
        TargetInput(kind="diff", repository=path, git_range=args.range)
        if args.scope == "diff"
        else TargetInput(kind="repository", repository=path)
    )
    return ReviewCommand(
        target=target,
        fresh=args.fresh if args.scope == "repository" else None,
        state_dir=None,
    )


def _exit_code(record: Record) -> int:
    if record.status == "ok":
        return 0
    if record.status == "interrupted":
        return TERMINATED_EXIT if record.attributes.get("reason") == TERMINATED else INTERRUPTED_EXIT
    code = record.error.code if record.error is not None else None
    if record.status == "failed" and code in {"config", "input"}:
        return USAGE_EXIT
    if record.status == "failed" and code == "internal":
        return INTERNAL_EXIT
    return UNFINISHED_EXIT
