"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from cyberjury import __version__
from cyberjury.envfile import load_env_file
from cyberjury.providers.base import Message
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderCredentialsError,
    provider_configuration_from_env,
)
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.diff.prepare import prepare_diff_review
from cyberjury.review.prepare import PreparedReview
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.repository.prepare import prepare_repository_review
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
)
from cyberjury.review.result import ReviewResultArtifact, SkippedFile
from cyberjury.review.run import ReviewRun, run_review
from cyberjury.review.seats import (
    DRY_RUN_SEAT,
    ReviewSeats,
    provider_seat_record,
    review_seats,
)
from cyberjury.review.session import ReviewAttempt, ReviewSession
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.target import (
    ResolvedTarget,
    TargetResolutionError,
    materialize_diff_target,
    resolve_diff_target,
    resolve_repository_target,
)
from cyberjury.sources.git import resolve_root
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from cyberjury.telemetry import progress, stage_timer

SLASH_COMMAND_FILE = Path(__file__).parent / "commands" / "slash-command.md"
ERROR_PREFIX = "error: "
_COMMAND_FAILED = " failed: "
_COMMAND_FAILURE = re.compile(rf"^(?:cyberjury|review|install-slash-command){_COMMAND_FAILED}")


def failure_text(line: str) -> str | None:
    """Return the failure message of one line this CLI printed to stderr, or None for any other line."""
    if line.startswith(ERROR_PREFIX):
        return line.removeprefix(ERROR_PREFIX)
    match = _COMMAND_FAILURE.match(line)
    return line[match.end() :] if match else None


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


def _dry_run_response(_system: str, _messages: list[Message]) -> str:
    return json.dumps({"findings": [], "evidence_requests": [], "source_queries": []})


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
    args = None
    try:
        load_env_file()
        parser = _build_parser()
        args = parser.parse_args(argv)
        return _dispatch(args, parser)
    except Exception as exc:
        label = (getattr(args, "command", None) if args is not None else None) or "cyberjury"
        print(f"{label}{_COMMAND_FAILED}{exc}", file=sys.stderr)
        return 1


@dataclass(kw_only=True)
class _AttemptContext:
    args: argparse.Namespace
    session: ReviewSession
    attempt: ReviewAttempt
    providers: ProviderConfiguration
    meter: UsageMeter
    target: ResolvedTarget
    snapshot: SourceSnapshot
    source: SourceSnapshot
    model_calls_recorded: bool = False


def _review_intent(args: argparse.Namespace) -> ReviewIntent:
    target = (
        TargetInput(
            kind="diff",
            repository=str(Path(args.repository).expanduser().resolve()),
            git_range=args.git_range,
        )
        if args.scope == "diff"
        else TargetInput(kind="repository", repository=str(Path(args.directory).expanduser().resolve()))
    )
    return ReviewIntent(target=target)


def _provider_plan(args: argparse.Namespace, configuration: ProviderConfiguration) -> ProviderPlanRecord:
    if args.dry_run:
        return ProviderPlanRecord(retries=None, timeout_seconds=None, seat=provider_seat_record(DRY_RUN_SEAT))
    return ProviderPlanRecord(
        retries=configuration.retries,
        timeout_seconds=configuration.timeout,
        seat=provider_seat_record(configuration.seat),
    )


def _attempt_request(args: argparse.Namespace, configuration: ProviderConfiguration) -> ReviewAttemptRequest:
    concurrency = args.concurrency or DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    return ReviewAttemptRequest(
        engine_version=__version__,
        concurrency=ConcurrencyRecord(review=concurrency),
        dry_run=args.dry_run,
        fresh=args.fresh if args.scope == "repository" else None,
        providers=_provider_plan(args, configuration),
    )


def _initialize_review_attempt(args: argparse.Namespace, *, source_stack: contextlib.ExitStack) -> _AttemptContext:
    configuration = provider_configuration_from_env()
    intent = _review_intent(args)
    request = _attempt_request(args, configuration)
    state_root = Path(args.workspace).expanduser().resolve()
    repository_root = Path(intent.target.repository)
    if intent.target.kind == "diff":
        repository_root = resolve_root(repository_root)
    if state_root == repository_root or state_root.is_relative_to(repository_root):
        raise TargetResolutionError("state root cannot be inside the reviewed repository")
    session = (
        ReviewSession.create(args.workspace, intent)
        if intent.target.kind == "diff"
        else ReviewSession.select_active(
            args.workspace,
            intent,
            reuse=request.fresh is not True,
        )
    )
    attempt = session.start_attempt(request)
    try:
        target = (
            resolve_diff_target(intent.target.repository, intent.target.git_range or "")
            if intent.target.kind == "diff"
            else resolve_repository_target(intent.target.repository)
        )
        attempt.bind_target(target)
        snapshot, source = _acquire_source(target, source_stack)
        attempt.bind_snapshot(snapshot)
        attempt.bind_contract(ContractReceipt.capture())
    except BaseException as exc:
        with contextlib.suppress(BaseException):
            attempt.fail(exc)
        raise
    print(f"Review: {session.workspace.path}", file=sys.stderr)
    print(f"Attempt: {attempt.workspace.attempt_id}", file=sys.stderr)
    return _AttemptContext(
        args=args,
        session=session,
        attempt=attempt,
        providers=configuration,
        meter=UsageMeter(),
        target=target,
        snapshot=snapshot,
        source=source,
    )


def _acquire_source(
    target: ResolvedTarget,
    source_stack: contextlib.ExitStack,
) -> tuple[SourceSnapshot, SourceSnapshot]:
    if target.kind == "diff":
        snapshot = capture_source_snapshot(source_stack.enter_context(materialize_diff_target(target)))
        return snapshot, snapshot
    snapshot = capture_source_snapshot(target.repository_root)
    root = source_stack.enter_context(snapshot.materialize(name=Path(target.repository_root).name))
    return snapshot, SourceSnapshot(root=root, entries=snapshot.entries, snapshot_id=snapshot.snapshot_id)


def _record_model_calls(run: _AttemptContext) -> None:
    if run.model_calls_recorded:
        return
    run.attempt.record_model_calls(run.meter.document())
    run.model_calls_recorded = True


def _report_skipped_files(skipped: tuple[SkippedFile, ...]) -> None:

    def listed(items: list[str]) -> str:
        more = f", and {len(items) - 5} more" if len(items) > 5 else ""
        return ", ".join(items[:5]) + more

    def files(count: int) -> str:
        return f"{count} file" if count == 1 else f"{count} files"

    noise = [item.path for item in skipped if item.reason == "noise"]
    unreviewable = [f"{item.path} ({item.description})" for item in skipped if item.reason != "noise"]
    if noise:
        progress(f"skipped {files(len(noise))} excluded by the noise rules: {listed(noise)}")
    if unreviewable:
        progress(f"skipped {files(len(unreviewable))} without reviewable content: {listed(unreviewable)}")


def _prepare(run: _AttemptContext) -> PreparedReview:
    with stage_timer("prepare"):
        prepared = (
            prepare_diff_review(run.target.patch.text, run.source)
            if run.target.kind == "diff"
            else prepare_repository_review(run.source)
        )
    run.attempt.bind_facts(prepared.facts)
    run.attempt.bind_unit_plan(prepared.unit_plan)
    run.attempt.bind_grounding(prepared.grounding)
    _report_skipped_files(prepared.skipped_files)
    return prepared


def _run_review(run: _AttemptContext, prepared: PreparedReview, seats: ReviewSeats) -> int:
    request = run.attempt.request
    diff = run.target.kind == "diff"
    with stage_timer("review"):
        result = run_review(
            prepared,
            target=DIFF_TARGET if diff else REPOSITORY_TARGET,
            seats=seats,
            concurrency=request.concurrency.review,
            work=None if diff else run.session.workspace.path / "work" / Path(run.target.repository_root).name,
            on_unit=lambda done, total, secs: progress(f"unit {done}/{total} ({secs}s)"),
        )
    run.attempt.bind_result(result.findings, result.outcome_artifact)
    return _report_review(run, result)


def _report_review(run: _AttemptContext, result: ReviewRun) -> int:
    outcome = result.outcome
    for error in result.issue_link_errors:
        print(f"NOTE: {error}. Those findings stay in separate issues", file=sys.stderr)
    print(
        f"{len(outcome.findings)} findings in {len(result.findings.issues)} issues: "
        + ", ".join(f"{count} {severity}" for severity, count in result.findings.summary),
        file=sys.stderr,
    )
    for failure in outcome.failures:
        paths = ", ".join(failure.paths[:3])
        more = f", and {len(failure.paths) - 3} more" if len(failure.paths) > 3 else ""
        print(
            f"{ERROR_PREFIX}review unit {failure.index}/{failure.total} failed for {paths}{more}: {failure.reason}",
            file=sys.stderr,
        )
    if outcome.failure_reason:
        print(f"{ERROR_PREFIX}{outcome.failure_reason}", file=sys.stderr)
    if not outcome.complete:
        print(
            f"{ERROR_PREFIX}the review is incomplete because grounding or judgment did not complete, "
            "so the result is not a clean pass. Re-run to retry open work",
            file=sys.stderr,
        )
    print(f"Findings written to {run.attempt.workspace.path}/findings.json", file=sys.stderr)
    if run.meter.snapshot()["model_requests"]:
        print(run.meter.summary(), file=sys.stderr)
    machine_result = ReviewResultArtifact(
        review_id=run.attempt.workspace.session_id,
        attempt_id=run.attempt.workspace.attempt_id,
        findings=result.findings,
        outcome=result.outcome_artifact,
    )
    print(json.dumps(machine_result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if outcome.complete else 1


def _execute_review(run: _AttemptContext) -> int:
    prepared = _prepare(run)
    seats = review_seats(
        run.providers,
        meter=run.meter,
        dry_run_provider=MockProvider(responder=_dry_run_response) if run.attempt.request.dry_run else None,
    )
    result = _run_review(run, prepared, seats)
    if not run.snapshot.matches():
        print(
            "NOTE: review source changed while the review was running, so "
            "the result describes the snapshot captured when the review started",
            file=sys.stderr,
        )
    return result


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


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command == "install-slash-command":
        return _cmd_install_slash_command(args)
    if args.command != "review":
        parser.print_help()
        return 1
    with contextlib.ExitStack() as source_stack:
        run = _initialize_review_attempt(args, source_stack=source_stack)
        attempt = run.attempt
        try:
            result = _execute_review(run)
            _record_model_calls(run)
            if result == 0:
                attempt.complete(exit_code=result)
            else:
                attempt.incomplete(exit_code=result)
            return result
        except KeyboardInterrupt:
            with contextlib.suppress(BaseException):
                _record_model_calls(run)
            with contextlib.suppress(BaseException):
                attempt.interrupt()
            raise
        except BaseException as exc:
            with contextlib.suppress(BaseException):
                _record_model_calls(run)
            with contextlib.suppress(BaseException):
                attempt.fail(exc)
            if isinstance(exc, ProviderCredentialsError):
                raise SystemExit(str(exc)) from exc
            raise


if __name__ == "__main__":
    raise SystemExit(main())
