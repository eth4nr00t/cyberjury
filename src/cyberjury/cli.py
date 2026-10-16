"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
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
from cyberjury.providers.factory import PROVIDERS, nonnegative_int, positive_float
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.review.contract import ContractReceipt
from cyberjury.review.diff.checkout import prepare_diff_review
from cyberjury.review.diff.finder import DIFF_TARGET
from cyberjury.review.prepare import PreparedReview
from cyberjury.review.repository.finder import REPOSITORY_TARGET
from cyberjury.review.repository.scaffold import prepare_repository_review
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    VerificationPolicyRecord,
)
from cyberjury.review.result import ReviewResultArtifact, SkippedFile
from cyberjury.review.run import ReviewRun, run_review
from cyberjury.review.seats import (
    DRY_RUN_SEAT,
    ReviewSeats,
    confirmer_seats,
    provider_seat_id,
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
from cyberjury.review.verification import VerificationReceipt
from cyberjury.sources.git import resolve_root
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from cyberjury.telemetry import progress, stage_timer

SLASH_COMMAND_FILE = Path(__file__).parent / "commands" / "slash-command.md"
_RUN_ONLY_OPTIONS = {
    "provider": "--provider",
    "model": "--model",
    "wire_api": "--wire-api",
    "retries": "--retries",
    "timeout": "--timeout",
    "concurrency": "--concurrency",
    "dry_run": "--dry-run",
}


def positive_int(value: str) -> int:
    """Parse a concurrency limit."""
    parsed = nonnegative_int(value)
    if parsed < 1:
        raise ValueError("must be a positive integer")
    return parsed


def _nonempty_string(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must be a nonempty string")
    return value


def _default_workspace() -> str:
    """Return a user-private path because the workspace holds sensitive review artifacts."""
    return str(Path(os.environ.get("CYBERJURY_HOME") or Path.home() / ".cyberjury"))


def _dry_run_response(_system: str, _messages: list[Message]) -> str:
    """Return the minimum valid Finder reply."""
    return json.dumps({"findings": [], "evidence_requests": [], "source_queries": []})


def _provider_configuration(args: argparse.Namespace) -> ProviderConfiguration:
    """Resolve the environment seats with the base seat and client policy flags applied."""
    return provider_configuration_from_env(
        provider=args.provider,
        model=args.model,
        wire_api=args.wire_api,
        retries=args.retries,
        timeout=args.timeout,
    )


def _note_verify_route(n: int) -> None:
    """State the verification route so the choice is visible rather than inferred."""
    if n == 0:
        route = "keep-all, no independent confirmer is set so nothing is dropped, the recall-safe default"
    else:
        plural = "s" if n != 1 else ""
        route = (
            f"skeptic plus {n} confirmer{plural}, a drop needs the skeptic to refute and every "
            "independent confirmer to uphold it"
        )
    print(f"Verify route: {route}.", file=sys.stderr)


def _add_model_args(target) -> None:
    """Base seat and client policy flags; unset values come from the CYBERJURY_* environment."""
    target.add_argument("--provider", choices=PROVIDERS, default=None, help="base seat provider")
    target.add_argument("--model", type=_nonempty_string, default=None, help="base seat model")
    target.add_argument(
        "--wire-api",
        default=None,
        dest="wire_api",
        choices=("chat", "responses"),
        help="OpenAI base seat wire API, default responses, chat for endpoints that only serve Chat Completions",
    )
    target.add_argument(
        "--retries", type=nonnegative_int, default=None, help="provider retry attempts on transient failure"
    )
    target.add_argument(
        "--timeout",
        type=positive_float,
        default=None,
        help="per-call deadline in seconds, also honored when a retry holds the bound",
    )


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


_MODEL_GROUP_HELP = (
    "API keys, endpoints, and the finder, skeptic, and confirmer seats come from CYBERJURY_* "
    "environment variables, see .env.example. The finder finds, the skeptic refutes, and an "
    "independent confirmer must approve a deletion. With no distinct confirmer, no finding is "
    "refuted, the recall-safe default"
)


def _add_audit_args(p) -> None:
    p.add_argument("--repository", required=True, help="repository containing the reviewed git range")
    p.add_argument("--git-range", required=True, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="run the repository-grounded engine with a mock provider and no key",
    )
    _add_concurrency_arg(p, "diff batch reviews or verification calls")
    _add_workspace_arg(p)
    _add_model_args(p.add_argument_group("model backend", _MODEL_GROUP_HELP))


def _add_repository_args(repository: argparse.ArgumentParser) -> None:
    repository.add_argument("directory", help="target repository to review")
    _add_workspace_arg(repository)
    repository.add_argument(
        "--review-id",
        default=None,
        help="continue one existing review session instead of the active session",
    )
    repository.add_argument(
        "--fresh", action="store_true", help="start a new review session and preserve the previous session"
    )
    mode = repository.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--scaffold",
        action="store_true",
        help="build the review workspace without model review: extract facts and plan units. "
        "--run performs this setup automatically",
    )
    mode.add_argument(
        "--run",
        action="store_true",
        help="run model review over the repository, not just scaffold: "
        "each open unit is reviewed once and verified, re-running resumes open work",
    )
    repository.add_argument(
        "--dry-run",
        action="store_true",
        help="run only: drive the engine with a mock provider and no key, to smoke test the pipeline",
    )

    tuning = repository.add_argument_group("run tuning", "applies to --run")
    _add_concurrency_arg(tuning, "how many unit reviews or verification calls")
    _add_model_args(repository.add_argument_group("model backend", f"applies to --run. {_MODEL_GROUP_HELP}"))


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
    review_subcommands = review.add_subparsers(dest="scope")
    _add_audit_args(
        review_subcommands.add_parser("diff", help="review a git range against its repository", allow_abbrev=False)
    )
    repository = review_subcommands.add_parser(
        "repository",
        help="run a repository review: --scaffold or --run",
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


def _report_loaded_env() -> None:
    """Report settings loaded from the working directory environment file."""
    env_loaded = load_env_file()
    if not env_loaded:
        return
    count = len(env_loaded)
    plural = "s" if count != 1 else ""
    print(f"loaded {count} setting{plural} from .env: {', '.join(env_loaded)}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    args = None
    try:
        _report_loaded_env()
        parser = _build_parser()
        args = parser.parse_args(argv)
        return _dispatch(args, parser)
    except Exception as exc:
        label = (getattr(args, "command", None) if args is not None else None) or "cyberjury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


@dataclass(kw_only=True)
class _ReviewRun:
    """Resolved command state shared by every step of one review attempt."""

    args: argparse.Namespace
    session: ReviewSession
    attempt: ReviewAttempt
    providers: ProviderConfiguration
    meter: UsageMeter
    target: ResolvedTarget
    snapshot: SourceSnapshot
    source: SourceSnapshot
    model_calls_recorded: bool = False


def _review_action(args: argparse.Namespace) -> str:
    if args.scope == "diff":
        return "run"
    return "scaffold" if args.scaffold else "run"


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


def _provider_plan(
    args: argparse.Namespace,
    action: str,
    configuration: ProviderConfiguration,
) -> ProviderPlanRecord | None:
    if action == "scaffold":
        return None
    if args.dry_run:
        seat = provider_seat_record(DRY_RUN_SEAT)
        return ProviderPlanRecord(
            retries=None,
            timeout_seconds=None,
            seats=(seat,),
            base_seat_id=seat.seat_id,
            finder_seat_id=seat.seat_id,
        )
    specs = (configuration.base, configuration.finder, configuration.skeptic, configuration.confirmer)
    seats = {provider_seat_id(spec): provider_seat_record(spec) for spec in specs}
    return ProviderPlanRecord(
        retries=configuration.retries,
        timeout_seconds=configuration.timeout,
        seats=tuple(sorted(seats.values(), key=lambda seat: seat.seat_id)),
        base_seat_id=provider_seat_id(configuration.base),
        finder_seat_id=provider_seat_id(configuration.finder),
    )


def _verification_record(
    args: argparse.Namespace,
    action: str,
    configuration: ProviderConfiguration,
) -> VerificationPolicyRecord | None:
    if action != "run":
        return None
    if args.dry_run:
        return VerificationPolicyRecord(enabled=False, skeptic_seat_id=None, confirmer_seat_ids=())
    return VerificationPolicyRecord(
        enabled=True,
        skeptic_seat_id=provider_seat_id(configuration.skeptic),
        confirmer_seat_ids=tuple(provider_seat_id(seat) for seat in confirmer_seats(configuration)),
    )


def _attempt_request(args: argparse.Namespace, configuration: ProviderConfiguration) -> ReviewAttemptRequest:
    action = _review_action(args)
    concurrency = args.concurrency or DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    return ReviewAttemptRequest(
        action=action,
        engine_version=__version__,
        concurrency=(
            ConcurrencyRecord(review=concurrency, verification=None if args.dry_run else concurrency)
            if action == "run"
            else None
        ),
        dry_run=args.dry_run if action == "run" else None,
        fresh=args.fresh if args.scope == "repository" else None,
        providers=_provider_plan(args, action, configuration),
        verification=_verification_record(args, action, configuration),
    )


def _initialize_review_attempt(args: argparse.Namespace, *, source_stack: contextlib.ExitStack) -> _ReviewRun:
    """Resolve all behavior-affecting command configuration once and bind it to an attempt."""
    configuration = _provider_configuration(args)
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
        else ReviewSession.open_existing(args.workspace, intent, review_id=args.review_id)
        if args.review_id is not None
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
    return _ReviewRun(
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
    """Capture the bound source snapshot and enter the private copy every consumer reads.

    A diff reads the committed head tree, already private. A repository reads its live tree,
    copied once so the review never sees later edits.
    """
    if target.kind == "diff":
        snapshot = capture_source_snapshot(source_stack.enter_context(materialize_diff_target(target)))
        return snapshot, snapshot
    snapshot = capture_source_snapshot(target.repository_root)
    root = source_stack.enter_context(snapshot.materialize(name=Path(target.repository_root).name))
    return snapshot, SourceSnapshot(root=root, entries=snapshot.entries, snapshot_id=snapshot.snapshot_id)


def _record_model_calls(run: _ReviewRun) -> None:
    """Persist the model call artifact once for a model backed action."""
    if run.attempt.request.action != "run" or run.model_calls_recorded:
        return
    run.attempt.record_model_calls(run.meter.document())
    run.model_calls_recorded = True


def _report_skipped_files(skipped: tuple[SkippedFile, ...]) -> None:
    """Report target files filtered before model work, separating noise from files without reviewable text."""

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


def _prepare(run: _ReviewRun) -> PreparedReview:
    """Plan and ground the target units and bind their receipts before any model work."""
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


def _run_review(run: _ReviewRun, prepared: PreparedReview, seats: ReviewSeats) -> int:
    """Review and verify the prepared units, bind the result to the attempt, and report it."""
    request = run.attempt.request
    diff = run.target.kind == "diff"
    with stage_timer("review"):
        result = run_review(
            prepared,
            target=DIFF_TARGET if diff else REPOSITORY_TARGET,
            seats=seats,
            concurrency=request.concurrency.review,
            verification_concurrency=request.concurrency.verification or request.concurrency.review,
            work=None if diff else run.session.workspace.path / "work" / Path(run.target.repository_root).name,
            on_unit=lambda done, total, secs: progress(f"unit {done}/{total} ({secs}s)"),
            on_verify=lambda done, total, secs: progress(f"verified {done}/{total} ({secs}s)"),
        )
    verification = result.verification
    run.attempt.bind_verification(
        VerificationReceipt.create(
            request_sha256=request.request_sha256,
            enabled=request.verification.enabled,
            candidate_ids=verification.candidate_ids,
            records=tuple(verification.records),
        )
    )
    run.attempt.bind_result(result.findings, result.outcome_artifact)
    return _report_review(run, result)


def _report_review(run: _ReviewRun, result: ReviewRun) -> int:
    """Report refutations, failures, and incomplete state, print the machine result, and return the exit code."""
    outcome = result.outcome
    for record in result.verification.records:
        if record.outcome != "refuted":
            continue
        finding = record.candidate
        print(f"NOTE: refuted finding at {finding.file}:{finding.line}: {record.reason}", file=sys.stderr)
        for vote in record.votes:
            print(
                f"NOTE: verification {vote.role} {vote.actor_id} on {vote.seat_id}: {vote.verdict}, {vote.reason}",
                file=sys.stderr,
            )
    print(
        f"{len(outcome.findings)} findings: "
        + ", ".join(f"{count} {severity}" for severity, count in result.findings.summary),
        file=sys.stderr,
    )
    for failure in outcome.failures:
        paths = ", ".join(failure.paths[:3])
        more = f", and {len(failure.paths) - 3} more" if len(failure.paths) > 3 else ""
        print(
            f"error: review unit {failure.index}/{failure.total} failed for {paths}{more}: {failure.reason}",
            file=sys.stderr,
        )
    if outcome.failure_reason:
        print(f"error: {outcome.failure_reason}", file=sys.stderr)
    if not outcome.complete:
        print(
            "error: the review is incomplete because grounding, judgment, or verification did not complete, "
            "so the result is not a clean pass. Re-run to retry open work",
            file=sys.stderr,
        )
    print(f"Findings written to {run.attempt.workspace.path}/findings.json", file=sys.stderr)
    if run.meter.model_requests:
        print(run.meter.summary(), file=sys.stderr)
    machine_result = ReviewResultArtifact(
        review_id=run.attempt.workspace.session_id,
        attempt_id=run.attempt.workspace.attempt_id,
        findings=result.findings,
        outcome=result.outcome_artifact,
    )
    print(json.dumps(machine_result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if outcome.complete else 1


def _report_scaffold(run: _ReviewRun, prepared: PreparedReview) -> int:
    target = run.target.repository_root
    print(
        f"Assigned {len(prepared.unit_plan.expected_owned_paths)} production source files to "
        f"{len(prepared.units)} review units. Unit plan: {run.session.workspace.path}/units.json",
        file=sys.stderr,
    )
    print(
        "This command sets up the review, it does not find anything itself. Next, run "
        f"`cyberjury review repository {target} --workspace {run.args.workspace} --run`."
    )
    return 0


def _execute_review(run: _ReviewRun) -> int:
    """Prepare the target once, then run model review unless the action only scaffolds."""
    prepared = _prepare(run)
    request = run.attempt.request
    if request.action == "scaffold":
        result = _report_scaffold(run, prepared)
    else:
        if request.verification.enabled:
            _note_verify_route(len(confirmer_seats(run.providers)))
        seats = review_seats(
            run.providers,
            meter=run.meter,
            dry_run_provider=MockProvider(responder=_dry_run_response) if request.dry_run else None,
        )
        result = _run_review(run, prepared, seats)
    if not run.snapshot.matches():
        print(
            "NOTE: review source changed while the review was running; "
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


def _check_repository_flags(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.scope != "repository":
        return
    if args.scaffold:
        for dest, flag in _RUN_ONLY_OPTIONS.items():
            if getattr(args, dest) not in (None, False):
                parser.error(f"{flag} does not apply to repository --scaffold")
    if args.fresh and args.review_id is not None:
        parser.error("--fresh cannot be combined with --review-id")


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.command == "install-slash-command":
        return _cmd_install_slash_command(args)
    if args.command != "review":
        parser.print_help()
        return 1
    if args.scope is None:
        print("usage: cyberjury review {diff,repository} ...", file=sys.stderr)
        print("  diff   review a git range against its repository", file=sys.stderr)
        print("  repository   scaffold or run a repository review", file=sys.stderr)
        return 1
    _check_repository_flags(args, parser)
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
