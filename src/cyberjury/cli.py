"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import sys
from dataclasses import dataclass, replace
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury import __version__
from cyberjury.envfile import load_env_file
from cyberjury.profiles.base import ReviewProfile, profile_binding
from cyberjury.profiles.registry import ProfileResolution, available_profiles, resolve_profile_binding
from cyberjury.providers.base import Message, Provider
from cyberjury.providers.configuration import (
    ProviderConfiguration,
    ProviderCredentialsError,
    ProviderSeat,
    ProviderSeatOverride,
    provider_configuration,
    provider_for_seat,
)
from cyberjury.providers.factory import PROVIDERS, ROLES, env_defaults
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.report import findings_artifact
from cyberjury.resources import SLASH_COMMAND_FILE
from cyberjury.review.diff.checkout import (
    DRY_RUN_SEAT,
    DiffCheckoutHooks,
    DiffGroundingReceipts,
    review_diff_checkout,
)
from cyberjury.review.diff.engine import DiffReviewResult
from cyberjury.review.grounding import GroundingReceipt
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    TargetInput,
    VerificationRecord,
)
from cyberjury.review.result import OutcomeArtifact, ReviewResultArtifact
from cyberjury.review.seats import confirmer_seats, provider_seat_id, provider_seat_record, verification_route
from cyberjury.review.session import ReviewAttempt, ReviewSession
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.review.target import (
    ResolvedTarget,
    TargetResolutionError,
    materialize_diff_target,
    resolve_diff_target,
    resolve_git_root,
    resolve_repository_target,
)
from cyberjury.review.verification import VerificationReceipt, verification_candidate_id
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from cyberjury.telemetry import progress, read_timeline, stage_timer

if TYPE_CHECKING:
    from cyberjury.profiles.base import ContentPaths, PoCBackend
    from cyberjury.review.repository.engine import RunResult
    from cyberjury.review.verification import Confirmer, Verifier


_PROFILE_HELP = "review profile to use: 'auto' detects from the target's files, or name one of: " + ", ".join(
    available_profiles()
)
_MODEL_BACKEND_OPTIONS = {
    "--provider",
    "--model",
    "--api-key",
    "--api-base",
    "--wire-api",
    "--retries",
    "--timeout",
    *(f"--{role}-{field}" for role in ROLES for field in ("provider", "model", "api-key", "api-base", "wire-api")),
}


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from None
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return parsed


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a finite positive number") from None
    if not isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
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
    """Resolve the base seat and every role override named by the parsed flags."""
    return provider_configuration(
        ProviderSeat(
            provider=args.provider,
            model=args.model,
            api_key=args.api_key,
            api_base=args.api_base,
            wire_api=args.wire_api,
        ),
        {
            role: ProviderSeatOverride(
                provider=getattr(args, f"{role}_provider"),
                model=getattr(args, f"{role}_model"),
                api_key=getattr(args, f"{role}_api_key"),
                api_base=getattr(args, f"{role}_api_base"),
                wire_api=getattr(args, f"{role}_wire_api"),
            )
            for role in ROLES
        },
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


def _warn_unlocatable(verify) -> None:
    kept = list(verify.unlocatable) if verify is not None else []
    if not kept:
        return
    shown = ", ".join(f"{c.title} at {c.file or '<no file>'}" for c in kept[:3])
    noun, verb, pronoun, aux = (
        ("finding", "cites", "it", "was") if len(kept) == 1 else ("findings", "cite", "they", "were")
    )
    print(
        f"WARNING: {len(kept)} {noun} {verb} a location no file in the repository matches, so {pronoun} "
        f"{aux} kept unverified and will be re-verified on resume: {shown}" + (", ..." if len(kept) > 3 else ""),
        file=sys.stderr,
    )


def _add_backend_args(target) -> None:
    d = env_defaults()
    target.add_argument("--provider", choices=PROVIDERS, default=d["provider"])
    target.add_argument("--model", type=_nonempty_string, default=d["model"])
    target.add_argument("--api-key", default=d["api_key"])
    target.add_argument("--api-base", default=d["api_base"])
    target.add_argument(
        "--wire-api",
        default=d["wire_api"],
        dest="wire_api",
        choices=("chat", "responses"),
        help="OpenAI base-seat wire API, unset means auto by model name",
    )
    target.add_argument(
        "--retries", type=_nonnegative_int, default=d["retries"], help="provider retry attempts on transient failure"
    )
    target.add_argument(
        "--timeout",
        type=_positive_float,
        default=d["timeout"],
        help="per-call deadline in seconds, also honored when a retry holds the bound",
    )


def _add_role_backend_args(target, role: str) -> None:
    """The per-role backend override flags for finder, skeptic, or confirmer.

    Each field defaults to None meaning inherit the base --provider/--model/--api-key/--api-
    base/--wire-api, resolved at build time, so a single-model run sets only --model. A role
    that overrides the provider to a different vendor takes its own key, not the base
    vendor's.
    """
    d = env_defaults()["role_backends"][role]
    target.add_argument(f"--{role}-provider", choices=PROVIDERS, default=d["provider"], dest=f"{role}_provider")
    target.add_argument(f"--{role}-model", default=d["model"], dest=f"{role}_model")
    target.add_argument(f"--{role}-api-key", default=d["api_key"], dest=f"{role}_api_key")
    target.add_argument(f"--{role}-api-base", default=d["api_base"], dest=f"{role}_api_base")
    target.add_argument(
        f"--{role}-wire-api",
        default=d["wire_api"],
        dest=f"{role}_wire_api",
        choices=("chat", "responses"),
        help=f"OpenAI {role} wire API, unset means auto by model name",
    )


def _add_model_args(backend, roles) -> None:
    _add_backend_args(backend)
    for role in ROLES:
        _add_role_backend_args(roles, role)


def _add_workspace_arg(target) -> None:
    target.add_argument(
        "--workspace",
        default=_default_workspace(),
        help="state root, review sessions are stored under reviews/<review-id>",
    )


def _add_concurrency_arg(target, work: str) -> None:
    target.add_argument(
        "--concurrency",
        type=_positive_int,
        default=None,
        help=f"{work} to run in parallel, default {DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency}",
    )


def _add_profile_arg(target) -> None:
    target.add_argument("--profile", default="auto", metavar="PROFILE", help=_PROFILE_HELP)


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
    _add_model_args(p, p)
    _add_profile_arg(p)


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
        "--gate",
        action="store_true",
        help="check that the workspace holds a complete, hash bound result for the unchanged source, "
        "exit 0 if it passes, 1 if any item is unmet",
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
    tuning.add_argument(
        "--poc",
        action="store_true",
        help="generate profile PoCs for manual sandbox execution, disabled by default",
    )

    roles = repository.add_argument_group(
        "model roles (advanced)",
        "finder finds, skeptic refutes, and an independent confirmer must approve a deletion. "
        "Each field inherits the base backend when unset, so override only the seat you change, set "
        "a different vendor in any seat for cross-model review, for example a GPT skeptic and a "
        "Claude confirmer. A cross-vendor seat brings its own api-key. With no distinct confirmer, no "
        "finding is refuted, the recall-safe default. Usually set through "
        "CYBERJURY_FINDER_*/SKEPTIC_*/CONFIRMER_*",
    )
    _add_model_args(repository.add_argument_group("model backend"), roles)

    _add_profile_arg(repository)


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
        help="run a repository review: --scaffold, --run, or --gate",
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
        raw_argv = list(sys.argv[1:] if argv is None else argv)
        args = parser.parse_args(raw_argv)
        explicit = {token.partition("=")[0] for token in raw_argv if token.startswith("--")}
        return _dispatch(args, parser, explicit)
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
    providers: ProviderConfiguration | None
    meter: UsageMeter | None
    target: ResolvedTarget
    snapshot: SourceSnapshot
    profile_resolution: ProfileResolution
    profile: ReviewProfile
    model_calls_recorded: bool = False

    @property
    def request(self) -> ReviewAttemptRequest:
        """Return the persisted request that owns every behavior affecting setting."""
        return self.attempt.request


def _review_action(args: argparse.Namespace) -> str:
    if args.scope == "diff":
        return "run"
    return next(name for name in ("scaffold", "gate", "run") if getattr(args, name, False))


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
    return ReviewIntent(target=target, requested_profile=args.profile)


def _provider_plan(
    args: argparse.Namespace,
    action: str,
    configuration: ProviderConfiguration | None,
) -> ProviderPlanRecord | None:
    if action in {"scaffold", "gate"}:
        return None
    if args.dry_run:
        seat = provider_seat_record(DRY_RUN_SEAT)
        return ProviderPlanRecord(
            retries=None,
            timeout_seconds=None,
            seats=(seat,),
            base_seat_id=seat.seat_id,
            finder_seat_id=seat.seat_id if action == "run" else None,
        )
    if configuration is None:
        raise RuntimeError("model backed action is missing provider configuration")
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
    providers: ProviderPlanRecord | None,
    configuration: ProviderConfiguration | None,
) -> VerificationRecord | None:
    if action != "run":
        return None
    if args.dry_run:
        return VerificationRecord(
            enabled=False,
            skeptic_seat_id=None,
            confirmer_seat_ids=(),
        )
    if configuration is None:
        raise RuntimeError("verification is missing provider configuration")
    if providers is None:
        raise RuntimeError("verification is missing its public provider plan")
    skeptic = provider_seat_id(configuration.skeptic)
    confirmers = tuple(provider_seat_id(seat) for seat in confirmer_seats(configuration))
    known = {seat.seat_id for seat in providers.seats}
    if skeptic not in known or not set(confirmers).issubset(known):
        raise ValueError("verification route references an unrecorded provider seat")
    return VerificationRecord(
        enabled=True,
        skeptic_seat_id=skeptic,
        confirmer_seat_ids=confirmers,
    )


def _attempt_request(
    args: argparse.Namespace,
    configuration: ProviderConfiguration | None,
) -> ReviewAttemptRequest:
    action = _review_action(args)
    concurrency = args.concurrency or DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency
    review_concurrency = concurrency if action == "run" else None
    verification_concurrency = concurrency if action == "run" and not args.dry_run else None
    providers = _provider_plan(args, action, configuration)
    concurrency = (
        ConcurrencyRecord(review=review_concurrency, verification=verification_concurrency) if action == "run" else None
    )
    return ReviewAttemptRequest(
        action=action,
        engine_version=__version__,
        concurrency=concurrency,
        dry_run=args.dry_run if action == "run" else None,
        fresh=args.fresh if args.scope == "repository" and action in {"run", "scaffold"} else None,
        providers=providers,
        verification=_verification_record(args, action, providers, configuration),
        poc=getattr(args, "poc", None) if action == "run" else None,
    )


def _initialize_review_attempt(args: argparse.Namespace, *, source_stack: contextlib.ExitStack) -> _ReviewRun:
    """Resolve all behavior-affecting command configuration once and bind it to an attempt."""
    action = _review_action(args)
    configuration = _provider_configuration(args) if action == "run" else None
    intent = _review_intent(args)
    request = _attempt_request(args, configuration)
    state_root = Path(args.workspace).expanduser().resolve()
    requested_root = Path(intent.target.repository).expanduser().resolve()
    if state_root == requested_root or state_root.is_relative_to(requested_root):
        raise TargetResolutionError("state root cannot be inside the reviewed repository")
    repository_root = resolve_git_root(intent.target.repository) if intent.target.kind == "diff" else requested_root
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
            create_if_missing=request.action in {"run", "scaffold"},
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
        if target.kind == "diff":
            source_root = source_stack.enter_context(materialize_diff_target(target))
            snapshot = capture_source_snapshot(source_root)
        else:
            snapshot = capture_source_snapshot(target.repository_root)
        attempt.bind_snapshot(snapshot)
        resolution = resolve_profile_binding(intent.requested_profile, snapshot.files)
        attempt.bind_profile(resolution.binding)
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
        meter=UsageMeter() if request.action == "run" else None,
        target=target,
        snapshot=snapshot,
        profile_resolution=resolution,
        profile=resolution.profile,
    )


def _configuration(run: _ReviewRun) -> ProviderConfiguration:
    if run.providers is None:
        raise RuntimeError("model action is missing provider configuration")
    return run.providers


def _meter(run: _ReviewRun) -> UsageMeter:
    if run.meter is None:
        raise RuntimeError("model action is missing its usage meter")
    return run.meter


def _role_provider(run: _ReviewRun, seat: ProviderSeat) -> Provider:
    """Build a metered provider for one resolved role seat.

    Construction is lazy, so no SDK or key is touched until a call is made. Every seat
    shares the run meter, so one total spans finder, skeptic, and confirmers.
    """
    try:
        return provider_for_seat(_configuration(run), seat, meter=_meter(run))
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc


def _verification_resources(run: _ReviewRun, content: ContentPaths) -> tuple[Verifier, list[Confirmer]]:
    """Build the skeptic and every independent confirmer for model verification."""
    try:
        verifier, confirmers = verification_route(_configuration(run), content, meter=_meter(run))
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc
    _note_verify_route(len(confirmers))
    return verifier, confirmers


def _record_provider_route(run: _ReviewRun) -> None:
    request = run.request
    if request.providers is None or request.verification is None:
        raise RuntimeError("model action is missing its provider route")
    seat_ids = {
        request.providers.base_seat_id,
        request.providers.finder_seat_id,
        request.verification.skeptic_seat_id,
        *request.verification.confirmer_seat_ids,
    }
    run.attempt.record_provider_route(seat_ids=tuple(sorted(seat_id for seat_id in seat_ids if seat_id)))


def _record_model_calls(run: _ReviewRun) -> None:
    """Persist the model call artifact once when this command created a meter."""
    if run.meter is None or run.model_calls_recorded:
        return
    run.attempt.record_model_calls(run.meter.document())
    run.model_calls_recorded = True


def _bind_scheduling(run: _ReviewRun, outcome) -> None:
    """Persist the shared scheduler receipt returned by either review path."""
    if outcome.scheduling is None:
        raise RuntimeError("review run did not produce a scheduling receipt")
    run.attempt.bind_scheduling(outcome.scheduling)


def _bind_verification(
    run: _ReviewRun,
    *,
    candidate_ids: tuple[str, ...],
    records=(),
    unlocatable=(),
) -> None:
    """Persist the shared candidate deletion decisions for this attempt."""
    request = run.request
    if request.verification is None:
        raise RuntimeError("review action is missing its verification policy")
    receipt = VerificationReceipt.create(
        request_sha256=request.request_sha256,
        enabled=request.verification.enabled,
        candidate_ids=candidate_ids,
        records=tuple(records),
        unlocatable_ids=tuple(verification_candidate_id(candidate) for candidate in unlocatable),
    )
    run.attempt.bind_verification(receipt)


def _repository_workspace_root(run: _ReviewRun) -> Path:
    return run.session.workspace.path / "work"


def _report_skipped_diff_files(skipped_paths: tuple[str, ...]) -> None:
    """Report changed files filtered before model work."""
    shown = ", ".join(skipped_paths[:5])
    more = f", and {len(skipped_paths) - 5} more" if len(skipped_paths) > 5 else ""
    file_label = "file" if len(skipped_paths) == 1 else "files"
    progress(f"skipped {len(skipped_paths)} non-reviewable {file_label}: {shown}{more}")


def _bind_diff_grounding(run: _ReviewRun, receipts: DiffGroundingReceipts) -> None:
    """Record diff grounding receipts before provider routing and model work."""
    run.attempt.bind_native_analysis(receipts.native_analysis)
    run.attempt.bind_facts_resolution(receipts.facts_resolution)
    run.attempt.bind_unit_plan(receipts.unit_plan)
    run.attempt.bind_grounding(receipts.grounding, duration_seconds=receipts.grounding_seconds)
    _record_provider_route(run)
    if receipts.review_paths:
        progress(f"grounded diff context for {len(receipts.review_paths)} changed source file(s)")


def _bind_diff_review(run: _ReviewRun, result: DiffReviewResult) -> None:
    """Record scheduling and verification decisions before the source drift check."""
    _bind_scheduling(run, result.outcome)
    _bind_verification(
        run,
        candidate_ids=result.verification_candidate_ids,
        records=result.verification_records,
    )


def _execute_diff_review(run: _ReviewRun) -> DiffReviewResult:
    """Run the shared checkout Diff Review and bind its receipts to the attempt."""
    request = run.request
    if request.concurrency is None or request.concurrency.review is None or request.verification is None:
        raise RuntimeError("diff run is missing its execution policy")
    if run.target.patch is None:
        raise RuntimeError("resolved diff target has no patch")
    configuration = _configuration(run)
    if request.verification.enabled:
        _note_verify_route(len(confirmer_seats(configuration)))
    try:
        review = review_diff_checkout(
            run.target.patch.text,
            root=run.snapshot.root,
            profile=run.profile,
            configuration=configuration,
            meter=_meter(run),
            concurrency=request.concurrency.review,
            verification_concurrency=request.concurrency.verification,
            source_snapshot=run.snapshot,
            dry_run_provider=MockProvider(responder=_dry_run_response) if request.dry_run else None,
            hooks=DiffCheckoutHooks(
                on_skipped=_report_skipped_diff_files,
                on_grounded=lambda receipts: _bind_diff_grounding(run, receipts),
                on_reviewed=lambda result: _bind_diff_review(run, result),
                on_batch=lambda done, total, secs: progress(f"batch {done}/{total} ({secs}s)"),
                on_judgment=lambda label, secs: progress(f"review judgment [{label}] ({secs}s)"),
                stage=stage_timer,
            ),
        )
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc
    result = review.result
    machine_findings = findings_artifact(
        result.outcome.findings,
        verified_ids={
            verification_candidate_id(record.candidate)
            for record in result.verification_records
            if record.outcome == "retained" and record.votes
        },
    )
    machine_outcome = OutcomeArtifact.create(
        target="diff",
        source_revision=review.source_snapshot.snapshot_id,
        findings=machine_findings,
        outcome=result.outcome,
    )
    run.attempt.bind_result(machine_findings, machine_outcome)
    return replace(
        result,
        findings_artifact=machine_findings,
        outcome_artifact=machine_outcome,
    )


def _print_review_result(run: _ReviewRun, findings, outcome) -> None:
    machine_result = ReviewResultArtifact(
        review_id=run.attempt.workspace.session_id,
        attempt_id=run.attempt.workspace.attempt_id,
        findings=findings,
        outcome=outcome,
    )
    print(json.dumps(machine_result.to_dict(), indent=2, ensure_ascii=False))


def _report_diff_result(run: _ReviewRun, result: DiffReviewResult) -> int:
    """Render findings and explicit incomplete state for the CLI."""
    if result.findings_artifact is None or result.outcome_artifact is None:
        raise RuntimeError("diff review did not produce result artifacts")
    _print_review_result(run, result.findings_artifact, result.outcome_artifact)
    for finding, reason in result.dropped:
        print(
            f"NOTE: refuted finding at {finding.file}:{finding.line}: {reason}",
            file=sys.stderr,
        )
    for record in result.verification_records:
        if record.outcome != "refuted":
            continue
        for vote in record.votes:
            print(
                f"NOTE: verification {vote.role} {vote.actor_id} on {vote.seat_id}: {vote.verdict}, {vote.reason}",
                file=sys.stderr,
            )
    for failure in result.outcome.failures:
        paths = ", ".join(failure.paths[:3])
        more = f", and {len(failure.paths) - 3} more" if len(failure.paths) > 3 else ""
        print(
            f"error: diff batch {failure.index}/{failure.total} failed for {paths}{more}: {failure.reason}",
            file=sys.stderr,
        )
    if result.outcome.grounding.failure_reason:
        print(f"error: {result.outcome.grounding.failure_reason}", file=sys.stderr)
    if result.outcome.degraded:
        print(
            "error: the diff audit degraded because grounding, judgment, or verification is incomplete, "
            "the result is incomplete and not a clean pass",
            file=sys.stderr,
        )
    usage = result.usage
    if usage and usage.get("model_requests"):
        print(
            "tokens over "
            f"{usage['model_requests']} model requests: "
            f"total_input={usage['total_input_tokens']} "
            f"uncached={usage['uncached_input_tokens']} "
            f"cache_read={usage['cache_read_tokens']} "
            f"cache_write={usage['cache_write_tokens']} "
            f"output={usage['output_tokens']}",
            file=sys.stderr,
        )
    return 1 if result.outcome.degraded else 0


def _cmd_review_diff(run: _ReviewRun) -> int:
    """Own the lifecycle for one Diff Review command."""
    return _report_diff_result(run, _execute_diff_review(run))


def _repo_ws(run: _ReviewRun) -> Path:
    """The per-target workspace directory, where the run artifacts and the timeline live."""
    return _repository_workspace_root(run) / Path(run.target.repository_root).name


def _verify_progress(done: int, total: int, secs: float) -> None:
    """Per-candidate heartbeat for the verify fan-out."""
    progress(f"verified {done}/{total} ({secs}s)")


def _timed_stage(name: str, *, reset: bool = False):
    """Record a repository stage's elapsed time in its workspace and on stderr."""

    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(run):
            with stage_timer(name, _repo_ws(run), reset=reset):
                return fn(run)

        return wrapper

    return decorate


@_timed_stage("gate")
def _cmd_repository_gate(run: _ReviewRun) -> int:
    from cyberjury.review.repository.gate import check_gate

    target = run.target.repository_root
    snapshot = run.snapshot
    project_dir = _repo_ws(run)
    with snapshot.materialize(name=Path(target).name) as source_root:
        result = check_gate(project_dir, root=source_root)
    if not snapshot.matches():
        raise RuntimeError("repository source changed while the completeness gate was running")
    timeline = read_timeline(project_dir)
    if timeline:
        total = round(sum(r.get("seconds", 0) for r in timeline), 1)
        progress(
            f"pipeline {total}s so far: "
            + ", ".join(f"{r.get('stage', '?')} {r.get('seconds', '?')}s" for r in timeline)
        )
    if result.passed:
        print(f"Completeness Gate PASSED for {project_dir}", file=sys.stderr)
        print("Checked: " + ", ".join(result.checked), file=sys.stderr)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return 0
    print(f"Completeness Gate FAILED for {project_dir}, {len(result.failures)} item(s) unmet:", file=sys.stderr)
    for f in result.failures:
        print(f"  - {f}", file=sys.stderr)
    print("Re-run the review to address these, then re-check. Do not report the review complete yet.", file=sys.stderr)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 1


@dataclass(frozen=True, kw_only=True)
class _RepositoryResources:
    """Verification and PoC resources for one repository run."""

    profile: ReviewProfile
    configuration: ProviderConfiguration
    verifier: Verifier | None = None
    confirmers: tuple[Confirmer, ...] = ()
    poc_backend: PoCBackend | None = None


def _prepare_repository_resources(run: _ReviewRun) -> _RepositoryResources:
    configuration = _configuration(run)
    request = run.request
    verifier = None
    confirmers: list[Confirmer] = []
    if request.verification is not None and request.verification.enabled:
        verifier, confirmers = _verification_resources(run, run.profile.paths)
    poc_backend = None
    if request.poc and not request.dry_run and run.profile.poc_backend is not None:
        poc_backend = run.profile.poc_backend(
            provider=_role_provider(run, configuration.base),
            model=configuration.base.model,
        )
    return _RepositoryResources(
        profile=run.profile,
        configuration=configuration,
        verifier=verifier,
        confirmers=tuple(confirmers),
        poc_backend=poc_backend,
    )


@dataclass(frozen=True, kw_only=True)
class _RepositoryRunState:
    """Resolved finder provider and shared resources for one Repository Review run."""

    resources: _RepositoryResources
    provider: Provider
    model: str


def _prepare_repository_run_resources(run: _ReviewRun) -> _RepositoryRunState:
    """Resolve the repository finder seat, verification, and PoC resources."""
    resources = _prepare_repository_resources(run)
    if run.request.dry_run:
        provider = MeteringProvider(MockProvider(responder=_dry_run_response), _meter(run))
        return _RepositoryRunState(resources=resources, provider=provider, model="mock")
    configuration = resources.configuration
    return _RepositoryRunState(
        resources=resources,
        provider=_role_provider(run, configuration.finder),
        model=configuration.finder.model,
    )


def _bind_repository_grounding(run: _ReviewRun, receipt: GroundingReceipt, duration_seconds: float) -> None:
    """Record initial grounding before provider routing and model work."""
    run.attempt.bind_grounding(receipt, duration_seconds=duration_seconds)
    _record_provider_route(run)


def _execute_repository_run(
    run: _ReviewRun,
    state: _RepositoryRunState,
    source_root: Path,
) -> RunResult:
    """Run the repository engine with resolved command resources."""
    from cyberjury.review.repository.engine import (
        RepositoryExecutionOptions,
        RepositoryLifecycleOptions,
        RepositoryOutputOptions,
        RepositoryRoleOptions,
        RepositoryRunOptions,
        RepositoryVerificationOptions,
        run_repository_review,
    )

    request = run.request
    if request.concurrency is None or request.concurrency.review is None or request.verification is None:
        raise RuntimeError("repository run is missing its execution policy")
    target_identity = run.target.repository_root
    configuration = state.resources.configuration
    print(f"Reviewing {target_identity} ...", file=sys.stderr)
    result = run_repository_review(
        str(source_root),
        _repository_workspace_root(run),
        options=RepositoryRunOptions(
            roles=RepositoryRoleOptions(
                provider=state.provider,
                model=state.model,
                finder_label=provider_seat_id(configuration.finder),
            ),
            verification=RepositoryVerificationOptions(
                enabled=request.verification.enabled,
                verifier=state.resources.verifier,
                confirmers=state.resources.confirmers,
                concurrency=request.concurrency.verification or request.concurrency.review,
                on_verify=_verify_progress,
            ),
            execution=RepositoryExecutionOptions(
                concurrency=request.concurrency.review,
                on_judgment=lambda unit, label, secs: print(
                    f"  unit {unit} review judgment [{label}] ({secs}s)",
                    file=sys.stderr,
                ),
                expected_snapshot_id=run.snapshot.snapshot_id,
                on_native_analysis=run.attempt.bind_native_analysis,
                on_facts_resolution=run.attempt.bind_facts_resolution,
                on_unit_plan=run.attempt.bind_unit_plan,
                on_grounding=lambda receipt, seconds: _bind_repository_grounding(run, receipt, seconds),
            ),
            lifecycle=RepositoryLifecycleOptions(
                fresh=request.fresh is True,
                target_identity=target_identity,
            ),
            output=RepositoryOutputOptions(
                profile=state.resources.profile,
                poc_backend=state.resources.poc_backend,
                meter=run.meter,
            ),
        ),
    )
    if result.outcome is None or result.findings_artifact is None or result.outcome_artifact is None:
        raise RuntimeError("repository run did not produce an outcome and result artifacts")
    _bind_scheduling(run, result.outcome)
    verify = result.verify
    _bind_verification(
        run,
        candidate_ids=(
            verify.candidate_ids
            if verify is not None
            else tuple(verification_candidate_id(candidate) for candidate in result.accumulator.findings)
        ),
        records=verify.records if verify is not None else (),
        unlocatable=verify.unlocatable if verify is not None else (),
    )
    run.attempt.bind_result(result.findings_artifact, result.outcome_artifact)
    return result


def _report_repository_run(run: _ReviewRun, result: RunResult) -> int:
    """Print repository review results and return the completion exit code."""
    accumulator = result.accumulator
    outcome = result.outcome
    by_severity: dict[str, int] = {}
    for candidate in outcome.findings:
        by_severity[candidate.severity] = by_severity.get(candidate.severity, 0) + 1
    print(f"Engine done: {result.units} units, {len(accumulator.findings)} candidates.", file=sys.stderr)
    if result.verify is not None:
        print(
            f"Union {len(accumulator.findings)} -> {len(result.verify.retained)} retained, "
            f"{len(result.verify.verified)} verified, "
            f"{len(result.verify.refuted)} refuted, see {result.scaffold.workspace}/_refuted.md.",
            file=sys.stderr,
        )
    print(
        f"{len(outcome.findings)} findings: "
        + ", ".join(f"{by_severity.get(severity, 0)} {severity}" for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
        file=sys.stderr,
    )
    _warn_unlocatable(result.verify)
    review_errors = accumulator.errors
    verify_errors = result.verify.errors if result.verify else 0
    if review_errors:
        print(
            f"WARNING: {review_errors} review step(s) failed. Results may be understated. "
            "Inspect the failure details and re-run after correcting their cause.",
            file=sys.stderr,
        )
        if outcome.failure_reason:
            print(f"  {outcome.failure_reason}", file=sys.stderr)
    if verify_errors:
        print(
            f"WARNING: {verify_errors} verification step(s) failed. Findings were kept incomplete; re-run to retry.",
            file=sys.stderr,
        )
    if result.poc_failures:
        print(
            f"WARNING: {len(result.poc_failures)} PoC generation(s) failed, "
            f"see {result.scaffold.workspace}/_pocs.md. Findings are unchanged.",
            file=sys.stderr,
        )
    print(
        f"Findings written to {result.scaffold.workspace}/findings.json",
        file=sys.stderr,
    )
    if _meter(run).model_requests:
        print(_meter(run).summary(), file=sys.stderr)
    _print_review_result(run, result.findings_artifact, result.outcome_artifact)
    return 1 if review_errors or verify_errors or outcome.degraded else 0


@_timed_stage("run")
def _cmd_repository_run(run: _ReviewRun) -> int:
    """Own the lifecycle for one Repository Review run command."""
    state = _prepare_repository_run_resources(run)
    with run.snapshot.materialize(name=Path(run.target.repository_root).name) as source_root:
        result = _execute_repository_run(run, state, source_root)
    if not run.snapshot.matches():
        raise RuntimeError("repository source changed while the review was running")
    return _report_repository_run(run, result)


@_timed_stage("scaffold", reset=True)
def _cmd_repository_scaffold(run: _ReviewRun) -> int:
    target = run.target.repository_root
    snapshot = run.snapshot
    with snapshot.materialize(name=Path(target).name) as source_root:
        res = scaffold(
            source_root,
            _repository_workspace_root(run),
            fresh=run.request.fresh is True,
            profile=run.profile,
            expected_snapshot_id=snapshot.snapshot_id,
            target_identity=target,
        )
    if not snapshot.matches():
        raise RuntimeError("repository source changed while the scaffold was running")
    run.attempt.bind_native_analysis(res.native_analysis)
    run.attempt.bind_facts_resolution(res.facts_resolution)
    run.attempt.bind_unit_plan(res.unit_plan)
    run.attempt.bind_grounding(res.grounding_receipt, duration_seconds=res.grounding_seconds)
    if res.cleared:
        print(f"Cleared {len(res.cleared)} prior-run paths in {res.workspace}", file=sys.stderr)
    elif res.had_prior_run:
        print(
            f"A previous review's output is in {res.workspace}. Re-run with --fresh to start a new session.",
            file=sys.stderr,
        )
    print(f"Workspace ready: {res.workspace}", file=sys.stderr)
    print(
        f"Assigned {len(res.candidate_files)} production source files to {len(res.units)} review units. "
        f"Unit plan: {res.workspace}/_unit_plan.json",
        file=sys.stderr,
    )
    print(
        "This command sets up the review, it does not find anything itself. Next, run "
        f"`cyberjury review repository {target} --workspace {run.args.workspace} --run`."
    )
    return 0


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
    print("Run it with: /cyberjury-review <repository or diff> [--profile <name>]")
    return 0


def _normalize_review_args(args: argparse.Namespace, parser: argparse.ArgumentParser, explicit: set[str]) -> None:
    if args.command != "review" or args.scope != "repository":
        return

    action = _review_action(args)
    if action in {"scaffold", "gate"}:
        unsupported = sorted(explicit.intersection(_MODEL_BACKEND_OPTIONS))
        if unsupported:
            parser.error(f"{unsupported[0]} does not apply to repository --{action}")

    if action not in {"scaffold", "run"} and args.fresh:
        parser.error(f"--fresh does not apply to repository --{action}")
    if args.fresh and args.review_id is not None:
        parser.error("--fresh cannot be combined with --review-id")
    if action != "run" and args.concurrency is not None:
        parser.error(f"--concurrency does not apply to repository --{action}")
    if action != "run" and args.poc:
        parser.error(f"--poc does not apply to repository --{action}")
    if action != "run" and args.dry_run:
        parser.error(f"--dry-run does not apply to repository --{action}")


def _dispatch_review_action(run: _ReviewRun) -> int:
    action = run.request.action
    if run.args.scope == "diff":
        return _cmd_review_diff(run)
    if action == "gate":
        return _cmd_repository_gate(run)
    if action == "run":
        return _cmd_repository_run(run)
    return _cmd_repository_scaffold(run)


def _dispatch_profile_bound_action(run: _ReviewRun) -> int:
    """Run one command against the exact profile content persisted in its resolved binding."""
    resolution = run.profile_resolution
    snapshot = resolution.content_snapshot
    with snapshot.materialize(name=resolution.profile.content_root.name) as content_root:
        active_profile = replace(resolution.profile, content_root=content_root)
        if active_profile.facts_backend is None:
            raise RuntimeError("resolved profile has no facts backend")
        active_profile = replace(
            active_profile,
            facts_backend=active_profile.facts_backend.bind_content(active_profile.paths),
        )
        if profile_binding(active_profile).to_dict() != resolution.binding.to_dict():
            raise RuntimeError("materialized profile does not match its resolved binding")
        run.profile = active_profile
        try:
            result = _dispatch_review_action(run)
        finally:
            run.profile = resolution.profile
    if not snapshot.matches():
        raise RuntimeError("profile content changed while the review command was running")
    return result


def _dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser, explicit: set[str]) -> int:
    _normalize_review_args(args, parser, explicit)
    if args.command == "review" and args.scope is not None:
        with contextlib.ExitStack() as source_stack:
            run = _initialize_review_attempt(args, source_stack=source_stack)
            attempt = run.attempt
            try:
                result = _dispatch_profile_bound_action(run)
                _record_model_calls(run)
                if result == 0 or attempt.request.action == "gate":
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
                raise
    if args.command == "install-slash-command":
        return _cmd_install_slash_command(args)
    if args.command == "review":
        print("usage: cyberjury review {diff,repository} ...", file=sys.stderr)
        print("  diff   review a git range against its repository", file=sys.stderr)
        print("  repository   scaffold or run a repository review", file=sys.stderr)
        return 1
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
