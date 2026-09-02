"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import sys
from dataclasses import dataclass, field, replace
from datetime import UTC
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury import __version__
from cyberjury.detection import load_detection
from cyberjury.envfile import load_env_file
from cyberjury.profiles.base import ReviewProfile, profile_binding
from cyberjury.profiles.registry import ProfileResolution, available_profiles, resolve_profile_binding
from cyberjury.providers.base import Message, Provider
from cyberjury.providers.configuration import (
    DiffProviders,
    ProviderConfiguration,
    ProviderCredentialsError,
    ProviderSeat,
    ProviderSeatOverride,
    provider_for_seat,
    require_provider_key,
    resolve_provider_seat,
)
from cyberjury.providers.configuration import build_diff_providers as create_diff_providers
from cyberjury.providers.factory import PROVIDERS, ROLES, env_defaults
from cyberjury.providers.metering import UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.report import render
from cyberjury.resources import SLASH_COMMAND_FILE
from cyberjury.review.diff.context import DiffContextCollector, build_diff_context_collector
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffReviewResult,
    DiffRoleOptions,
    DiffVerificationOptions,
    run_diff_review,
)
from cyberjury.review.diff.model import DiffUnit, batch_paths, diff_unit_plan_receipt, strip_unreviewable_files
from cyberjury.review.engine import review_schedule
from cyberjury.review.facts import FactsResolutionReceipt, NativeAnalysisReceipt
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.review.request import (
    ConcurrencyRecord,
    ProviderPlanRecord,
    ProviderSeatRecord,
    ReviewAttemptRequest,
    ReviewIntent,
    ScheduleRecord,
    TargetInput,
    VerificationRecord,
    endpoint_identity,
    seat_identity,
)
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
from cyberjury.review.unit_plans import UnitPlanReceipt
from cyberjury.sources.explorer import CHAINS
from cyberjury.sources.snapshot import SourceSnapshot, capture_source_snapshot
from cyberjury.telemetry import progress, read_timeline, stage_timer

if TYPE_CHECKING:
    from cyberjury.profiles.base import PoCBackend
    from cyberjury.review.repository.engine import FinalizeResult, RunResult
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


def _add_profile_arg(p) -> None:
    p.add_argument("--profile", default="auto", metavar="PROFILE", help=_PROFILE_HELP)


def _default_workspace() -> str:
    """Return a user-private path because the workspace holds sensitive review artifacts."""
    return str(Path(os.environ.get("CYBERJURY_HOME") or Path.home() / ".cyberjury"))


def _utc_now() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_MOCK_REPLY = {"real": True, "findings": []}

_REPOSITORY_MOCK_REPLY = {
    "real": True,
    "reason": "mock",
    "findings": [],
    "rebuttals": [],
    "new_findings": [],
}


def _dry_run_reply(base: dict[str, object], messages: list[Message]) -> str:
    """Add exact class receipts when the dry run prompt assigns judgment work."""
    prompt = messages[-1].content if messages else ""
    marker = "Assessment class ids:\n"
    assigned = prompt.partition(marker)[2].partition("\n")[0]
    categories = tuple(category.strip() for category in assigned.split(",") if category.strip())
    reply = dict(base)
    if categories:
        reply["assessments"] = [
            {
                "category": category,
                "decision": "not_exploitable",
                "reason": "dry run completed the assigned response contract",
                "evidence_refs": ["seed"],
            }
            for category in categories
        ]
    return json.dumps(reply)


def _diff_dry_run_response(system: str, messages: list[Message]) -> str:
    """Return one strict response for each Diff Review dry run phase."""
    return _dry_run_reply(_MOCK_REPLY, messages)


def _repository_dry_run_response(system: str, messages: list[Message]) -> str:
    """Return the canned response for the phase named by the dry run prompt."""
    return _dry_run_reply(_REPOSITORY_MOCK_REPLY, messages)


def _base_spec(args: argparse.Namespace) -> ProviderSeat:
    """The base backend each role inherits from when its own field is unset."""
    return ProviderSeat(
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
        api_base=args.api_base,
        wire_api=args.wire_api,
    )


def _role_spec(args: argparse.Namespace, role: str, base: ProviderSeat) -> ProviderSeat:
    """Resolve one role's backend from role overrides and the base seat.

    A role that keeps the base provider inherits the base provider-specific fields. A role
    that switches provider uses that provider's default model and its own key, endpoint, and
    wire API, so one vendor's wire or model name is never forced onto another.
    """
    return resolve_provider_seat(
        base,
        ProviderSeatOverride(
            provider=getattr(args, f"{role}_provider"),
            model=getattr(args, f"{role}_model"),
            api_key=getattr(args, f"{role}_api_key"),
            api_base=getattr(args, f"{role}_api_base"),
            wire_api=getattr(args, f"{role}_wire_api"),
        ),
    )


def _role_provider(args: argparse.Namespace, seat: ProviderSeat) -> Provider:
    """Build a provider for a resolved role seat.

    Construction is lazy, so a per-role provider object is cheap, no SDK or key is touched
    until a call is made. When the run has set a usage meter, every seat is wrapped so one
    shared total spans finder, skeptic, and confirmers.
    """
    command = getattr(args, "_resolved_review_command", None)
    command_configuration = command.providers if command is not None else None
    retries = command_configuration.retries if command_configuration is not None else args.retries
    timeout = command_configuration.timeout if command_configuration is not None else args.timeout
    configuration = ProviderConfiguration(
        base=seat,
        finder=seat,
        challenger=seat,
        judge=seat,
        retries=retries,
        timeout=timeout,
    )
    return provider_for_seat(
        configuration,
        seat,
        meter=getattr(args, "_usage_meter", None),
    )


def _key_reachable(seat: ProviderSeat) -> bool:
    """Whether a seat can authenticate a provider call.

    It carries a key, or its vendor SDK env var is set so the SDK finds one.
    """
    try:
        require_provider_key(seat)
    except ProviderCredentialsError:
        return False
    return True


def _require_key(seat: ProviderSeat) -> None:
    """Fail before a review starts when a provider seat cannot authenticate."""
    try:
        require_provider_key(seat)
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc


def _warn_secondary_env() -> None:
    """Warn when deprecated secondary seat variables would otherwise be ignored."""
    if any(k.startswith("CYBERJURY_SECONDARY_") for k in os.environ):
        print(
            "NOTE: CYBERJURY_SECONDARY_* is no longer read. Use CYBERJURY_CHALLENGER_* for the "
            "skeptic and CYBERJURY_JUDGE_* for the confirmer.",
            file=sys.stderr,
        )


def _confirmer_for(args, spec, content=None):
    """One confirmer's `RefutationChecker`, resolved from the role's API backend."""
    from cyberjury.review.verification import ModelRefutationChecker

    _require_key(spec)
    return ModelRefutationChecker(provider=_role_provider(args, spec), model=spec.model, content=content)


def _verifier_for(args, spec, content):
    """One skeptic verifier, resolved by the role's API backend."""
    from cyberjury.review.verification import ModelVerifier

    _require_key(spec)
    return ModelVerifier(provider=_role_provider(args, spec), model=spec.model, content=content)


def _seat_identity(spec) -> str:
    return _seat_record(spec).seat_id


def _seat_label(spec) -> str:
    return spec.model


def _confirmers(args, *, challenger, judge, finder=None, content=None):
    """The independent confirmers a drop needs, each label and checker pair.

    A refuted finding is dropped only when every applicable confirmer upholds the
    refutation. The challenger is the skeptic, so it is never a confirmer, a read cannot
    confirm its own refutation. The judge and the finder are confirmers, deduped by their
    effective seat, each labeled by that seat so the route skips it for a finding that seat
    itself surfaced. With no distinct confirmer the list is empty and nothing is dropped,
    the recall-safe default.
    """
    out = []
    seen = {_seat_identity(challenger)}
    for spec in (judge, finder):
        if spec is None:
            continue
        key = _seat_identity(spec)
        if key in seen:
            continue
        seen.add(key)
        out.append((_seat_label(spec), _confirmer_for(args, spec, content)))
    return out


def _close_backends(*objs) -> None:
    """Release any backend that exposes a close hook."""
    seen: set[int] = set()
    for obj in objs:
        obj_id = id(obj)
        if obj_id in seen:
            continue
        seen.add(obj_id)
        close = getattr(obj, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()


def _warn_unlocatable(verify) -> None:
    kept = list(getattr(verify, "unlocatable", ()) or ())
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


def _note_verify_route(args, confirmers) -> None:
    """State the verification route so the choice is visible rather than inferred.

    There is one route: the skeptic refutes and every independent confirmer must uphold the
    refutation before a drop. With no confirmer nothing is dropped, the recall-safe default.
    """
    attempt = getattr(args, "_review_attempt", None)
    dry_run = attempt.request.dry_run if attempt is not None else args.dry_run
    if dry_run:
        return
    n = len(confirmers)
    if n == 0:
        route = "keep-all, no independent confirmer is set so nothing is dropped, the recall-safe default"
    else:
        plural = "s" if n != 1 else ""
        route = (
            f"skeptic plus {n} confirmer{plural}, a drop needs the skeptic to refute and every "
            "independent confirmer to uphold it"
        )
    print(f"Verify route: {route}.", file=sys.stderr)


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
    """The per-role backend override flags for finder, challenger, or judge.

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


def _add_audit_args(p) -> None:
    p.add_argument("--repository", required=True, help="repository containing the reviewed git range")
    p.add_argument("--git-range", required=True, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="run the repository-grounded engine with a mock provider and no key",
    )
    p.add_argument("--mode", choices=("standard", "adversarial"), default=None)
    p.add_argument(
        "--rounds",
        type=_positive_int,
        default=None,
        help="adversarial only: role rounds",
    )
    p.add_argument(
        "--concurrency",
        type=_positive_int,
        default=None,
        help=(
            "diff batch reviews or verification calls to run in parallel, default "
            f"{DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency}"
        ),
    )
    p.add_argument(
        "--workspace",
        default=_default_workspace(),
        help="state root, review sessions are stored under reviews/<review-id>",
    )
    _add_backend_args(p)
    for role in ROLES:
        _add_role_backend_args(p, role)
    _add_profile_arg(p)


def _auto_concurrency(concurrency: int | None) -> int:
    """Pick the API fan-out parallelism when the operator set none."""
    if concurrency is not None:
        return concurrency
    return DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency


def _add_repository_args(repository: argparse.ArgumentParser) -> None:
    repository.add_argument("directory", help="target repository to review")
    repository.add_argument(
        "--workspace",
        default=_default_workspace(),
        help="state root, review sessions are stored under reviews/<review-id>",
    )
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
        help="build the review workspace without model review: detect the stack, slice units, "
        "and seed the inventory. --run performs this setup automatically",
    )
    mode.add_argument(
        "--gate",
        action="store_true",
        help="check the existing workspace against the Completeness Gate instead of scaffolding, "
        "exit 0 if it passes, 1 if any item is unmet",
    )
    mode.add_argument(
        "--run",
        action="store_true",
        help="run the coded review engine over the repository, not just scaffold: "
        "standard mode covers every unit once, adversarial mode runs role rounds until convergence",
    )
    mode.add_argument(
        "--finalize",
        action="store_true",
        help="post-process an existing workspace's candidates in code: dedup, "
        "adversarially verify, and write the ranked report, resumable",
    )
    repository.add_argument(
        "--dry-run",
        action="store_true",
        help="run only: drive the engine with a mock provider and no key, to smoke test the pipeline",
    )

    _add_backend_args(repository.add_argument_group("model backend"))

    strategy = repository.add_argument_group("review strategy")
    strategy.add_argument("--mode", choices=("standard", "adversarial"), default=None)
    strategy.add_argument(
        "--rounds",
        type=_positive_int,
        default=None,
        help="adversarial only: role rounds",
    )

    tuning = repository.add_argument_group("run tuning", "applies to --run and --finalize")
    tuning.add_argument(
        "--concurrency",
        type=_positive_int,
        default=None,
        help=(
            "how many unit reviews or verification calls run in parallel, default "
            f"{DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency}"
        ),
    )

    roles = repository.add_argument_group(
        "model roles (advanced)",
        "finder finds, challenger refutes, and an independent confirmer must approve a deletion. "
        "Each field inherits the base backend when unset, so override only the seat you change, set "
        "a different vendor in any seat for cross-model review, for example a GPT challenger and a "
        "Claude judge. A cross-vendor seat brings its own api-key. With no distinct confirmer, no "
        "finding is refuted, the recall-safe default. Usually set through "
        "CYBERJURY_FINDER_*/CHALLENGER_*/JUDGE_*",
    )
    for role in ROLES:
        _add_role_backend_args(roles, role)

    _add_profile_arg(repository)


def _add_fetch_args(fetch: argparse.ArgumentParser) -> None:
    fsub = fetch.add_subparsers(dest="fetch_kind")
    src = fsub.add_parser("source", help="fetch verified source from a block explorer, no review")
    src.add_argument(
        "--chain", default="bsc", help="which chain's explorer to query, one of: " + ", ".join(sorted(CHAINS))
    )
    src.add_argument("--address", required=True, help="the contract address, 0x and 40 hex digits")
    src.add_argument("--out", required=True, help="directory to write the source tree and metadata into")
    src.add_argument(
        "--api-key",
        default=None,
        dest="api_key",
        help="Etherscan API key, defaults to CYBERJURY_ETHERSCAN_API_KEY, one key covers every chain",
    )
    src.add_argument(
        "--overwrite", action="store_true", help="replace a non-empty output directory instead of refusing"
    )


def _add_install_args(inst: argparse.ArgumentParser) -> None:
    inst.add_argument(
        "--dir", default=None, help="install into this one directory instead of the agent command directories"
    )
    inst.add_argument(
        "--force", action="store_true", help="overwrite an existing cyberjury-review.md at the destination"
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyberjury")
    parser.add_argument("--version", action="version", version=f"cyberjury {__version__}")
    sub = parser.add_subparsers(dest="command")
    review = sub.add_parser("review", help="review code for security findings")
    review_subcommands = review.add_subparsers(dest="scope")
    _add_audit_args(review_subcommands.add_parser("diff", help="audit a unified diff (the coded engine)"))
    repository = review_subcommands.add_parser(
        "repository",
        help="run a repository review: --scaffold, --run, --finalize, or --gate",
    )
    _add_repository_args(repository)
    fetch = sub.add_parser("fetch", help="fetch verified source for a contract address")
    _add_fetch_args(fetch)
    inst = sub.add_parser(
        "install-slash-command", help="install the /cyberjury-review slash command for Claude Code and Codex"
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
        args._explicit_long_options = {token.partition("=")[0] for token in raw_argv if token.startswith("--")}
        return _dispatch(args, parser)
    except Exception as exc:
        label = (getattr(args, "command", None) if args is not None else None) or "cyberjury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


def _provider_configuration(args: argparse.Namespace) -> ProviderConfiguration:
    command = getattr(args, "_resolved_review_command", None)
    if command is not None and command.providers is not None:
        return command.providers
    cached = getattr(args, "_resolved_provider_configuration", None)
    if cached is not None:
        return cached
    base = _base_spec(args)
    seats = {role: _role_spec(args, role, base) for role in ROLES}
    configuration = ProviderConfiguration(
        base=base,
        finder=seats["finder"],
        challenger=seats["challenger"],
        judge=seats["judge"],
        retries=args.retries,
        timeout=args.timeout,
    )
    args._resolved_provider_configuration = configuration
    return configuration


def _build_diff_providers(args: argparse.Namespace) -> DiffProviders:
    meter = UsageMeter()
    args._usage_meter = meter
    request = getattr(getattr(args, "_review_attempt", None), "request", None)
    mode = request.schedule.mode if request is not None and request.schedule is not None else args.mode
    try:
        return create_diff_providers(_provider_configuration(args), mode, meter=meter)
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc


def _review_action(args: argparse.Namespace) -> str:
    if args.scope == "diff":
        return "run"
    return next(name for name in ("scaffold", "gate", "run", "finalize") if getattr(args, name, False))


def _review_intent(args: argparse.Namespace) -> ReviewIntent:
    command = getattr(args, "_resolved_review_command", None)
    if command is not None:
        return command.intent
    scope = getattr(args, "scope", "diff" if hasattr(args, "repository") else "repository")
    target = (
        TargetInput(
            kind="diff",
            repository=str(Path(args.repository).expanduser().resolve()),
            git_range=args.git_range,
        )
        if scope == "diff"
        else TargetInput(kind="repository", repository=str(Path(args.directory).expanduser().resolve()))
    )
    return ReviewIntent(target=target, requested_profile=getattr(args, "profile", "auto"))


def _seat_record(spec: ProviderSeat) -> ProviderSeatRecord:
    endpoint = endpoint_identity(spec.api_base)
    return ProviderSeatRecord(
        seat_id=seat_identity(spec.provider, spec.model, endpoint, spec.wire_api),
        provider=spec.provider,
        model=spec.model,
        endpoint_identity=endpoint,
        wire_api=spec.wire_api,
    )


def _provider_plan(
    args: argparse.Namespace,
    action: str,
    configuration: ProviderConfiguration | None,
) -> ProviderPlanRecord | None:
    if action in {"scaffold", "gate"}:
        return None
    if args.dry_run:
        mock = ProviderSeat(provider="mock", model="mock")
        seat = _seat_record(mock)
        adversarial = action == "run" and args.mode == "adversarial"
        return ProviderPlanRecord(
            retries=None,
            timeout_seconds=None,
            seats=(seat,),
            base_seat_id=seat.seat_id,
            finder_seat_id=seat.seat_id if action == "run" else None,
            challenger_seat_id=seat.seat_id if adversarial else None,
            judge_seat_id=seat.seat_id if adversarial else None,
        )
    if configuration is None:
        raise RuntimeError("model backed action is missing provider configuration")
    specs = (
        (configuration.base, configuration.finder, configuration.challenger, configuration.judge)
        if action == "run"
        else (configuration.base, configuration.challenger, configuration.judge)
    )
    seats = {_seat_record(spec).seat_id: _seat_record(spec) for spec in specs}

    def identity(spec: ProviderSeat) -> str:
        return _seat_record(spec).seat_id

    adversarial = action == "run" and args.mode == "adversarial"
    return ProviderPlanRecord(
        retries=configuration.retries,
        timeout_seconds=configuration.timeout,
        seats=tuple(sorted(seats.values(), key=lambda seat: seat.seat_id)),
        base_seat_id=identity(configuration.base),
        finder_seat_id=identity(configuration.finder) if action == "run" else None,
        challenger_seat_id=identity(configuration.challenger) if adversarial else None,
        judge_seat_id=identity(configuration.judge) if adversarial else None,
    )


def _verification_record(
    args: argparse.Namespace,
    action: str,
    providers: ProviderPlanRecord | None,
    configuration: ProviderConfiguration | None,
) -> VerificationRecord | None:
    enabled = action in {"run", "finalize"} and not args.dry_run
    if action not in {"run", "finalize"}:
        return None
    if not enabled:
        return VerificationRecord(
            enabled=False,
            votes_required=None,
            skeptic_seat_id=None,
            confirmer_seat_ids=(),
        )
    if configuration is None:
        raise RuntimeError("verification is missing provider configuration")
    if providers is None:
        raise RuntimeError("verification is missing its public provider plan")

    def identity(spec: ProviderSeat) -> str:
        return _seat_record(spec).seat_id

    skeptic = identity(configuration.challenger)
    seen = {skeptic}
    confirmers = []
    candidates = [configuration.judge]
    if action == "run":
        candidates.append(configuration.finder)
    for spec in candidates:
        seat_id = identity(spec)
        if seat_id not in seen:
            seen.add(seat_id)
            confirmers.append(seat_id)
    known = {seat.seat_id for seat in providers.seats}
    if skeptic not in known or not set(confirmers).issubset(known):
        raise ValueError("verification route references an unrecorded provider seat")
    return VerificationRecord(
        enabled=True,
        votes_required=DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
        skeptic_seat_id=skeptic,
        confirmer_seat_ids=tuple(confirmers),
    )


def _attempt_request(
    args: argparse.Namespace,
    configuration: ProviderConfiguration | None,
) -> ReviewAttemptRequest:
    action = _review_action(args)
    schedule = (
        ScheduleRecord.from_schedule(
            review_schedule(
                args.mode,
                max_rounds=args.rounds,
                min_rounds=1,
                converge_after=DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge,
                stop_on_failure=args.scope == "diff",
            )
        )
        if action == "run"
        else None
    )
    review_concurrency = _auto_concurrency(args.concurrency) if action == "run" else None
    verification_concurrency = (
        _auto_concurrency(args.concurrency) if action in {"run", "finalize"} and not args.dry_run else None
    )
    providers = _provider_plan(args, action, configuration)
    concurrency = (
        ConcurrencyRecord(review=review_concurrency, verification=verification_concurrency)
        if action in {"run", "finalize"}
        else None
    )
    return ReviewAttemptRequest(
        action=action,
        engine_version=__version__,
        schedule=schedule,
        concurrency=concurrency,
        dry_run=args.dry_run if action == "run" else None,
        fresh=getattr(args, "fresh", False) if args.scope == "repository" and action in {"run", "scaffold"} else None,
        providers=providers,
        verification=_verification_record(args, action, providers, configuration),
    )


@dataclass(frozen=True, kw_only=True)
class _ResolvedReviewCommand:
    """One in-memory source for public policy and private provider credentials."""

    intent: ReviewIntent
    request: ReviewAttemptRequest
    providers: ProviderConfiguration | None


def _resolve_review_command(args: argparse.Namespace) -> _ResolvedReviewCommand:
    """Resolve all behavior-affecting command configuration once."""
    action = _review_action(args)
    providers = _provider_configuration(args) if action in {"run", "finalize"} else None
    return _ResolvedReviewCommand(
        intent=_review_intent(args),
        request=_attempt_request(args, providers),
        providers=providers,
    )


def _command(args: argparse.Namespace) -> _ResolvedReviewCommand:
    command = getattr(args, "_resolved_review_command", None)
    if command is None:
        raise RuntimeError("review command configuration is not resolved")
    return command


def _initialize_review_attempt(args: argparse.Namespace) -> ReviewAttempt:
    command = _resolve_review_command(args)
    args._resolved_review_command = command
    intent = command.intent
    request = command.request
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
    args._review_session = session
    args._review_attempt = attempt
    try:
        target = (
            resolve_diff_target(intent.target.repository, intent.target.git_range or "")
            if intent.target.kind == "diff"
            else resolve_repository_target(intent.target.repository)
        )
        attempt.bind_target(target)
        args._resolved_target = target
        if target.kind == "diff":
            with materialize_diff_target(target) as source_root:
                snapshot = capture_source_snapshot(source_root)
        else:
            snapshot = capture_source_snapshot(target.repository_root)
        attempt.bind_snapshot(snapshot)
        args._source_snapshot = snapshot
        resolution = resolve_profile_binding(intent.requested_profile, snapshot.files)
        attempt.bind_profile(resolution.binding)
        args._profile_resolution = resolution
    except BaseException as exc:
        with contextlib.suppress(BaseException):
            attempt.fail(exc)
        raise
    print(f"Review: {session.workspace.path}", file=sys.stderr)
    print(f"Attempt: {attempt.workspace.attempt_id}", file=sys.stderr)
    return attempt


def _attempt(args: argparse.Namespace) -> ReviewAttempt:
    attempt = getattr(args, "_review_attempt", None)
    if attempt is None:
        raise RuntimeError("review attempt is not initialized")
    return attempt


def _target(args: argparse.Namespace) -> ResolvedTarget:
    target = getattr(args, "_resolved_target", None)
    if target is None:
        raise RuntimeError("review target is not resolved")
    return target


def _source_snapshot(args: argparse.Namespace) -> SourceSnapshot:
    snapshot = getattr(args, "_source_snapshot", None)
    if snapshot is None:
        raise RuntimeError("review source snapshot is not captured")
    return snapshot


def _profile_resolution(args: argparse.Namespace) -> ProfileResolution:
    resolution = getattr(args, "_profile_resolution", None)
    if resolution is None:
        raise RuntimeError("review profile is not resolved")
    return resolution


def _profile(args: argparse.Namespace) -> ReviewProfile:
    return getattr(args, "_active_profile", None) or _profile_resolution(args).profile


def _record_provider_route(args: argparse.Namespace) -> None:
    request = _attempt(args).request
    if request.providers is None or request.verification is None:
        raise RuntimeError("model action is missing its provider route")
    seat_ids = {
        request.providers.base_seat_id,
        request.providers.finder_seat_id,
        request.providers.challenger_seat_id,
        request.providers.judge_seat_id,
        request.verification.skeptic_seat_id,
        *request.verification.confirmer_seat_ids,
    }
    _attempt(args).record_provider_route(seat_ids=tuple(sorted(seat_id for seat_id in seat_ids if seat_id)))


def _repository_workspace_root(args: argparse.Namespace) -> Path:
    session = getattr(args, "_review_session", None)
    if session is None:
        raise RuntimeError("review session is not initialized")
    return session.workspace.path / "work"


@dataclass(kw_only=True)
class _DiffCommandState:
    """Backend seats and mutable verification resources for one diff command."""

    diff: str
    profile: ReviewProfile
    provider: Provider
    model: str
    finder_provider: Provider | None = None
    challenger_provider: Provider | None = None
    judge_provider: Provider | None = None
    finder_model: str | None = None
    challenger_model: str | None = None
    judge_model: str | None = None
    finder_label: str | None = None
    challenger_label: str | None = None
    judge_label: str | None = None
    finder_spec: ProviderSeat | None = None
    challenger_spec: ProviderSeat | None = None
    judge_spec: ProviderSeat | None = None
    verifier: Verifier | None = None
    confirmers: list[Confirmer] = field(default_factory=list)


def _prepare_diff_command(
    args: argparse.Namespace,
    request: ReviewAttemptRequest | None = None,
) -> _DiffCommandState:
    """Resolve diff input, profile, and provider seats before execution."""
    dry_run = request.dry_run if request is not None else args.dry_run
    resolved = _target(args)
    if resolved.patch is None:
        raise RuntimeError("resolved diff target has no patch")
    diff = resolved.patch.text
    if dry_run:
        return _DiffCommandState(
            diff=diff,
            profile=_profile(args),
            provider=MockProvider(responder=_diff_dry_run_response),
            model="mock",
        )
    profile = _profile(args)
    providers = _build_diff_providers(args)
    configuration = _provider_configuration(args)
    finder = configuration.finder
    challenger = configuration.challenger
    judge = configuration.judge
    return _DiffCommandState(
        diff=diff,
        profile=profile,
        provider=providers.base_provider,
        model=providers.base_model,
        finder_provider=providers.finder_provider,
        challenger_provider=providers.challenger_provider,
        judge_provider=providers.judge_provider,
        finder_model=providers.finder_model,
        challenger_model=providers.challenger_model,
        judge_model=providers.judge_model,
        finder_label=_seat_label(finder),
        challenger_label=_seat_label(challenger),
        judge_label=_seat_label(judge),
        finder_spec=finder,
        challenger_spec=challenger,
        judge_spec=judge,
    )


def _report_skipped_diff_files(state: _DiffCommandState) -> None:
    """Report changed files filtered before model work."""
    detection = load_detection(state.profile.paths.detection_file)
    _, skipped_paths = strip_unreviewable_files(state.diff, detection)
    if not skipped_paths:
        return
    shown = ", ".join(skipped_paths[:5])
    more = f", and {len(skipped_paths) - 5} more" if len(skipped_paths) > 5 else ""
    file_label = "file" if len(skipped_paths) == 1 else "files"
    progress(f"skipped {len(skipped_paths)} non-reviewable {file_label}: {shown}{more}")


def _configure_diff_verification(args: argparse.Namespace, state: _DiffCommandState) -> tuple[str, ...]:
    """Bind verification resources and return the finder provenance labels."""
    verification = _attempt(args).request.verification
    if verification is None:
        raise RuntimeError("diff run is missing its verification policy")
    if not verification.enabled:
        return ()
    challenger = state.challenger_spec
    if challenger is None:
        raise RuntimeError("diff verification requires a challenger seat")
    state.verifier = _verifier_for(args, challenger, state.profile.paths)
    state.confirmers = _confirmers(
        args,
        challenger=challenger,
        judge=state.judge_spec,
        finder=state.finder_spec,
        content=state.profile.paths,
    )
    _note_verify_route(args, state.confirmers)
    schedule = _attempt(args).request.schedule
    return (state.finder_label,) if schedule is not None and schedule.mode == "standard" and state.finder_label else ()


def _run_diff_engine(
    args: argparse.Namespace,
    state: _DiffCommandState,
    source_root: Path,
    context_collector: DiffContextCollector,
    units: list[DiffUnit],
) -> DiffReviewResult:
    """Run the diff engine with resolved command state."""
    request = _attempt(args).request
    schedule = request.schedule
    if schedule is None or request.concurrency is None or request.verification is None:
        raise RuntimeError("diff run is missing its review schedule")
    verification_found_by = _configure_diff_verification(args, state)
    concurrency = request.concurrency.review
    verification_concurrency = request.concurrency.verification
    if concurrency is None:
        raise RuntimeError("diff run is missing review concurrency")

    with stage_timer("diff review"):
        return run_diff_review(
            state.diff,
            provider=state.provider,
            model=state.model,
            options=DiffReviewOptions(
                roles=DiffRoleOptions(
                    mode=schedule.mode,
                    max_rounds=schedule.max_rounds,
                    finder_model=state.finder_model,
                    challenger_model=state.challenger_model,
                    judge_model=state.judge_model,
                    finder_provider=state.finder_provider,
                    challenger_provider=state.challenger_provider,
                    judge_provider=state.judge_provider,
                    finder_label=state.finder_label,
                    challenger_label=state.challenger_label,
                    judge_label=state.judge_label,
                ),
                grounding=DiffGroundingOptions(
                    prepare_diff=lambda _diff: units,
                    source_snapshot=context_collector.source_snapshot,
                ),
                verification=DiffVerificationOptions(
                    root=str(source_root),
                    verifier=state.verifier,
                    confirmers=state.confirmers,
                    found_by=verification_found_by,
                    concurrency=verification_concurrency or concurrency,
                ),
                execution=DiffExecutionOptions(
                    concurrency=concurrency,
                    profile=state.profile,
                    on_batch=lambda done, total, secs: progress(f"batch {done}/{total} ({secs}s)"),
                    on_judgment=lambda done, total, label, secs: progress(
                        f"knowledge judgment {done}/{total} [{label}] ({secs}s)"
                    ),
                    trace=None,
                    meter=getattr(args, "_usage_meter", None),
                ),
            ),
        )


def _execute_diff_review(args: argparse.Namespace, state: _DiffCommandState) -> DiffReviewResult:
    """Collect repository grounding and execute one diff review."""
    _report_skipped_diff_files(state)
    detection = load_detection(state.profile.paths.detection_file)
    review_diff, _skipped_paths = strip_unreviewable_files(state.diff, detection)
    snapshot = _source_snapshot(args)
    with materialize_diff_target(_target(args)) as source_root:
        materialized_snapshot = capture_source_snapshot(source_root)
        if materialized_snapshot.snapshot_id != snapshot.snapshot_id:
            raise RuntimeError("resolved Git source does not match the bound source snapshot")
        with stage_timer("diff context"):
            context_collector = build_diff_context_collector(
                source_root,
                state.profile,
                review_diff=review_diff,
            )
        context_snapshot = context_collector.source_snapshot
        if context_snapshot is None or context_snapshot.snapshot_id != snapshot.snapshot_id:
            raise RuntimeError("diff context did not consume the bound source snapshot")
        if context_collector.native_analysis is None:
            raise RuntimeError("diff context did not produce a native analysis receipt")
        if context_collector.facts_resolution is None:
            raise RuntimeError("diff context did not produce a facts resolution receipt")
        _attempt(args).bind_native_analysis(context_collector.native_analysis)
        _attempt(args).bind_facts_resolution(context_collector.facts_resolution)
        units = context_collector.prepare(review_diff)
        unit_plan = diff_unit_plan_receipt(
            units,
            context_collector.facts_resolution,
            expected_owned_paths=batch_paths(review_diff) if review_diff else (),
        )
        _attempt(args).bind_unit_plan(unit_plan)
        _record_provider_route(args)
        if context_collector.review_paths:
            progress(f"grounded diff context for {len(context_collector.review_paths)} changed source file(s)")
        result = _run_diff_engine(args, state, source_root, context_collector, units)
        if not context_snapshot.matches():
            raise RuntimeError("diff source changed while the review was running")
        return result


def _report_diff_result(args: argparse.Namespace, result: DiffReviewResult) -> int:
    """Render findings and explicit incomplete state for the CLI."""
    print(render("json", result.outcome.findings))
    for finding, reason in getattr(result, "dropped", ()):
        print(
            f"NOTE: refuted finding at {finding.file}:{finding.line}: {reason}",
            file=sys.stderr,
        )
    for record in getattr(result, "verification_records", ()):
        if record.outcome != "refuted":
            continue
        for vote in record.votes:
            print(
                f"NOTE: verification {vote.role} {vote.actor_id} on {vote.seat_id}: {vote.verdict}, {vote.reason}",
                file=sys.stderr,
            )
    for item in getattr(result, "coverage_suggestions", ()):
        represented_by = ", ".join(f"{finding.file}:{finding.line}" for finding in item.represented_by)
        print(
            f"NOTE: coverage suggestion for {item.finding.file}:{item.finding.line}, represented by "
            f"{represented_by}: {item.reason}",
            file=sys.stderr,
        )
    for failure in result.outcome.failures:
        paths = ", ".join(failure.paths[:3])
        more = f", and {len(failure.paths) - 3} more" if len(failure.paths) > 3 else ""
        print(
            f"error: diff batch {failure.index}/{failure.total} failed for {paths}{more}: {failure.reason}",
            file=sys.stderr,
        )
    grounding = getattr(result.outcome, "grounding", None)
    grounding_reason = getattr(grounding, "failure_reason", "")
    if grounding_reason:
        print(f"error: {grounding_reason}", file=sys.stderr)
    if result.outcome.degraded:
        print(
            "error: the diff audit degraded because grounding, judgment, or verification is incomplete, "
            "the result is incomplete and not a clean pass",
            file=sys.stderr,
        )
    usage = getattr(result, "usage", None)
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


def _cmd_review_diff(args: argparse.Namespace) -> int:
    """Own the lifecycle for one Diff Review command."""
    _warn_secondary_env()
    state = _prepare_diff_command(args, _attempt(args).request)
    try:
        return _report_diff_result(args, _execute_diff_review(args, state))
    finally:
        _close_backends(
            state.provider,
            state.finder_provider,
            state.challenger_provider,
            state.judge_provider,
            state.verifier,
            *(checker for _label, checker in state.confirmers),
        )


def _repo_ws(args) -> Path:
    """The per-target workspace directory, where the run artifacts and the timeline live."""
    return _repository_workspace_root(args) / Path(_target(args).repository_root).name


def _verify_progress(done: int, total: int, secs: float) -> None:
    """Per-candidate heartbeat for the verify fan-out, shared by the run and finalize commands."""
    progress(f"verified {done}/{total} ({secs}s)")


def _timed_stage(name: str, *, reset: bool = False):
    """Record a repository stage's elapsed time in its workspace and on stderr."""

    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(args):
            with stage_timer(name, _repo_ws(args), reset=reset):
                return fn(args)

        return wrapper

    return decorate


@_timed_stage("gate")
def _cmd_repository_gate(args) -> int:
    from cyberjury.review.repository.gate import check_gate

    target = _target(args).repository_root
    profile = _profile(args)
    detection = load_detection(profile.paths.detection_file)
    snapshot = _source_snapshot(args)
    project_dir = _repo_ws(args)
    with snapshot.materialize(name=Path(target).name) as source_root:
        result = check_gate(project_dir, root=source_root, detection=detection)
    if not snapshot.matches():
        raise RuntimeError("repository source changed while the completeness gate was running")
    timeline = read_timeline(project_dir)
    if timeline:
        total = round(sum(r.get("seconds", 0) for r in timeline), 1)
        progress(
            f"pipeline {total}s so far: "
            + ", ".join(f"{r.get('stage', '?')} {r.get('seconds', '?')}s" for r in timeline)
        )
    for note in result.notes:
        print(f"NOTE: {note}", file=sys.stderr)
    if result.passed:
        print(f"Completeness Gate PASSED for {project_dir}")
        print("Checked: " + ", ".join(result.checked))
        return 0
    print(f"Completeness Gate FAILED for {project_dir}, {len(result.failures)} item(s) unmet:", file=sys.stderr)
    for f in result.failures:
        print(f"  - {f}", file=sys.stderr)
    print("Run another round to address these, then re-check. Do not report the review complete yet.", file=sys.stderr)
    return 1


@dataclass(kw_only=True)
class _RepositoryResources:
    """Shared role, verification, and PoC resources for run and finalize."""

    profile: ReviewProfile
    base: ProviderSeat
    finder: ProviderSeat
    challenger: ProviderSeat
    judge: ProviderSeat
    verification_provider: Provider | None = None
    verification_model: str = ""
    verifier: Verifier | None = None
    confirmers: list[Confirmer] = field(default_factory=list)
    poc_backend: PoCBackend | None = None
    poc_provider: Provider | None = None


def _prepare_repository_poc(
    args: argparse.Namespace,
    profile: ReviewProfile,
    base: ProviderSeat,
) -> tuple[PoCBackend | None, Provider | None]:
    if _attempt(args).request.dry_run or profile.poc_backend is None:
        return None, None
    _require_key(base)
    provider = _role_provider(args, base)
    try:
        backend = profile.poc_backend(provider=provider, model=base.model)
        if backend.executes and not backend.available():
            note = f"NOTE: PoC toolchain not found, PoCs will be written but not run here. {backend.install_hint}"
            print(
                note.rstrip(),
                file=sys.stderr,
            )
        return backend, provider
    except BaseException:
        _close_backends(provider)
        raise


def _prepare_repository_resources(
    args: argparse.Namespace,
    *,
    finder_confirms: bool,
    profile: ReviewProfile | None = None,
) -> _RepositoryResources:
    from cyberjury.review.verification import ModelVerifier

    profile = profile or _profile(args)
    _warn_secondary_env()
    configuration = _provider_configuration(args)
    base = configuration.base
    finder = configuration.finder
    challenger = configuration.challenger
    judge = configuration.judge
    args._usage_meter = UsageMeter()
    verification_provider = None
    verifier = None
    confirmers = []
    poc_provider = None
    try:
        if _attempt(args).request.dry_run:
            verification_provider = MockProvider(default='{"real": true, "reason": "[mock]"}')
            verification_model = "mock"
        else:
            _require_key(challenger)
            verification_model = challenger.model
            verifier = ModelVerifier(
                provider=_role_provider(args, challenger),
                model=challenger.model,
                content=profile.paths,
            )
            confirmers = _confirmers(
                args,
                challenger=challenger,
                judge=judge,
                finder=finder if finder_confirms else None,
                content=profile.paths,
            )
        poc_backend, poc_provider = _prepare_repository_poc(args, profile, base)
        return _RepositoryResources(
            profile=profile,
            base=base,
            finder=finder,
            challenger=challenger,
            judge=judge,
            verification_provider=verification_provider,
            verification_model=verification_model,
            verifier=verifier,
            confirmers=confirmers,
            poc_backend=poc_backend,
            poc_provider=poc_provider,
        )
    except BaseException:
        _close_backends(
            verification_provider,
            verifier,
            poc_provider,
            *(checker for _label, checker in confirmers),
        )
        raise


def _close_repository_resources(resources: _RepositoryResources) -> None:
    _close_backends(
        resources.verification_provider,
        resources.verifier,
        resources.poc_provider,
        *(checker for _label, checker in resources.confirmers),
    )


def _execute_repository_finalize(
    args: argparse.Namespace,
    resources: _RepositoryResources,
    snapshot: SourceSnapshot,
    source_root: Path,
) -> FinalizeResult:
    from cyberjury.review.repository.engine import (
        RepositoryFinalizeOptions,
        RepositoryOutputOptions,
        RepositoryVerificationOptions,
        finalize_repository_review,
    )

    target_identity = _target(args).repository_root
    print(f"Finalizing {target_identity}: dedup + verify + report ...", file=sys.stderr)
    request = _attempt(args).request
    if request.concurrency is None or request.verification is None:
        raise RuntimeError("repository finalize is missing its verification policy")
    return finalize_repository_review(
        str(source_root),
        _repository_workspace_root(args),
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(
                verifier=resources.verifier,
                confirmers=resources.confirmers,
                provider=resources.verification_provider,
                model=resources.verification_model,
                votes=DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
                concurrency=request.concurrency.verification or 1,
                on_verify=_verify_progress,
            ),
            output=RepositoryOutputOptions(
                profile=resources.profile,
                poc_backend=resources.poc_backend,
                meter=args._usage_meter,
            ),
            expected_snapshot_id=snapshot.snapshot_id,
        ),
    )


def _report_repository_finalize(args: argparse.Namespace, result: FinalizeResult) -> int:
    kept = len(result.verify.retained) if result.verify else result.deduped
    refuted = len(result.verify.refuted) if result.verify else 0
    print(
        f"Finalize done: parsed {result.parsed} candidates -> {result.deduped} after dedup -> "
        f"{kept} confirmed, {refuted} refuted, see {result.workspace}/_refuted.md."
    )
    print(f"Confirmed findings in {result.workspace}/findings/ and {result.workspace}/findings.json")
    if (Path(result.workspace) / "_pocs.md").exists():
        print(f"PoC reconciliation in {result.workspace}/_pocs.md")
    if args._usage_meter.model_requests:
        print(args._usage_meter.summary(), file=sys.stderr)
    _warn_unlocatable(result.verify)
    if result.verify and result.verify.errors:
        print(f"WARNING: {result.verify.errors} verification calls failed. Re-run to resume.", file=sys.stderr)
    return 0 if result.outcome.complete else 1


@_timed_stage("finalize")
def _cmd_repository_finalize(args: argparse.Namespace) -> int:
    resources = _prepare_repository_resources(args, finder_confirms=False)
    target = _target(args).repository_root
    snapshot = _source_snapshot(args)
    _record_provider_route(args)
    _note_verify_route(args, resources.confirmers)
    try:
        with snapshot.materialize(name=Path(target).name) as source_root:
            result = _execute_repository_finalize(args, resources, snapshot, source_root)
        if not snapshot.matches():
            raise RuntimeError("repository source changed while finalization was running")
        return _report_repository_finalize(args, result)
    finally:
        _close_repository_resources(resources)


@dataclass(kw_only=True)
class _RepositoryRunState:
    """Resolved seats and owned resources for one Repository Review run."""

    resources: _RepositoryResources
    provider: Provider
    model: str
    challenger_provider: Provider | None = None
    judge_provider: Provider | None = None


def _prepare_repository_run_resources(
    args: argparse.Namespace,
    *,
    profile: ReviewProfile | None = None,
) -> _RepositoryRunState:
    """Resolve repository profile, role seats, verification, and PoC resources."""
    resources = _prepare_repository_resources(args, finder_confirms=True, profile=profile)
    provider = challenger_provider = judge_provider = None
    try:
        request = getattr(getattr(args, "_review_attempt", None), "request", None)
        dry_run = request.dry_run if request is not None else args.dry_run
        mode = request.schedule.mode if request is not None and request.schedule is not None else args.mode
        if dry_run:
            provider = MockProvider(responder=_repository_dry_run_response)
            role_provider = provider if mode == "adversarial" else None
            return _RepositoryRunState(
                resources=resources,
                provider=provider,
                model="mock",
                challenger_provider=role_provider,
                judge_provider=role_provider,
            )
        _require_key(resources.finder)
        provider = _role_provider(args, resources.finder)
        if mode == "adversarial":
            _require_key(resources.challenger)
            _require_key(resources.judge)
            challenger_provider = _role_provider(args, resources.challenger)
            judge_provider = _role_provider(args, resources.judge)
        return _RepositoryRunState(
            resources=resources,
            provider=provider,
            model=resources.finder.model,
            challenger_provider=challenger_provider,
            judge_provider=judge_provider,
        )
    except BaseException:
        _close_backends(provider, challenger_provider, judge_provider)
        _close_repository_resources(resources)
        raise


def _repository_pass_progress(pass_number: int, reviewer_label: str, new: int, total: int) -> None:
    print(f"  pass {pass_number} [{reviewer_label}]  +{new} new  union={total}", file=sys.stderr)


def _bind_repository_native_analysis(args: argparse.Namespace, receipt: NativeAnalysisReceipt) -> None:
    """Record repository native analysis before facts resolution."""
    _attempt(args).bind_native_analysis(receipt)


def _bind_repository_facts_resolution(args: argparse.Namespace, receipt: FactsResolutionReceipt) -> None:
    """Record repository facts resolution before unit planning."""
    _attempt(args).bind_facts_resolution(receipt)


def _bind_repository_unit_plan(args: argparse.Namespace, receipt: UnitPlanReceipt) -> None:
    """Record repository unit planning before provider routing and model work."""
    _attempt(args).bind_unit_plan(receipt)
    _record_provider_route(args)


def _execute_repository_run(
    args: argparse.Namespace,
    state: _RepositoryRunState,
    snapshot: SourceSnapshot,
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

    request = _attempt(args).request
    schedule = request.schedule
    if (
        schedule is None
        or request.concurrency is None
        or request.concurrency.review is None
        or request.verification is None
    ):
        raise RuntimeError("repository run is missing its execution policy")
    target_identity = _target(args).repository_root
    print(f"Running the coded review engine over {target_identity} ...", file=sys.stderr)
    return run_repository_review(
        str(source_root),
        _repository_workspace_root(args),
        options=RepositoryRunOptions(
            roles=RepositoryRoleOptions(
                mode=schedule.mode,
                provider=state.provider,
                model=state.model,
                challenger_provider=state.challenger_provider,
                challenger_model=state.resources.challenger.model,
                judge_provider=state.judge_provider,
                judge_model=state.resources.judge.model,
            ),
            verification=RepositoryVerificationOptions(
                enabled=request.verification.enabled,
                verifier=state.resources.verifier,
                confirmers=state.resources.confirmers,
                votes=request.verification.votes_required or 1,
                concurrency=request.concurrency.verification or request.concurrency.review,
                on_verify=_verify_progress,
            ),
            execution=RepositoryExecutionOptions(
                max_passes=schedule.max_rounds,
                converge_after=schedule.converge_after or 1,
                min_rounds=schedule.min_rounds,
                concurrency=request.concurrency.review,
                on_pass=_repository_pass_progress,
                on_judgment=lambda unit, done, total, label, secs: print(
                    f"  unit {unit} knowledge judgment {done}/{total} [{label}] ({secs}s)",
                    file=sys.stderr,
                ),
                expected_snapshot_id=snapshot.snapshot_id,
                on_native_analysis=lambda receipt: _bind_repository_native_analysis(args, receipt),
                on_facts_resolution=lambda receipt: _bind_repository_facts_resolution(args, receipt),
                on_unit_plan=lambda receipt: _bind_repository_unit_plan(args, receipt),
            ),
            lifecycle=RepositoryLifecycleOptions(
                fresh=request.fresh is True,
                target_identity=target_identity,
            ),
            output=RepositoryOutputOptions(
                profile=state.resources.profile,
                poc_backend=state.resources.poc_backend,
                meter=args._usage_meter,
            ),
        ),
    )


def _report_repository_run(args: argparse.Namespace, result: RunResult) -> int:
    """Print repository review results and return the completion exit code."""
    if result.scaffold.fallback_note:
        print(f"NOTE: {result.scaffold.fallback_note}.", file=sys.stderr)
    accumulator = result.accumulator
    outcome = getattr(result, "outcome", None)
    reported = (
        outcome.findings if outcome is not None else result.verify.retained if result.verify else accumulator.findings
    )
    by_severity: dict[str, int] = {}
    for candidate in reported:
        by_severity[candidate.severity] = by_severity.get(candidate.severity, 0) + 1
    print(
        f"Engine done: {result.units} units, {len(accumulator.new_per_pass)} passes, converged={accumulator.converged}."
    )
    if result.verify is not None:
        print(
            f"Union {len(accumulator.findings)} -> {len(result.verify.retained)} retained, "
            f"{len(result.verify.verified)} verified, "
            f"{len(result.verify.refuted)} refuted, see {result.scaffold.workspace}/_refuted.md."
        )
    print(
        f"{len(reported)} findings: "
        + ", ".join(f"{by_severity.get(severity, 0)} {severity}" for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
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
        if outcome is not None and outcome.failure_reason:
            print(f"  {outcome.failure_reason}", file=sys.stderr)
    if verify_errors:
        print(
            f"WARNING: {verify_errors} verification step(s) failed. Findings were kept incomplete; re-run to retry.",
            file=sys.stderr,
        )
    schedule = _attempt(args).request.schedule
    if schedule is not None and schedule.mode == "adversarial" and not accumulator.converged:
        print(
            f"WARNING: the union did not converge within {schedule.max_rounds} rounds, it was "
            "still finding new issues when the cap stopped it. Coverage is incomplete and "
            "recall is not guaranteed. Raise --rounds or narrow the scope and re-run.",
            file=sys.stderr,
        )
    print(f"Findings written to {result.scaffold.workspace}/findings/ and {result.scaffold.workspace}/findings.json")
    if args._usage_meter.model_requests:
        print(args._usage_meter.summary(), file=sys.stderr)
    incomplete = (
        outcome.degraded
        if outcome is not None
        else schedule is not None and schedule.mode == "adversarial" and not accumulator.converged
    )
    return 1 if review_errors or verify_errors or incomplete else 0


@_timed_stage("run")
def _cmd_repository_run(args: argparse.Namespace) -> int:
    """Own the lifecycle for one Repository Review run command."""
    state = _prepare_repository_run_resources(args)
    target = _target(args).repository_root
    snapshot = _source_snapshot(args)
    _note_verify_route(args, state.resources.confirmers)
    try:
        with snapshot.materialize(name=Path(target).name) as source_root:
            result = _execute_repository_run(args, state, snapshot, source_root)
        if not snapshot.matches():
            raise RuntimeError("repository source changed while the review was running")
        return _report_repository_run(args, result)
    finally:
        _close_backends(
            state.provider,
            state.challenger_provider,
            state.judge_provider,
        )
        _close_repository_resources(state.resources)


@_timed_stage("scaffold", reset=True)
def _cmd_repository_scaffold(args) -> int:
    request = _attempt(args).request
    target = _target(args).repository_root
    profile = _profile(args)
    snapshot = _source_snapshot(args)
    with snapshot.materialize(name=Path(target).name) as source_root:
        res = scaffold(
            source_root,
            _repository_workspace_root(args),
            fresh=request.fresh is True,
            profile=profile,
            expected_snapshot_id=snapshot.snapshot_id,
            target_identity=target,
        )
    if not snapshot.matches():
        raise RuntimeError("repository source changed while the scaffold was running")
    if res.source_snapshot is None:
        raise RuntimeError("repository scaffold did not capture a source snapshot")
    if res.native_analysis is None:
        raise RuntimeError("repository scaffold did not produce a native analysis receipt")
    if res.facts_resolution is None:
        raise RuntimeError("repository scaffold did not produce a facts resolution receipt")
    if res.unit_plan is None:
        raise RuntimeError("repository scaffold did not produce a unit plan receipt")
    _attempt(args).bind_native_analysis(res.native_analysis)
    _attempt(args).bind_facts_resolution(res.facts_resolution)
    _attempt(args).bind_unit_plan(res.unit_plan)
    (Path(res.workspace) / "methodology.md").write_text(res.methodology, encoding="utf-8")
    if res.cleared:
        print(f"Cleared {len(res.cleared)} prior-run paths in {res.workspace}", file=sys.stderr)
    elif res.had_prior_run:
        print(
            f"A previous review's output is in {res.workspace}. Re-run with --fresh to start a new session.",
            file=sys.stderr,
        )
    print(f"Workspace ready: {res.workspace}", file=sys.stderr)
    if res.guides:
        print(f"Detected stack: {', '.join(res.guides)}, notes in {res.workspace}/_stack.md", file=sys.stderr)
    print(
        f"Seeded {len(res.candidate_files)} candidate entrypoint files and "
        f"{len(res.raw_review_files)} raw production files with "
        f"{len(res.trace_targets)} logic-layer trace targets into "
        f"{res.workspace}/inventory/_entrypoints.md",
        file=sys.stderr,
    )
    if res.fallback_note:
        print(f"NOTE: {res.fallback_note}.", file=sys.stderr)
    print(f"Methodology: {res.workspace}/methodology.md", file=sys.stderr)
    print(
        "This command sets up the review, it does not find anything itself. Next, run "
        f"`cyberjury review repository {target} --workspace {args.workspace} --run`, "
        f"then finalize candidates into {res.workspace}/findings/."
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
    print("Run it with: /cyberjury-review <repository or diff> [--profile auto|web|evm]")
    return 0


def _cmd_fetch_source(args) -> int:
    from cyberjury.sources.fetch import fetch_source

    api_key = args.api_key or os.environ.get("CYBERJURY_ETHERSCAN_API_KEY", "")
    result = fetch_source(
        chain_key=args.chain,
        address=args.address,
        api_key=api_key,
        out=args.out,
        fetched_at=_utc_now(),
        overwrite=args.overwrite,
    )
    print(f"Fetched {result.file_count} source file(s) for {result.meta.address} on {result.meta.chain}")
    print(f"Source tree and metadata written to {result.out_dir}")
    print(f"Next: cyberjury review repository {result.out_dir} --profile evm --run", file=sys.stderr)
    return 0


def _normalize_review_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if getattr(args, "command", None) != "review":
        return
    scope = getattr(args, "scope", None)
    if scope == "diff":
        args.mode = args.mode or "standard"
        if args.mode == "standard":
            if args.rounds is not None:
                parser.error("--rounds applies only with --mode adversarial")
            args.rounds = 1
        else:
            args.rounds = args.rounds or DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
        if not str(args.model).strip():
            parser.error("--model must be a nonempty string")
        return
    if scope != "repository":
        return

    action = next(
        (name for name in ("scaffold", "gate", "run", "finalize") if getattr(args, name, False)),
        "",
    )
    explicit = getattr(args, "_explicit_long_options", set())
    if action in {"scaffold", "gate"}:
        unsupported = sorted(explicit.intersection(_MODEL_BACKEND_OPTIONS))
        if unsupported:
            parser.error(f"{unsupported[0]} does not apply to repository --{action}")
    if action == "run":
        args.mode = args.mode or "standard"
        if args.mode == "standard":
            if args.rounds is not None:
                parser.error("--rounds applies only with --mode adversarial")
            args.rounds = 1
        else:
            args.rounds = args.rounds or DEFAULT_REVIEW_SETTINGS.execution.default_adversarial_rounds
    else:
        if args.mode is not None:
            parser.error(f"--mode does not apply to repository --{action}")
        if args.rounds is not None:
            parser.error(f"--rounds does not apply to repository --{action}")
        args.mode = "standard"
        args.rounds = 1

    if action not in {"scaffold", "run"} and args.fresh:
        parser.error(f"--fresh does not apply to repository --{action}")
    if args.fresh and args.review_id is not None:
        parser.error("--fresh cannot be combined with --review-id")
    if action not in {"run", "finalize"} and args.concurrency is not None:
        parser.error(f"--concurrency does not apply to repository --{action}")
    if action != "run" and args.dry_run:
        parser.error(f"--dry-run does not apply to repository --{action}")
    if not str(args.model).strip():
        parser.error("--model must be a nonempty string")


def _dispatch_review_action(args: argparse.Namespace) -> int:
    scope = getattr(args, "scope", None)
    if scope == "diff":
        return _cmd_review_diff(args)
    if scope == "repository" and args.gate:
        return _cmd_repository_gate(args)
    if scope == "repository" and args.finalize:
        return _cmd_repository_finalize(args)
    if scope == "repository" and args.run:
        return _cmd_repository_run(args)
    if scope == "repository" and args.scaffold:
        return _cmd_repository_scaffold(args)
    raise ValueError(f"unknown review scope {scope!r}")


def _dispatch_profile_bound_action(args: argparse.Namespace) -> int:
    """Run one command against the exact profile content persisted by Stage 03."""
    resolution = _profile_resolution(args)
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
        args._active_profile = active_profile
        try:
            result = _dispatch_review_action(args)
        finally:
            del args._active_profile
    if not snapshot.matches():
        raise RuntimeError("profile content changed while the review command was running")
    return result


def _dispatch(args, parser) -> int:
    _normalize_review_args(args, parser)
    if args.command == "review" and getattr(args, "scope", None) is not None:
        attempt = _initialize_review_attempt(args)
        try:
            result = _dispatch_profile_bound_action(args)
        except KeyboardInterrupt:
            with contextlib.suppress(BaseException):
                attempt.interrupt()
            raise
        except BaseException as exc:
            with contextlib.suppress(BaseException):
                attempt.fail(exc)
            raise
        if result == 0 or attempt.request.action == "gate":
            attempt.complete(exit_code=result)
        else:
            attempt.incomplete(exit_code=result)
        return result
    if args.command == "install-slash-command":
        return _cmd_install_slash_command(args)
    if args.command == "fetch" and getattr(args, "fetch_kind", None) == "source":
        return _cmd_fetch_source(args)
    if args.command == "fetch":
        print("usage: cyberjury fetch source --chain <chain> --address 0x... --out <dir>", file=sys.stderr)
        return 1
    if args.command == "review":
        print("usage: cyberjury review {diff,repository} ...", file=sys.stderr)
        print("  diff   audit a unified diff for security findings", file=sys.stderr)
        print("  repository   scaffold or run a repository review", file=sys.stderr)
        return 1
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
