"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING

from cyberjury import __version__
from cyberjury.detection import load_detection
from cyberjury.envfile import load_env_file
from cyberjury.profiles.base import ReviewProfile
from cyberjury.profiles.registry import available_profiles, resolve_profile
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
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import (
    DiffExecutionOptions,
    DiffGroundingOptions,
    DiffReviewOptions,
    DiffReviewResult,
    DiffRoleOptions,
    DiffVerificationOptions,
    run_diff_review,
)
from cyberjury.review.diff.model import diff_paths, strip_unreviewable_files
from cyberjury.review.prompts import NAVIGATOR_SYSTEM
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from cyberjury.sources.explorer import CHAINS
from cyberjury.telemetry import progress, read_timeline, stage_timer

if TYPE_CHECKING:
    from cyberjury.profiles.base import PoCBackend
    from cyberjury.review.diff.model import DiffUnit
    from cyberjury.review.repository.engine import FinalizeResult, RunResult
    from cyberjury.review.trace import Trace
    from cyberjury.review.verification import Confirmer, Verifier

_FORMATS = ("text", "markdown", "json", "sarif")

_PROFILE_HELP = "review profile to use: 'auto' detects from the target's files, or name one of: " + ", ".join(
    available_profiles()
)
_PROFILE_SCAN_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target", "out"}
_REPOSITORY_BACKEND_FLAGS = {
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


def _repository_file_names(directory: str) -> list[str]:
    """File names under the target, for profile detection only.

    Names carry the extensions the heuristic counts, so the walk reads no file content and
    prunes the usual heavy directories to stay fast on a large repository.
    """
    names: list[str] = []
    for _root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in _PROFILE_SCAN_PRUNE)
        names.extend(sorted(files))
    return names


def _default_workspace() -> str:
    """Return a user-private path because the workspace holds sensitive review artifacts."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return str(Path(base) / "cyberjury" / "reviews")


def _read_diff(args) -> str:
    return subprocess.run(
        ["git", "-C", args.repository, "diff", args.git_range],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _git_range_ref(git_range: str) -> str | None:
    for sep in ("...", ".."):
        if sep in git_range:
            ref = git_range.rsplit(sep, 1)[1].strip()
            return ref or "HEAD"
    return None


@contextlib.contextmanager
def _diff_source_root(args):
    repository = Path(args.repository)
    ref = _git_range_ref(args.git_range)
    if ref is None:
        yield repository
        return
    tmp = Path(tempfile.mkdtemp(prefix="cyberjury-diff-target-"))
    try:
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "add", "--detach", "--quiet", str(tmp), ref],
            check=True,
            capture_output=True,
            text=True,
        )
        yield tmp
    finally:
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "remove", "--force", str(tmp)],
            check=False,
            capture_output=True,
            text=True,
        )
        shutil.rmtree(tmp, ignore_errors=True)


def _utc_now() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diff_should_verify(args) -> bool:
    return not args.dry_run


_MOCK_REPLY = '{"real": true, "findings": []}'

_REPOSITORY_MOCK_REPLY = '{"real": true, "reason": "mock", "findings": [], "rebuttals": [], "new_findings": []}'

_NAVIGATION_MOCK_REPLY = '{"evidence_requests": [], "source_queries": []}'


def _diff_dry_run_response(system: str, _messages: list[Message]) -> str:
    """Return one strict response for each Diff Review dry run phase."""
    if system == NAVIGATOR_SYSTEM:
        return _NAVIGATION_MOCK_REPLY
    return _MOCK_REPLY


def _repository_dry_run_response(system: str, _messages: list[Message]) -> str:
    """Return the canned response for the phase named by the dry run prompt."""
    if system == NAVIGATOR_SYSTEM:
        return _NAVIGATION_MOCK_REPLY
    return _REPOSITORY_MOCK_REPLY


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
    configuration = ProviderConfiguration(
        base=seat,
        finder=seat,
        challenger=seat,
        judge=seat,
        retries=args.retries,
        timeout=args.timeout,
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


def _seat_identity(args, spec) -> tuple:
    return ("api", spec.provider, spec.model, spec.api_base, spec.wire_api)


def _seat_label(args, spec) -> str:
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
    seen = {_seat_identity(args, challenger)}
    for spec in (judge, finder):
        if spec is None:
            continue
        key = _seat_identity(args, spec)
        if key in seen:
            continue
        seen.add(key)
        out.append((_seat_label(args, spec), _confirmer_for(args, spec, content)))
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
    if args.dry_run:
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
    _add_backend_args(p)
    for role in ROLES:
        _add_role_backend_args(p, role)
    p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    p.add_argument("--debug", action="store_true", help="emit review stage diagnostics")
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
        help="where to create the review workspace, defaults to a user-private "
        "directory under XDG_STATE_HOME or ~/.local/state",
    )
    repository.add_argument(
        "--fresh", action="store_true", help="clear a previous review's output in the workspace first"
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
    try:
        return create_diff_providers(_provider_configuration(args), args.mode)
    except ProviderCredentialsError as exc:
        raise SystemExit(str(exc)) from exc


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


def _prepare_diff_command(args: argparse.Namespace) -> _DiffCommandState:
    """Resolve diff input, profile, and provider seats before execution."""
    if args.dry_run:
        diff = _read_diff(args)
        return _DiffCommandState(
            diff=diff,
            profile=resolve_profile(args.profile, diff_paths(diff)),
            provider=MockProvider(responder=_diff_dry_run_response),
            model="mock",
        )
    diff = _read_diff(args)
    profile = resolve_profile(args.profile, diff_paths(diff))
    providers = _build_diff_providers(args)
    base = _base_spec(args)
    finder = _role_spec(args, "finder", base)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
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
        finder_label=_seat_label(args, finder),
        challenger_label=_seat_label(args, challenger),
        judge_label=_seat_label(args, judge),
        finder_spec=finder,
        challenger_spec=challenger,
        judge_spec=judge,
    )


def _trace_for(args: argparse.Namespace) -> Trace | None:
    """Return the stderr trace sink requested by the operator."""
    if not getattr(args, "debug", False):
        return None

    def trace(event: dict[str, object]) -> None:
        print(json.dumps(event, sort_keys=True), file=sys.stderr, flush=True)

    return trace


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
    if not _diff_should_verify(args):
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
    return (state.finder_label,) if args.mode == "standard" and state.finder_label else ()


def _run_diff_engine(
    args: argparse.Namespace,
    state: _DiffCommandState,
    source_root: Path,
    prepare_diff: Callable[[str], list[DiffUnit]],
) -> DiffReviewResult:
    """Run the diff engine with resolved command state."""
    verification_found_by = _configure_diff_verification(args, state)
    concurrency = _auto_concurrency(args.concurrency)
    with stage_timer("diff review"):
        return run_diff_review(
            state.diff,
            provider=state.provider,
            model=state.model,
            options=DiffReviewOptions(
                roles=DiffRoleOptions(
                    mode=args.mode,
                    max_rounds=args.rounds,
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
                grounding=DiffGroundingOptions(prepare_diff=prepare_diff),
                verification=DiffVerificationOptions(
                    root=str(source_root),
                    verifier=state.verifier,
                    confirmers=state.confirmers,
                    found_by=verification_found_by,
                    concurrency=concurrency,
                ),
                execution=DiffExecutionOptions(
                    concurrency=concurrency,
                    profile=state.profile,
                    on_batch=lambda done, total, secs: progress(f"batch {done}/{total} ({secs}s)"),
                    on_judgment=lambda done, total, label, secs: progress(
                        f"knowledge judgment {done}/{total} [{label}] ({secs}s)"
                    ),
                    trace=_trace_for(args),
                ),
            ),
        )


def _execute_diff_review(args: argparse.Namespace, state: _DiffCommandState) -> DiffReviewResult:
    """Collect repository grounding and execute one diff review."""
    _report_skipped_diff_files(state)
    with _diff_source_root(args) as source_root:
        with stage_timer("diff context"):
            context_collector = build_diff_context_collector(
                source_root,
                state.profile,
                review_diff=state.diff,
            )
        if context_collector.review_paths:
            progress(f"grounded diff context for {len(context_collector.review_paths)} changed source file(s)")
        return _run_diff_engine(args, state, source_root, context_collector.prepare)


def _report_diff_result(args: argparse.Namespace, result: DiffReviewResult) -> int:
    """Render findings and explicit incomplete state for the CLI."""
    print(render(args.fmt, result.outcome.findings))
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
    return 1 if result.outcome.degraded else 0


def _cmd_review_diff(args: argparse.Namespace) -> int:
    """Own the lifecycle for one Diff Review command."""
    _warn_secondary_env()
    state = _prepare_diff_command(args)
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
    return Path(args.workspace) / Path(args.directory).resolve().name


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

    profile = resolve_profile(args.profile, _repository_file_names(args.directory))
    detection = load_detection(profile.paths.detection_file)
    project_dir = _repo_ws(args)
    result = check_gate(project_dir, root=Path(args.directory).resolve(), detection=detection)
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
    if args.dry_run or profile.poc_backend is None:
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


def _prepare_repository_resources(args: argparse.Namespace, *, finder_confirms: bool) -> _RepositoryResources:
    from cyberjury.review.verification import ModelVerifier

    profile = resolve_profile(args.profile, _repository_file_names(args.directory))
    _warn_secondary_env()
    base = _base_spec(args)
    finder = _role_spec(args, "finder", base)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
    args._usage_meter = UsageMeter()
    verification_provider = None
    verifier = None
    confirmers = []
    poc_provider = None
    try:
        if args.dry_run:
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


def _execute_repository_finalize(args: argparse.Namespace, resources: _RepositoryResources) -> FinalizeResult:
    from cyberjury.review.repository.engine import (
        RepositoryFinalizeOptions,
        RepositoryOutputOptions,
        RepositoryVerificationOptions,
        finalize_repository_review,
    )

    print(f"Finalizing {args.directory}: dedup + verify + report ...", file=sys.stderr)
    return finalize_repository_review(
        args.directory,
        args.workspace,
        options=RepositoryFinalizeOptions(
            verification=RepositoryVerificationOptions(
                verifier=resources.verifier,
                confirmers=resources.confirmers,
                provider=resources.verification_provider,
                model=resources.verification_model,
                votes=DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
                concurrency=_auto_concurrency(args.concurrency),
                on_verify=_verify_progress,
            ),
            output=RepositoryOutputOptions(
                profile=resources.profile,
                poc_backend=resources.poc_backend,
                meter=args._usage_meter,
            ),
        ),
    )


def _report_repository_finalize(args: argparse.Namespace, result: FinalizeResult) -> int:
    kept = len(result.verify.confirmed) if result.verify else result.deduped
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
    _note_verify_route(args, resources.confirmers)
    try:
        return _report_repository_finalize(args, _execute_repository_finalize(args, resources))
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


def _prepare_repository_run_resources(args: argparse.Namespace) -> _RepositoryRunState:
    """Resolve repository profile, role seats, verification, and PoC resources."""
    resources = _prepare_repository_resources(args, finder_confirms=True)
    provider = challenger_provider = judge_provider = None
    try:
        if args.dry_run:
            provider = MockProvider(responder=_repository_dry_run_response)
            role_provider = provider if args.mode == "adversarial" else None
            return _RepositoryRunState(
                resources=resources,
                provider=provider,
                model="mock",
                challenger_provider=role_provider,
                judge_provider=role_provider,
            )
        _require_key(resources.finder)
        provider = _role_provider(args, resources.finder)
        if args.mode == "adversarial":
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


def _execute_repository_run(args: argparse.Namespace, state: _RepositoryRunState) -> RunResult:
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

    print(f"Running the coded review engine over {args.directory} ...", file=sys.stderr)
    return run_repository_review(
        args.directory,
        args.workspace,
        options=RepositoryRunOptions(
            roles=RepositoryRoleOptions(
                mode=args.mode,
                provider=state.provider,
                model=state.model,
                challenger_provider=state.challenger_provider,
                challenger_model=state.resources.challenger.model,
                judge_provider=state.judge_provider,
                judge_model=state.resources.judge.model,
            ),
            verification=RepositoryVerificationOptions(
                enabled=not args.dry_run,
                verifier=state.resources.verifier,
                confirmers=state.resources.confirmers,
                votes=DEFAULT_REVIEW_SETTINGS.execution.verification_votes_required,
                concurrency=_auto_concurrency(args.concurrency),
                on_verify=_verify_progress,
            ),
            execution=RepositoryExecutionOptions(
                max_passes=args.rounds if args.mode == "adversarial" else 1,
                converge_after=DEFAULT_REVIEW_SETTINGS.execution.clean_rounds_to_converge,
                min_rounds=1,
                concurrency=_auto_concurrency(args.concurrency),
                on_pass=_repository_pass_progress,
                on_judgment=lambda unit, done, total, label, secs: print(
                    f"  unit {unit} knowledge judgment {done}/{total} [{label}] ({secs}s)",
                    file=sys.stderr,
                ),
            ),
            lifecycle=RepositoryLifecycleOptions(fresh=args.fresh),
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
        outcome.findings if outcome is not None else result.verify.confirmed if result.verify else accumulator.findings
    )
    by_severity: dict[str, int] = {}
    for candidate in reported:
        by_severity[candidate.severity] = by_severity.get(candidate.severity, 0) + 1
    print(
        f"Engine done: {result.units} units, {len(accumulator.new_per_pass)} passes, converged={accumulator.converged}."
    )
    if result.verify is not None:
        print(
            f"Union {len(accumulator.findings)} -> verified {len(reported)} confirmed, "
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
    if args.mode == "adversarial" and not accumulator.converged:
        print(
            f"WARNING: the union did not converge within {args.rounds} rounds, it was "
            "still finding new issues when the cap stopped it. Coverage is incomplete and "
            "recall is not guaranteed. Raise --rounds or narrow the scope and re-run.",
            file=sys.stderr,
        )
    print(f"Findings written to {result.scaffold.workspace}/findings/ and {result.scaffold.workspace}/findings.json")
    if args._usage_meter.model_requests:
        print(args._usage_meter.summary(), file=sys.stderr)
    incomplete = outcome.degraded if outcome is not None else args.mode == "adversarial" and not accumulator.converged
    return 1 if review_errors or verify_errors or incomplete else 0


@_timed_stage("run")
def _cmd_repository_run(args: argparse.Namespace) -> int:
    """Own the lifecycle for one Repository Review run command."""
    state = _prepare_repository_run_resources(args)
    _note_verify_route(args, state.resources.confirmers)
    try:
        return _report_repository_run(args, _execute_repository_run(args, state))
    finally:
        _close_backends(
            state.provider,
            state.challenger_provider,
            state.judge_provider,
        )
        _close_repository_resources(state.resources)


@_timed_stage("scaffold", reset=True)
def _cmd_repository_scaffold(args) -> int:
    profile = resolve_profile(args.profile, _repository_file_names(args.directory))
    res = scaffold(
        args.directory,
        args.workspace,
        fresh=args.fresh,
        profile=profile,
    )
    (Path(res.workspace) / "methodology.md").write_text(res.methodology, encoding="utf-8")
    if res.cleared:
        print(f"Cleared {len(res.cleared)} prior-run paths in {res.workspace}", file=sys.stderr)
    elif res.had_prior_run:
        print(
            f"A previous review's output is in {res.workspace}. Re-run with --fresh to clear it first.",
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
        f"`cyberjury review repository {args.directory} --workspace {args.workspace} --run`, "
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
        unsupported = sorted(explicit.intersection(_REPOSITORY_BACKEND_FLAGS))
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
    if action not in {"run", "finalize"} and args.concurrency is not None:
        parser.error(f"--concurrency does not apply to repository --{action}")
    if action != "run" and args.dry_run:
        parser.error(f"--dry-run does not apply to repository --{action}")
    if not str(args.model).strip():
        parser.error("--model must be a nonempty string")


def _dispatch(args, parser) -> int:
    _normalize_review_args(args, parser)
    scope = getattr(args, "scope", None)
    if args.command == "review" and scope == "diff":
        return _cmd_review_diff(args)
    if args.command == "review" and scope == "repository" and args.gate:
        return _cmd_repository_gate(args)
    if args.command == "review" and scope == "repository" and args.finalize:
        return _cmd_repository_finalize(args)
    if args.command == "review" and scope == "repository" and args.run:
        return _cmd_repository_run(args)
    if args.command == "review" and scope == "repository" and args.scaffold:
        return _cmd_repository_scaffold(args)
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
