"""Command line argument parsing, provider seat resolution, and command dispatch."""

from __future__ import annotations

import argparse
import contextlib
import functools
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC
from pathlib import Path

from cyberjury import __version__
from cyberjury.detection import load_detection
from cyberjury.domains.registry import available_domains, resolve_domain
from cyberjury.envfile import load_env_file
from cyberjury.providers.factory import PROVIDERS, ROLES, env_defaults, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.report import render
from cyberjury.resources import SLASH_COMMAND_FILE
from cyberjury.review.diff.context import build_diff_context_collector
from cyberjury.review.diff.engine import audit_diff, strip_noise_files
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.sources.explorer import CHAINS
from cyberjury.telemetry import progress, read_timeline, stage_timer

_FORMATS = ("text", "markdown", "json", "sarif")

_DOMAIN_HELP = "review domain to use: 'auto' detects from the target's files, or name one of: " + ", ".join(
    available_domains()
)
_DOMAIN_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target", "out"}


def _add_domain_arg(p) -> None:
    p.add_argument("--domain", default="auto", metavar="DOMAIN", help=_DOMAIN_HELP)


def _repository_file_names(directory: str) -> list[str]:
    """File names under the target, for domain detection only.

    Names carry the extensions the heuristic counts, so the walk reads no file content and
    prunes the usual heavy directories to stay fast on a large repository.
    """
    names: list[str] = []
    for _root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _DOMAIN_PRUNE]
        names.extend(files)
    return names


def _diff_paths(diff: str) -> list[str]:
    """The changed file paths named in a unified diff, for domain detection."""
    return re.findall(r"(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", diff)


def _default_workspace() -> str:
    """A user-private default, since the workspace holds the auth model, exploit paths.

    and PoCs.
    """
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return str(Path(base) / "cyberjury" / "reviews")


def _read_diff(args) -> str:
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            return f.read()
    if args.git_range:
        return subprocess.run(
            ["git", "-C", args.repository or ".", "diff", args.git_range],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return sys.stdin.read()


def _git_range_ref(git_range: str) -> str | None:
    for sep in ("...", ".."):
        if sep in git_range:
            ref = git_range.rsplit(sep, 1)[1].strip()
            return ref or "HEAD"
    return None


@contextlib.contextmanager
def _diff_source_root(args):
    repository = Path(args.repository or ".")
    if not args.git_range:
        yield repository
        return
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


def _dry_run_diff() -> str:
    return "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _utc_now() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diff_has_source_root(args) -> bool:
    return bool(args.git_range or args.repository)


def _diff_should_verify(args) -> bool:
    return not args.dry_run and _diff_has_source_root(args)


_MOCK_REPLY = (
    '{"real": true, "findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
    '"category": "sql_injection", "description": "[mock] no backend called", '
    '"confidence": 0.9}]}'
)

_REPOSITORY_MOCK_REPLY = (
    '{"real": true, "reason": "mock", "findings": [{"title": "[mock] no backend called", '
    '"category": "other", "endpoint": "GET /mock", "file": "mock.py", "line": 1, '
    '"severity": "MEDIUM", "evidence": "mock.py:1", "status": "confirmed"}], '
    '"rebuttals": [], "new_findings": []}'
)


def _base_spec(args):
    """The base backend each role inherits from when its own field is unset."""
    return {
        "provider": args.provider,
        "model": args.model,
        "api_key": args.api_key,
        "api_base": args.api_base,
        "wire_api": args.wire_api,
    }


def _role_spec(args, role, base):
    """Resolve one role's backend, each field inheriting the base when its own is unset.

    A role that overrides the provider to a different vendor does not inherit the base key
    or endpoint, which belong to the base vendor, it falls back to its own field or the SDK
    env.
    """
    provider = getattr(args, f"{role}_provider") or base["provider"]
    same_vendor = provider == base["provider"]
    return {
        "provider": provider,
        "model": getattr(args, f"{role}_model") or base["model"],
        "api_key": getattr(args, f"{role}_api_key") or (base["api_key"] if same_vendor else None),
        "api_base": getattr(args, f"{role}_api_base") or (base["api_base"] if same_vendor else None),
        "wire_api": getattr(args, f"{role}_wire_api") or base["wire_api"],
    }


def _role_provider(args, spec):
    """Build a provider for a resolved role spec.

    Construction is lazy, so a per-role provider object is cheap, no SDK or key is touched
    until a call is made. When the run has set a usage meter, every seat is wrapped so one
    shared total spans finder, skeptic, and confirmers.
    """
    provider = make_provider(
        spec["provider"],
        api_key=spec["api_key"],
        api_base=spec["api_base"],
        retries=args.retries,
        wire_api=spec["wire_api"],
        timeout=args.timeout,
    )
    meter = getattr(args, "_usage_meter", None)
    return MeteringProvider(provider, meter) if meter is not None else provider


_SDK_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def _key_reachable(spec) -> bool:
    """Whether a seat can authenticate a provider call.

    It carries a key, or its vendor SDK env var is set so the SDK finds one.
    """
    if spec["api_key"]:
        return True
    env = _SDK_KEY_ENV.get(spec["provider"])
    return bool(env and os.environ.get(env))


def _require_key(spec) -> None:
    """Fail before a review starts when a provider seat cannot authenticate."""
    if _key_reachable(spec):
        return
    sdk_key = _SDK_KEY_ENV.get(spec["provider"], "the provider SDK key")
    raise SystemExit(
        f"the {spec['provider']} seat has no reachable API key. Set CYBERJURY_API_KEY, {sdk_key}, "
        "or a role-specific API key."
    )


def _warn_secondary_env() -> None:
    """Warn when the deprecated CYBERJURY_SECONDARY_* names are still set so they are not.

    silently ignored. They are no longer read, the per-role CYBERJURY_CHALLENGER_* and
    CYBERJURY_JUDGE_* names replace them.
    """
    if any(k.startswith("CYBERJURY_SECONDARY_") for k in os.environ):
        print(
            "NOTE: CYBERJURY_SECONDARY_* is no longer read. Use CYBERJURY_CHALLENGER_* for the "
            "skeptic and CYBERJURY_JUDGE_* for the confirmer.",
            file=sys.stderr,
        )


def _confirmer_for(args, spec):
    """One confirmer's `RefutationChecker`, resolved from the role's API backend."""
    from cyberjury.review.repository.verifier import ModelRefutationChecker

    _require_key(spec)
    return ModelRefutationChecker(provider=_role_provider(args, spec), model=spec["model"])


def _verifier_for(args, spec, content):
    """One skeptic verifier, resolved by the role's API backend."""
    from cyberjury.review.repository.verifier import ModelVerifier

    _require_key(spec)
    return ModelVerifier(provider=_role_provider(args, spec), model=spec["model"], content=content)


def _seat_identity(args, spec) -> tuple:
    return ("api", spec["provider"], spec["model"], spec.get("api_base"), spec.get("wire_api"))


def _seat_label(args, spec) -> str:
    return spec["model"]


def _confirmers(args, *, challenger, judge, finder=None):
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
        out.append((_seat_label(args, spec), _confirmer_for(args, spec)))
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
    """The model-backend flags shared by both review paths.

    so the two parsers cannot drift on a default. `target` is a parser or an argument group,
    both expose add_argument.
    """
    d = env_defaults()
    target.add_argument("--provider", choices=PROVIDERS, default=d["provider"])
    target.add_argument("--model", default=d["model"])
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
        "--retries", type=int, default=d["retries"], help="provider retry attempts on transient failure"
    )
    target.add_argument(
        "--timeout",
        type=float,
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
    p.add_argument("--file", default=None, help="unified diff file (default: read stdin)")
    p.add_argument("--repository", default=None, help="repository path for --git-range")
    p.add_argument("--git-range", default=None, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="run the engine with a mock provider and no key (a built-in demo diff if none is given)",
    )
    p.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    p.add_argument("--rounds", type=int, default=3, help="adversarial only: role rounds")
    p.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="verification calls to run in parallel, default 8",
    )
    _add_backend_args(p)
    for role in ROLES:
        _add_role_backend_args(p, role)
    p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    _add_domain_arg(p)


def _auto_concurrency(concurrency: int | None) -> int:
    """Pick the API fan-out parallelism when the operator set none."""
    if concurrency is not None:
        return concurrency
    return 8


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    env_loaded = load_env_file()
    if env_loaded:
        n = len(env_loaded)
        plural = "s" if n != 1 else ""
        print(f"loaded {n} setting{plural} from .env: {', '.join(env_loaded)}", file=sys.stderr)
    parser = argparse.ArgumentParser(prog="cyberjury")
    parser.add_argument("--version", action="version", version=f"cyberjury {__version__}")
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review", help="review code for security findings")
    rsub = review.add_subparsers(dest="scope")
    _add_audit_args(rsub.add_parser("diff", help="audit a unified diff (the coded engine)"))
    repository = rsub.add_parser(
        "repository", help="run a whole-repository review: --scaffold, --run, --finalize, or --gate"
    )
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
        help="build the review workspace: detect the stack, slice units, seed the inventory, "
        "the prerequisite for --run, --finalize, and --gate",
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
    strategy.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    strategy.add_argument("--rounds", type=int, default=3, help="adversarial only: role rounds")

    tuning = repository.add_argument_group("run tuning", "applies to --run and --finalize")
    tuning.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="how many unit reviews or verification calls run in parallel, default 8",
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

    _add_domain_arg(repository)

    fetch = sub.add_parser("fetch", help="fetch verified source for a contract address")
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

    inst = sub.add_parser(
        "install-slash-command", help="install the /cyberjury-review slash command for Claude Code and Codex"
    )
    inst.add_argument(
        "--dir", default=None, help="install into this one directory instead of the agent command directories"
    )
    inst.add_argument(
        "--force", action="store_true", help="overwrite an existing cyberjury-review.md at the destination"
    )

    args = parser.parse_args(argv)
    try:
        return _dispatch(args, parser)
    except Exception as exc:
        label = getattr(args, "command", None) or "cyberjury"
        print(f"{label} failed: {exc}", file=sys.stderr)
        return 1


def _diff_provider(args, spec):
    """A diff seat's API provider for its resolved role spec."""
    _require_key(spec)
    return _role_provider(args, spec)


def build_diff_providers(args):
    """Resolve the diff seats into providers exactly as `review diff` does.

    so a non-CLI caller such as the eval runs a case through the same wiring a user gets.
    Returns the base provider and model the audit needs plus the per-role finder,
    challenger, and judge providers and models, the role fields None in standard mode. The
    single source the CLI and the eval share, so the probe cannot drift from the product on
    which model or seat reviews a diff.
    """
    base = _base_spec(args)
    finder = _role_spec(args, "finder", base)
    if args.mode == "adversarial":
        roles = {
            "finder": finder,
            "challenger": _role_spec(args, "challenger", base),
            "judge": _role_spec(args, "judge", base),
        }
        fp = _diff_provider(args, roles["finder"])
        cp = _diff_provider(args, roles["challenger"])
        jp = _diff_provider(args, roles["judge"])
        return (
            fp,
            roles["finder"]["model"],
            fp,
            roles["finder"]["model"],
            cp,
            roles["challenger"]["model"],
            jp,
            roles["judge"]["model"],
        )
    finder_provider = _diff_provider(args, finder)
    return (finder_provider, finder["model"], None, None, None, None, None, None)


def diff_args_from_env(mode: str, *, rounds: int = 3):
    """A diff args namespace from the environment defaults.

    the same values `review diff` reads when no flag is passed, so `build_diff_providers`
    builds the user's real wiring. Lets the eval drive the audit through the product path
    rather than a hardcoded provider.
    """
    from types import SimpleNamespace

    load_env_file()
    defaults = env_defaults()
    ns = {
        "provider": defaults["provider"],
        "model": defaults["model"],
        "api_key": defaults["api_key"],
        "api_base": defaults["api_base"],
        "wire_api": defaults["wire_api"],
        "retries": defaults["retries"],
        "timeout": defaults["timeout"],
        "mode": mode,
        "rounds": rounds,
        "concurrency": None,
    }
    for role in ROLES:
        d = defaults["role_backends"][role]
        ns[f"{role}_provider"] = d["provider"]
        ns[f"{role}_model"] = d["model"]
        ns[f"{role}_api_key"] = d["api_key"]
        ns[f"{role}_api_base"] = d["api_base"]
        ns[f"{role}_wire_api"] = d["wire_api"]
    return SimpleNamespace(**ns)


def _cmd_review_diff(args) -> int:
    _warn_secondary_env()
    finder_provider = challenger_provider = judge_provider = None
    finder_model = challenger_model = judge_model = None
    finder_label = challenger_label = judge_label = None
    verifier = None
    verification_confirmers: list = []
    verification_found_by: tuple[str, ...] = ()
    if args.dry_run:
        provider = MockProvider(default=_MOCK_REPLY)
        model = "mock"
        diff = _read_diff(args) if (args.file or args.git_range) else _dry_run_diff()
        domain = resolve_domain(args.domain, _diff_paths(diff))
    else:
        diff = _read_diff(args)
        domain = resolve_domain(args.domain, _diff_paths(diff))
        (
            provider,
            model,
            finder_provider,
            finder_model,
            challenger_provider,
            challenger_model,
            judge_provider,
            judge_model,
        ) = build_diff_providers(args)
        base = _base_spec(args)
        finder = _role_spec(args, "finder", base)
        challenger = _role_spec(args, "challenger", base)
        judge = _role_spec(args, "judge", base)
        finder_label = _seat_label(args, finder)
        challenger_label = _seat_label(args, challenger)
        judge_label = _seat_label(args, judge)
    try:
        _, skipped_noise = strip_noise_files(diff, load_detection(domain.paths.detection_file))
        if skipped_noise:
            shown = ", ".join(skipped_noise[:5])
            more = f", and {len(skipped_noise) - 5} more" if len(skipped_noise) > 5 else ""
            progress(f"skipped {len(skipped_noise)} non-source file(s): {shown}{more}")
        context = ""
        context_for_diff = None
        with _diff_source_root(args) as source_root:
            if _diff_has_source_root(args):
                with stage_timer("diff context"):
                    context_collector = build_diff_context_collector(source_root, domain)
                    ctx = context_collector.collect(diff)
                    context = ctx.text
                    context_for_diff = context_collector.text_for_diff
                if ctx.files:
                    progress(f"grounded diff context for {len(ctx.files)} changed source file(s)")
            if _diff_should_verify(args):
                verifier = _verifier_for(args, challenger, domain.paths)
                verification_confirmers = _confirmers(
                    args,
                    challenger=challenger,
                    judge=judge,
                    finder=finder,
                )
                if args.mode == "standard":
                    verification_found_by = (finder_label,)
                verification_concurrency = _auto_concurrency(args.concurrency)
                _note_verify_route(args, verification_confirmers)
            else:
                verification_concurrency = _auto_concurrency(args.concurrency)
            batch_failures = []
            with stage_timer("diff review"):
                kept, _, degraded = audit_diff(
                    diff,
                    provider=provider,
                    model=model,
                    mode=args.mode,
                    max_rounds=args.rounds,
                    finder_model=finder_model,
                    challenger_model=challenger_model,
                    judge_model=judge_model,
                    finder_provider=finder_provider,
                    challenger_provider=challenger_provider,
                    judge_provider=judge_provider,
                    finder_label=finder_label,
                    challenger_label=challenger_label,
                    judge_label=judge_label,
                    context=context,
                    context_for_diff=context_for_diff,
                    verification_root=str(source_root),
                    verifier=verifier,
                    verification_confirmers=verification_confirmers,
                    verification_found_by=verification_found_by,
                    verification_concurrency=verification_concurrency,
                    batch_failures=batch_failures,
                    domain=domain,
                    on_batch=lambda done, total, secs: progress(f"batch {done}/{total} ({secs}s)"),
                )
        print(render(args.fmt, kept))
        for failure in batch_failures:
            paths = ", ".join(failure.paths[:3])
            more = f", and {len(failure.paths) - 3} more" if len(failure.paths) > 3 else ""
            print(
                f"error: diff batch {failure.index}/{failure.total} failed for {paths}{more}: {failure.reason}",
                file=sys.stderr,
            )
        if degraded:
            print(
                "error: the diff audit degraded because a judgment or verification step failed, "
                "the result is incomplete and not a clean pass",
                file=sys.stderr,
            )
        return 1 if degraded else 0
    finally:
        _close_backends(
            provider,
            finder_provider,
            challenger_provider,
            judge_provider,
            verifier,
            *(chk for _label, chk in verification_confirmers),
        )


def _repo_ws(args) -> Path:
    """The per-target workspace directory, where the run artifacts and the timeline live."""
    return Path(args.workspace) / Path(args.directory).resolve().name


def _verify_progress(done: int, total: int, secs: float) -> None:
    """Per-candidate heartbeat for the verify fan-out, shared by the run and finalize commands."""
    progress(f"verified {done}/{total} ({secs}s)")


def _timed_stage(name: str, *, reset: bool = False):
    """Wrap a repository stage command so it records its elapsed to the workspace timeline and.

    prints it to stderr, giving a whole-pipeline cost readable across the separate commands.
    """

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

    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    detection = load_detection(domain.paths.detection_file)
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


@_timed_stage("finalize")
def _cmd_repository_finalize(args) -> int:
    from cyberjury.review.repository.engine import finalize_repository_review
    from cyberjury.review.repository.verifier import ModelVerifier

    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    _warn_secondary_env()
    base = _base_spec(args)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
    provider = None
    verifier_obj = None
    confirmers: list = []
    args._usage_meter = UsageMeter()
    if args.dry_run:
        provider = MockProvider(default='{"real": true, "reason": "[mock]"}')
        args.model = "mock"
    else:
        _require_key(challenger)
        verifier_obj = ModelVerifier(
            provider=_role_provider(args, challenger), model=challenger["model"], content=domain.paths
        )
    if not args.dry_run:
        confirmers = _confirmers(args, challenger=challenger, judge=judge)
    _note_verify_route(args, confirmers)
    concurrency = _auto_concurrency(args.concurrency)
    poc_backend_obj = None
    poc_provider = None
    if not args.dry_run and domain.poc_backend is not None:
        _require_key(base)
        gen_provider = _role_provider(args, base)
        poc_provider = gen_provider
        poc_backend_obj = domain.poc_backend(provider=gen_provider, model=base["model"])
        if getattr(poc_backend_obj, "executes", True) and not poc_backend_obj.available():
            hint = getattr(poc_backend_obj, "install_hint", "")
            print(
                f"NOTE: PoC toolchain not found, PoCs will be written but not run here. {hint}".rstrip(),
                file=sys.stderr,
            )
    print(f"Finalizing {args.directory}: dedup + verify + report ...", file=sys.stderr)
    try:
        fr = finalize_repository_review(
            args.directory,
            args.workspace,
            verifier=verifier_obj,
            confirmers=confirmers,
            provider=provider,
            model=args.model,
            verify=True,
            votes=1,
            concurrency=concurrency,
            domain=domain,
            poc_backend=poc_backend_obj,
            on_verify=_verify_progress,
            meter=args._usage_meter,
        )
        kept = len(fr.verify.confirmed) if fr.verify else fr.deduped
        refuted = len(fr.verify.refuted) if fr.verify else 0
        print(
            f"Finalize done: parsed {fr.parsed} candidates -> {fr.deduped} after dedup -> "
            f"{kept} confirmed, {refuted} refuted, see {fr.workspace}/_refuted.md."
        )
        print(f"Confirmed findings in {fr.workspace}/findings/ and {fr.workspace}/findings.json")
        if (Path(fr.workspace) / "_pocs.md").exists():
            print(f"PoC reconciliation in {fr.workspace}/_pocs.md")
        if args._usage_meter.model_requests:
            print(args._usage_meter.summary(), file=sys.stderr)
        _warn_unlocatable(fr.verify)
        if fr.verify and fr.verify.errors:
            print(f"WARNING: {fr.verify.errors} verification calls failed. Re-run to resume.", file=sys.stderr)
            return 1
        return 0
    finally:
        _close_backends(verifier_obj, poc_provider, *(chk for _label, chk in confirmers))


@_timed_stage("run")
def _cmd_repository_run(args) -> int:
    from cyberjury.review.repository.engine import run_repository_review
    from cyberjury.review.repository.verifier import ModelVerifier

    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    _warn_secondary_env()
    base = _base_spec(args)
    finder = _role_spec(args, "finder", base)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
    reviewer_obj = challenger_reviewer_obj = judge_reviewer_obj = verifier_obj = None
    provider = challenger_provider = judge_provider = None
    model = args.model
    confirmers: list = []
    args._usage_meter = UsageMeter()
    poc_backend_obj = None
    poc_provider = None
    if args.dry_run:
        provider = MockProvider(default=_REPOSITORY_MOCK_REPLY)
        if args.mode == "adversarial":
            challenger_provider = provider
            judge_provider = provider
        model = "mock"
    else:
        _require_key(finder)
        provider = _role_provider(args, finder)
        model = finder["model"]
        if args.mode == "adversarial":
            _require_key(challenger)
            _require_key(judge)
            challenger_provider = _role_provider(args, challenger)
            judge_provider = _role_provider(args, judge)
        _require_key(challenger)
        verifier_obj = ModelVerifier(
            provider=_role_provider(args, challenger), model=challenger["model"], content=domain.paths
        )
        confirmers = _confirmers(args, challenger=challenger, judge=judge, finder=finder)
        if domain.poc_backend is not None:
            _require_key(base)
            poc_provider = _role_provider(args, base)
            poc_backend_obj = domain.poc_backend(provider=poc_provider, model=base["model"])
            if getattr(poc_backend_obj, "executes", True) and not poc_backend_obj.available():
                hint = getattr(poc_backend_obj, "install_hint", "")
                print(
                    f"NOTE: PoC toolchain not found, PoCs will be written but not run here. {hint}".rstrip(),
                    file=sys.stderr,
                )

    concurrency = _auto_concurrency(args.concurrency)

    def _progress(p, reviewer_label, new, total):
        print(f"  pass {p} [{reviewer_label}]  +{new} new  union={total}", file=sys.stderr)

    _note_verify_route(args, confirmers)
    print(f"Running the coded review engine over {args.directory} ...", file=sys.stderr)
    try:
        res = run_repository_review(
            args.directory,
            args.workspace,
            provider=provider,
            model=model,
            challenger_provider=challenger_provider,
            challenger_model=challenger["model"],
            judge_provider=judge_provider,
            judge_model=judge["model"],
            reviewer=reviewer_obj,
            challenger_reviewer=challenger_reviewer_obj,
            judge_reviewer=judge_reviewer_obj,
            verifier=verifier_obj,
            confirmers=confirmers,
            verify=True,
            votes=1,
            mode=args.mode,
            max_passes=args.rounds if args.mode == "adversarial" else 1,
            converge_after=2,
            min_rounds=1,
            concurrency=concurrency,
            fresh=args.fresh,
            on_pass=_progress,
            on_verify=_verify_progress,
            domain=domain,
            poc_backend=poc_backend_obj,
            meter=args._usage_meter,
        )
        if res.scaffold.fallback_note:
            print(f"NOTE: {res.scaffold.fallback_note}.", file=sys.stderr)
        acc = res.accumulator
        reported = res.verify.confirmed if res.verify else acc.findings
        by_sev: dict[str, int] = {}
        for c in reported:
            by_sev[c.severity] = by_sev.get(c.severity, 0) + 1
        print(f"Engine done: {res.units} units, {len(acc.new_per_pass)} passes, converged={acc.converged}.")
        if res.verify is not None:
            print(
                f"Union {len(acc.findings)} -> verified {len(reported)} confirmed, "
                f"{len(res.verify.refuted)} refuted, see {res.scaffold.workspace}/_refuted.md."
            )
        print(
            f"{len(reported)} findings: "
            + ", ".join(f"{by_sev.get(s, 0)} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        )
        _warn_unlocatable(res.verify)
        failures = acc.errors + (res.verify.errors if res.verify else 0)
        if failures:
            print(
                f"WARNING: {failures} model calls failed, e.g. provider errors or rate limits. "
                "Results may be understated. Raise --retries and re-run.",
                file=sys.stderr,
            )
        if args.mode == "adversarial" and not acc.converged:
            print(
                f"WARNING: the union did not converge within {args.rounds} rounds, it was "
                "still finding new issues when the cap stopped it. Coverage is incomplete and "
                "recall is not guaranteed. Raise --rounds or narrow the scope and re-run.",
                file=sys.stderr,
            )
        print(f"Findings written to {res.scaffold.workspace}/findings/ and {res.scaffold.workspace}/findings.json")
        if args._usage_meter.model_requests:
            print(args._usage_meter.summary(), file=sys.stderr)
        incomplete = args.mode == "adversarial" and not acc.converged
        return 1 if failures or incomplete else 0
    finally:
        _close_backends(
            reviewer_obj,
            challenger_reviewer_obj,
            judge_reviewer_obj,
            provider,
            challenger_provider,
            judge_provider,
            verifier_obj,
            poc_provider,
            *(chk for _label, chk in confirmers),
        )


@_timed_stage("scaffold", reset=True)
def _cmd_repository_scaffold(args) -> int:
    ignored = [
        flag
        for flag, used in (
            ("--dry-run", args.dry_run),
            ("--concurrency", args.concurrency is not None),
        )
        if used
    ]
    if ignored:
        print(
            f"NOTE: {', '.join(ignored)} do not affect --scaffold. Add --run or --finalize where the flag applies.",
            file=sys.stderr,
        )
    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    res = scaffold(
        args.directory,
        args.workspace,
        fresh=args.fresh,
        domain=domain,
    )
    (Path(res.workspace) / "METHODOLOGY.md").write_text(res.methodology, encoding="utf-8")
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
        f"{len(res.trace_targets)} logic-layer trace targets into "
        f"{res.workspace}/inventory/_entrypoints.md",
        file=sys.stderr,
    )
    if res.fallback_note:
        print(f"NOTE: {res.fallback_note}.", file=sys.stderr)
    print(f"Methodology: {res.workspace}/METHODOLOGY.md", file=sys.stderr)
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
    print("Run it with: /cyberjury-review <repository or diff> [--domain auto|web|evm]")
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
    print(f"Next: cyberjury review repository {result.out_dir} --domain evm --run", file=sys.stderr)
    return 0


def _dispatch(args, parser) -> int:
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
        print("  repository   scaffold or run a whole-repository review", file=sys.stderr)
        return 1
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
