"""Command line interface: argument parsing, backend seat resolution, and command dispatch.

Two paths matched to their nature:

- ``review diff`` runs the coded diff engine over a unified diff: a single
  balanced call in standard mode or the adversarial Finder/Challenger/Judge pass.
- ``review repository <dir>`` drives a whole-repository review from a fan-out workspace. It
  requires one explicit mode. ``--scaffold`` builds the workspace for an interactive agent to
  follow the methodology. ``--run`` runs the coded multi-pass engine to convergence,
  ``--finalize`` dedups and adversarially verifies the candidates an agent or a run proposed,
  and ``--gate`` checks completeness.

``review diff --dry-run`` exercises the engine with a mock provider and no key.
The audit orchestration itself lives in ``cyberjury.review.diff.engine``.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import os
import re
import subprocess
import sys
from datetime import UTC
from pathlib import Path

from cyberjury import __version__
from cyberjury.detection import load_detection
from cyberjury.domains.registry import available_domains, resolve_domain
from cyberjury.envfile import load_env_file
from cyberjury.providers.factory import PROVIDERS, ROLES, env_defaults, make_provider
from cyberjury.providers.metering import MeteringProvider, UsageMeter
from cyberjury.providers.mock import MockProvider
from cyberjury.report import gate, render
from cyberjury.resources import SLASH_COMMAND_FILE
from cyberjury.review.diff.engine import audit_diff, strip_noise_files
from cyberjury.review.repository.scaffold import scaffold
from cyberjury.sources.explorer import CHAINS
from cyberjury.telemetry import progress, read_timeline, stage_timer

_FORMATS = ("text", "markdown", "json", "sarif")
_FAIL_ON = ("critical", "high", "medium", "low")

_DOMAIN_HELP = "review domain to use: 'auto' detects from the target's files, or name one of: " + ", ".join(
    available_domains()
)
_DOMAIN_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__", "build", "dist", "target", "out"}


def _add_domain_arg(p) -> None:
    p.add_argument("--domain", default="auto", metavar="DOMAIN", help=_DOMAIN_HELP)


def _repository_file_names(directory: str) -> list[str]:
    """File names under the target, for domain detection only. Names carry the
    extensions the heuristic counts, so the walk reads no file content and prunes the
    usual heavy directories to stay fast on a large repository."""
    names: list[str] = []
    for _root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _DOMAIN_PRUNE]
        names.extend(files)
    return names


def _diff_paths(diff: str) -> list[str]:
    """The changed file paths named in a unified diff, for domain detection."""
    return re.findall(r"(?:\+\+\+ b/|diff --git a/\S+ b/)(\S+)", diff)


def _default_workspace() -> str:
    """A user-private default, since the workspace holds the auth model, exploit paths, and PoCs."""
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


def _dry_run_diff() -> str:
    return "+++ b/app.py\n@@ -0,0 +1 @@\n+cursor.execute('SELECT * FROM u WHERE n=' + name)\n"


def _utc_now() -> str:
    from datetime import datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diff_source_meta(args):
    """The optional report provenance for a diff review. A flag that names a
    missing file fails loud, invariant 4, since the operator asked for it."""
    if not getattr(args, "source_meta", None):
        return None
    from cyberjury.sources.metadata import SourceError, read_source_meta_file

    path = Path(args.source_meta)
    if not path.exists():
        raise SourceError(f"source metadata file not found: {path}")
    return read_source_meta_file(path)


_MOCK_REPLY = (
    '{"findings": [{"file": "app.py", "line": 1, "severity": "HIGH", '
    '"category": "sql_injection", "description": "[mock] no backend called", '
    '"confidence": 0.9}]}'
)

# One canned reply serves both roles the dry-run exercises: the finder reads `findings`, the
# verifier reads `real`, so the keyless smoke path confirms rather than counting a parse failure.
_REPOSITORY_MOCK_REPLY = (
    '{"real": true, "reason": "mock", "findings": [{"title": "[mock] no backend called", '
    '"category": "other", "endpoint": "GET /mock", "file": "mock.py", "line": 1, '
    '"severity": "MEDIUM", "evidence": "mock.py:1", "status": "confirmed"}]}'
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
    """Resolve one role's backend, each field inheriting the base when its own is unset. A role
    that overrides the provider to a different vendor does not inherit the base key or endpoint,
    which belong to the base vendor, it falls back to its own field or the SDK env."""
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
    """Build a provider for a resolved role spec. Construction is lazy, so a per-role provider
    object is cheap, no SDK or key is touched until a call is made. When the run has set a usage
    meter, every seat is wrapped so one shared total spans finder, skeptic, and confirmers."""
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


# The env var each vendor SDK reads when no explicit key is passed. LiteLLM has no single name, so
# it is reachable only with an explicit key, never a subscription seat.
_SDK_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def _key_reachable(spec) -> bool:
    """Whether a seat can authenticate a provider call: it carries a key, or its vendor SDK env var
    is set so the SDK finds one. A seat with no reachable key is where the subscription fallback or
    a loud error applies."""
    if spec["api_key"]:
        return True
    env = _SDK_KEY_ENV.get(spec["provider"])
    return bool(env and os.environ.get(env))


def _seat_backend(spec, executor: str) -> str:
    """How one seat runs, 'agent' or 'api', by one rule for every seat. A key-reachable seat calls
    the provider. A keyless seat runs on the Claude Code subscription when that is possible, an
    Anthropic seat under auto or any seat under subscription. Otherwise it is a loud startup error,
    never a deferred mid-run failure, so api and auto fail at the same point on a missing key."""
    if executor == "subscription":
        return "agent"
    if _key_reachable(spec):
        return "api"
    if executor == "auto" and spec["provider"] == "anthropic":
        return "agent"
    if executor == "auto":
        raise SystemExit(
            f"the {spec['provider']} seat has no reachable API key and no Claude Code subscription "
            "to fall back to, only an Anthropic seat can. Set its key, or make it an Anthropic seat."
        )
    raise SystemExit(
        f"the {spec['provider']} seat has no reachable API key, and --executor api requires one. "
        "Set its key, or use --executor auto or subscription to run it on your Claude Code subscription."
    )


def _warn_secondary_env() -> None:
    """Warn when the deprecated CYBERJURY_SECONDARY_* names are still set so they are not silently
    ignored. They are no longer read, the per-role CYBERJURY_CHALLENGER_* and CYBERJURY_JUDGE_* names
    replace them."""
    if any(k.startswith("CYBERJURY_SECONDARY_") for k in os.environ):
        print(
            "NOTE: CYBERJURY_SECONDARY_* is no longer read. Use CYBERJURY_CHALLENGER_* for the "
            "skeptic and CYBERJURY_JUDGE_* for the confirmer.",
            file=sys.stderr,
        )


def _warn_roles_under_agent(args, agent_roles) -> None:
    """A seat that runs as the Claude Code agent supplies its own review, so its provider backend
    flags are ignored. Warn when such a seat also carries those flags, so they are not silently
    dropped. `agent_roles` names the seats resolved to the agent. The judge still applies as the
    confirmer. Role names map to flag prefixes, the skeptic seat is the challenger."""
    fields = ("provider", "model", "api_key", "api_base", "wire_api")
    overridden = [r for r in agent_roles if any(getattr(args, f"{r}_{f}") for f in fields)]
    if overridden:
        print(
            f"NOTE: the {' and '.join(overridden)} run as the Claude Code agent, so their backend "
            "flags are ignored. The judge still applies as the confirmer.",
            file=sys.stderr,
        )


def _note_subscription_fallback(roles) -> None:
    """Tell the operator when a seat fell back to the subscription for want of a key, so a slow,
    limit-bound agent run is a visible choice, not a silent one."""
    if roles:
        print(
            f"NOTE: no API key for the {' and '.join(roles)}, running on your Claude Code "
            "subscription, slower and counted against subscription limits. Pass --executor api "
            "to require a key instead.",
            file=sys.stderr,
        )


def _confirmer_for(args, spec):
    """One confirmer's `RefutationChecker`, resolved per seat like the finder and skeptic. A
    key-reachable seat is a grounded model call, a keyless Anthropic seat rides the subscription as
    an agent, a keyless non-Anthropic seat is a loud error."""
    from cyberjury.review.repository.verifier import ModelRefutationChecker

    if _seat_backend(spec, args.executor) == "agent":
        from cyberjury.review.repository.agent import AgentRefutationChecker

        return AgentRefutationChecker(**_agent_backend_kw(args))
    return ModelRefutationChecker(provider=_role_provider(args, spec), model=spec["model"])


def _confirmers(args, *, challenger, judge, finder=None):
    """The independent confirmers a drop needs, each label and checker pair. A refuted finding
    is dropped only when every applicable confirmer upholds the refutation. The challenger is the
    skeptic, so it is never a confirmer, a read cannot confirm its own refutation. The judge and the
    finder are confirmers, deduped by model, each labeled by its model so the route skips it for a
    finding that model itself surfaced. With no distinct confirmer the list is empty and nothing is
    dropped, the recall-safe default."""
    out = []
    seen = {(challenger["provider"], challenger["model"])}
    for spec in (judge, finder):
        if spec is None:
            continue
        key = (spec["provider"], spec["model"])
        if key in seen:
            continue
        seen.add(key)
        out.append((spec["model"], _confirmer_for(args, spec)))
    return out


def _close_backends(*objs) -> None:
    """Release any subscription backend that holds a persistent session, the SDK transport most of
    all, so its pooled Claude Code processes are shut down at the end of a run. A backend with no
    session, a model call or the process transport, has nothing to close and is skipped."""
    for obj in objs:
        close = getattr(obj, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                close()


def _warn_unlocatable(verify) -> None:
    kept = list(getattr(verify, "unlocatable", ()) or ())
    if not kept:
        return
    shown = ", ".join(f"{c.title} at {c.file or '<no file>'}" for c in kept[:3])
    print(
        f"WARNING: {len(kept)} finding(s) cite a location no file in the repository matches, so they "
        f"were kept unverified and will be re-verified on resume: {shown}" + (", ..." if len(kept) > 3 else ""),
        file=sys.stderr,
    )


def _note_verify_route(args, confirmers) -> None:
    """State the verification route so the choice is visible rather than inferred. There is one
    route: the skeptic refutes and every independent confirmer must uphold the refutation before a
    drop. With no confirmer nothing is dropped, the recall-safe default."""
    if not args.verify or args.dry_run:
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
    """The model-backend flags shared by both review paths, so the two parsers cannot drift on
    a default. `target` is a parser or an argument group, both expose add_argument."""
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
        help="OpenAI base-seat wire API, responses for the GPT-5 reasoning models",
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
    """The per-role backend override flags for finder, challenger, or judge. Each field defaults
    to None meaning inherit the base --provider/--model/--api-key/--api-base/--wire-api, resolved
    at build time, so a single-model run sets only --model. A role that overrides the provider to a
    different vendor takes its own key, not the base vendor's."""
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
        help=f"OpenAI {role} wire API, responses for the GPT-5 reasoning models",
    )


_EXECUTOR_HELP = (
    "how each seat runs. 'auto', the default, calls the provider when a seat has a reachable key and "
    "falls back to your Claude Code subscription for a keyless Anthropic seat, so a keyless run works "
    "with no provider key. 'api' always calls the provider and requires a key. 'subscription' always "
    "runs the headless `claude -p` agent. A missing key is a loud startup error under auto and api "
    "alike, never a deferred mid-run failure"
)


def _add_executor_arg(target) -> None:
    """The seat-backend selector, shared by both review paths so they cannot drift on a default."""
    target.add_argument("--executor", choices=("auto", "api", "subscription"), default="auto", help=_EXECUTOR_HELP)


def _add_audit_args(p) -> None:
    """The diff audit flags for `review diff`."""
    p.add_argument("--file", default=None, help="unified diff file (default: read stdin)")
    p.add_argument("--repository", default=None, help="repository path for --git-range")
    p.add_argument("--git-range", default=None, help="git range to diff, e.g. origin/main...HEAD")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="run the engine with a mock provider and no key (a built-in demo diff if none is given)",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATH",
        help="drop findings whose file path contains this substring (repeatable)",
    )
    p.add_argument(
        "--source-meta",
        default=None,
        dest="source_meta",
        metavar="FILE",
        help="a cyberjury-source.json to show as report provenance, from cyberjury fetch source",
    )
    p.add_argument("--mode", choices=("standard", "adversarial"), default="standard")
    p.add_argument("--rounds", type=int, default=3, help="adversarial only: debate rounds")
    _add_executor_arg(p)
    _add_backend_args(p)
    # adversarial only: finder scans, challenger refutes, judge decides, each on --model unless a
    # per-role flag or env overrides
    for role in ROLES:
        _add_role_backend_args(p, role)
    p.add_argument("--format", choices=_FORMATS, default="text", dest="fmt")
    p.add_argument("--no-filter", action="store_true", help="skip the false-positive filter")
    p.add_argument("--fail-on", choices=_FAIL_ON, default=None, dest="fail_on")
    _add_domain_arg(p)


# --effort is the one depth dial, so a run is one flag not a handful. Each level fixes two numbers,
# a min_lens_shots and a votes: how many times every lens must fire, and how many skeptics must
# agree before a candidate is dropped. The medium level equals the bare defaults, so leaving
# --effort unset changes nothing.
_EFFORT_PRESETS = {"low": (1, 1), "medium": (2, 1), "high": (3, 2)}


def _resolve_effort(effort: str, shots: int | None, votes: int | None) -> tuple[int, int]:
    """Fill min_lens_shots and votes from the effort level, an explicit flag on either overrides it."""
    preset_shots, preset_votes = _EFFORT_PRESETS[effort]
    return preset_shots if shots is None else shots, preset_votes if votes is None else votes


def _auto_concurrency(concurrency: int | None, finder_kind: str) -> int:
    """Pick the pass parallelism from the resolved finder backend when the operator set none. The
    subscription agent shares one rate cap, so a wide fan-out trips it and every call fails, which
    is a degraded run not zero findings, invariant 4. Hold it to 2 there, let a keyed API path run
    wider. An explicit --concurrency always wins."""
    if concurrency is not None:
        return concurrency
    return 2 if finder_kind == "agent" else 6


def _agent_backend_kw(args) -> dict:
    """The run tuning flags the subscription agent backends must honor, so --retries and --timeout
    reach the agent path instead of silently keeping the _ClaudeBackend constructor defaults,
    invariant 4."""
    return {"retries": args.retries, "timeout": args.timeout}


def main(argv: list[str] | None = None) -> int:
    # load .env before the parser reads its env-backed defaults
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
    repository.add_argument(
        "--invariants",
        default=None,
        metavar="FILE",
        help="seed inventory/_invariants.md from FILE, the business rules only you "
        "know, kept with the product and imported here",
    )
    # the workspace modes are mutually exclusive and one is required, no implicit default.
    # Two at once would otherwise fall to a dispatch precedence and silently run just one, so
    # --run --finalize could finalize and rewrite findings/, argparse rejects the pair instead
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
        help="run the coded multi-pass engine over the repository, not just scaffold, "
        "covers every unit each pass, cycles lenses, unions until convergence",
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
    _add_executor_arg(strategy)
    strategy.add_argument(
        "--effort",
        choices=("low", "medium", "high"),
        default="medium",
        help="how hard the run looks: low is one shot per lens and a fast pass, "
        "medium is the default two shots, high is three shots plus a "
        "majority of two skeptics before a candidate is dropped. Sets "
        "--min-lens-shots and --votes, either flag overrides it",
    )
    strategy.add_argument(
        "--facts",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="ground review in a tool-extracted call graph, storage layout, and "
        "read and write sets from the domain's facts backend such as the EVM "
        "Slither backend. Defaults on when the domain binds a backend, so the "
        "EVM domain grounds by default, except at --effort low where the cheap "
        "fast pass stays file-slice only. It degrades to file-slice review with "
        "a note when the toolchain is absent. Pass --no-facts to force it off or "
        "--facts to force it on, the result is cached by source hash so a re-run is free",
    )
    strategy.add_argument(
        "--poc",
        action="store_true",
        default=False,
        help="on finalize, generate and run an executable PoC per confirmed finding "
        "when the domain binds a PoC backend such as the EVM Foundry reproducer. "
        "When the run toolchain is absent the PoC is written but not run, with a "
        "note on how to run it, never a failure. Off by default since it calls a "
        "model and a compiler per finding. Local only, it never forks, broadcasts, "
        "or holds a key. It only adds evidence, a finding is kept whether or not "
        "its PoC reproduces",
    )

    roles = repository.add_argument_group(
        "model roles (advanced)",
        "finder finds, challenger refutes, judge confirms before a deletion. Each field inherits the "
        "base backend when unset, so override only the seat you change, set a different vendor in any "
        "seat for cross-model review, for example a GPT challenger and a Claude judge. A cross-vendor "
        "seat brings its own api-key. A deletion needs the judge to be a distinct model from "
        "the challenger, with none distinct no finding is refuted, the recall-safe default. A seat "
        "that runs on the subscription ignores its backend flags. Usually set through "
        "CYBERJURY_FINDER_*/CHALLENGER_*/JUDGE_*",
    )
    for role in ROLES:
        _add_role_backend_args(roles, role)

    tuning = repository.add_argument_group("run tuning (advanced)", "only affect --run, sane defaults otherwise")
    tuning.add_argument(
        "--max-passes",
        type=int,
        default=None,
        dest="max_passes",
        help="cap on diverse passes before stopping, default scales to the domain: "
        "(min-lens-shots + 1) * number of lenses, so every lens meets its shot "
        "floor with a cycle of headroom for convergence",
    )
    tuning.add_argument(
        "--converge-after",
        type=int,
        default=2,
        dest="converge_after",
        help="stop once this many consecutive passes add no new finding",
    )
    tuning.add_argument(
        "--min-lens-shots",
        type=int,
        default=None,
        dest="min_lens_shots",
        help="keep going until every lens has reviewed this many times, so a hard "
        "class is not left to one shot on a repository that converges fast, default "
        "from --effort",
    )
    tuning.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="how many unit reviews to run in parallel within a pass, default 2 "
        "on the subscription backend so a wide fan-out does not trip its rate "
        "cap, 6 on an API key",
    )
    tuning.add_argument(
        "--max-units",
        type=int,
        default=None,
        help="cap on the public API fallback used for a library with no "
        "application entrypoint. Over this many files the run fails loud so "
        "you narrow the scope or raise it, default unset so nothing is capped",
    )
    tuning.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        default=True,
        help="skip the adversarial verification stage, keep every candidate",
    )
    tuning.add_argument(
        "--votes",
        type=int,
        default=None,
        help="independent skeptic votes per candidate, refuted only on a majority, default from --effort",
    )
    tuning.add_argument(
        "--strict-coverage",
        action="store_true",
        default=False,
        dest="strict_coverage",
        help="with --gate, fail when a source file is owned by no unit instead of "
        "only noting it, so the source tree is the enforced coverage denominator",
    )
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


def _diff_provider(args, spec, kind: str):
    """A diff seat's provider for its resolved kind. An agent seat runs on the subscription through
    `ClaudeAgentProvider`, a drop-in for the diff runners that answers from the diff in the prompt
    with no file tools. An api seat builds the provider as before. Imported lazily so a pure-api run
    never loads the agent transport."""
    if kind == "agent":
        from cyberjury.providers.claude_agent import ClaudeAgentProvider

        return ClaudeAgentProvider()
    return _role_provider(args, spec)


def build_diff_providers(args):
    """Resolve the diff seats into providers exactly as `review diff` does, so a non-CLI caller
    such as the eval runs a case through the same wiring a user gets. Returns the base provider
    and model the audit needs plus the per-role finder, challenger, and judge providers and
    models, the role fields None in standard mode. The single source the CLI and the eval share,
    so the probe cannot drift from the product on which model or seat reviews a diff."""
    base = _base_spec(args)
    if args.mode == "adversarial":
        roles = {r: _role_spec(args, r, base) for r in ("finder", "challenger", "judge")}
        kinds = {r: _seat_backend(s, args.executor) for r, s in roles.items()}
        agent_roles = [r for r, k in kinds.items() if k == "agent"]
        _warn_roles_under_agent(args, agent_roles)
        if args.executor == "auto":
            _note_subscription_fallback(agent_roles)
        fp = _diff_provider(args, roles["finder"], kinds["finder"])
        cp = _diff_provider(args, roles["challenger"], kinds["challenger"])
        jp = _diff_provider(args, roles["judge"], kinds["judge"])
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
    base_kind = _seat_backend(base, args.executor)
    if args.executor == "auto" and base_kind == "agent":
        _note_subscription_fallback(("audit",))
    return (_diff_provider(args, base, base_kind), base["model"], None, None, None, None, None, None)


def diff_args_from_env(mode: str, *, executor: str = "auto", rounds: int = 3):
    """A diff args namespace from the environment defaults, the same values `review diff` reads
    when no flag is passed, so `build_diff_providers` builds the user's real wiring. Lets the eval
    drive the audit through the product path rather than a hardcoded provider."""
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
        "executor": executor,
        "mode": mode,
        "rounds": rounds,
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
    finder_provider = challenger_provider = judge_provider = None
    finder_model = challenger_model = judge_model = None
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
    try:
        _, skipped_noise = strip_noise_files(diff, load_detection(domain.paths.detection_file))
        if skipped_noise:
            shown = ", ".join(skipped_noise[:5])
            more = f", and {len(skipped_noise) - 5} more" if len(skipped_noise) > 5 else ""
            progress(f"skipped {len(skipped_noise)} non-source file(s): {shown}{more}")
        with stage_timer("diff review"):
            kept, _, degraded = audit_diff(
                diff,
                provider=provider,
                model=model,
                mode=args.mode,
                max_rounds=args.rounds,
                filter_findings=not args.no_filter,
                finder_model=finder_model,
                challenger_model=challenger_model,
                judge_model=judge_model,
                finder_provider=finder_provider,
                challenger_provider=challenger_provider,
                judge_provider=judge_provider,
                exclude_paths=tuple(args.exclude or ()),
                domain=domain,
                on_batch=lambda done, total, secs: progress(f"batch {done}/{total} ({secs}s)"),
            )
        print(render(args.fmt, kept, _diff_source_meta(args)))
        if degraded:
            # the adversarial judge was unusable and the result fell back to the finder set minus
            # the challenger's dismissals plus its new findings, unjudged, a failed audit not a
            # clean pass, invariant 4
            print(
                "error: the adversarial audit degraded on an unusable judge reply, "
                "the result is incomplete and not a clean pass",
                file=sys.stderr,
            )
        return 1 if degraded or gate(kept, args.fail_on) else 0
    finally:
        _close_backends(provider, finder_provider, challenger_provider, judge_provider)


def _repo_ws(args) -> Path:
    """The per-target workspace directory, where the run artifacts and the timeline live."""
    return Path(args.workspace) / Path(args.directory).resolve().name


def _verify_progress(done: int, total: int, secs: float) -> None:
    """Per-candidate heartbeat for the verify fan-out, shared by the run and finalize commands."""
    progress(f"verified {done}/{total} ({secs}s)")


def _timed_stage(name: str, *, reset: bool = False):
    """Wrap a repository stage command so it records its elapsed to the workspace timeline and
    prints it to stderr, giving a whole-pipeline cost readable across the separate commands."""

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
    result = check_gate(
        project_dir, root=Path(args.directory).resolve(), detection=detection, strict_coverage=args.strict_coverage
    )
    timeline = read_timeline(project_dir)
    if timeline:
        # gate usually runs last, so sum the recorded stages for a whole-pipeline cost, gate's own
        # record is written after this by stage_timer so it is not yet counted
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
    args.min_lens_shots, args.votes = _resolve_effort(args.effort, args.min_lens_shots, args.votes)
    _warn_secondary_env()
    base = _base_spec(args)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
    provider = None
    verifier_obj = None
    confirmers: list = []
    args._usage_meter = UsageMeter()
    # the challenger backs the skeptic, the judge backs the confirmer, a drop needs the two to be
    # distinct models so a single read cannot drop a real finding
    if args.dry_run:
        provider = MockProvider(default='{"real": true, "reason": "[mock]"}')
        args.model = "mock"
    elif _seat_backend(challenger, args.executor) == "agent":
        from cyberjury.review.repository.agent import AgentVerifier

        verifier_obj = AgentVerifier(content=domain.paths, **_agent_backend_kw(args))
        _warn_roles_under_agent(args, ("challenger",))
        if args.executor == "auto":
            _note_subscription_fallback(("skeptic",))
    else:
        verifier_obj = ModelVerifier(
            provider=_role_provider(args, challenger), model=challenger["model"], content=domain.paths
        )
    if not args.dry_run:
        confirmers = _confirmers(args, challenger=challenger, judge=judge)
    _note_verify_route(args, confirmers)
    args.concurrency = _auto_concurrency(
        args.concurrency, "" if args.dry_run else _seat_backend(challenger, args.executor)
    )
    poc_backend_obj = None
    if args.poc and not args.dry_run:
        if domain.poc_backend is None:
            print(f"NOTE: --poc ignored, the {domain.name} domain binds no PoC backend.", file=sys.stderr)
        else:
            if _seat_backend(base, args.executor) == "agent":
                from cyberjury.providers.claude_agent import ClaudeAgentProvider

                gen_provider = ClaudeAgentProvider(**_agent_backend_kw(args))
            else:
                gen_provider = _role_provider(args, base)
            poc_backend_obj = domain.poc_backend(provider=gen_provider, model=base["model"])
            if getattr(poc_backend_obj, "executes", True) and not poc_backend_obj.available():
                # write-only degrade, not an abort, so the operator learns how to enable the run
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
            verify=args.verify,
            votes=args.votes,
            concurrency=args.concurrency,
            domain=domain,
            poc_backend=poc_backend_obj,
            on_verify=_verify_progress,
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
            return 1  # fail loud: an incomplete verification is not a clean finalize, invariant 4
        return 0
    finally:
        _close_backends(verifier_obj, *(chk for _label, chk in confirmers))


def _facts_enabled(args, domain) -> bool:
    """Resolve the tri-state --facts flag. An explicit --facts or --no-facts wins. Otherwise facts
    are on when the domain binds a backend, so the EVM domain grounds by default while web, with no
    backend, does not. The exception is --effort low, the cheap fast tier, where the extra call-path
    units are not worth their cost, so a low pass stays file-slice only unless --facts is explicit."""
    if args.facts is not None:
        return args.facts
    return domain.facts_backend is not None and args.effort != "low"


@_timed_stage("run")
def _cmd_repository_run(args) -> int:
    from cyberjury.review.repository.engine import run_repository_review
    from cyberjury.review.repository.verifier import ModelVerifier

    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    args.min_lens_shots, args.votes = _resolve_effort(args.effort, args.min_lens_shots, args.votes)
    # scale the pass cap to the domain, so the min-lens-shots floor is always meetable and the
    # convergence early-stop can fire, with one lens cycle of headroom above the floor
    if args.max_passes is None:
        args.max_passes = (args.min_lens_shots + 1) * len(domain.lenses)
    _warn_secondary_env()
    base = _base_spec(args)
    finder = _role_spec(args, "finder", base)
    challenger = _role_spec(args, "challenger", base)
    judge = _role_spec(args, "judge", base)
    reviewer_obj = verifier_obj = None
    provider = None
    model = args.model
    confirmers: list = []
    args._usage_meter = UsageMeter()
    if args.dry_run:
        provider = MockProvider(default=_REPOSITORY_MOCK_REPLY)
        model = "mock"
    else:
        finder_kind = _seat_backend(finder, args.executor)
        skeptic_kind = _seat_backend(challenger, args.executor)
        if finder_kind == "agent":
            from cyberjury.review.repository.agent import AgentReviewer

            reviewer_obj = AgentReviewer(content=domain.paths, **_agent_backend_kw(args))
        else:
            # finder goes through provider+model so the engine builds the unit reviewer with its
            # facts wiring, the skeptic and confirmers are injected from the challenger and judge
            provider = _role_provider(args, finder)
            model = finder["model"]
        if skeptic_kind == "agent":
            from cyberjury.review.repository.agent import AgentVerifier

            verifier_obj = AgentVerifier(content=domain.paths, **_agent_backend_kw(args))
        else:
            verifier_obj = ModelVerifier(
                provider=_role_provider(args, challenger), model=challenger["model"], content=domain.paths
            )
        agent_roles = [r for r, k in (("finder", finder_kind), ("challenger", skeptic_kind)) if k == "agent"]
        _warn_roles_under_agent(args, agent_roles)
        if args.executor == "auto":
            _note_subscription_fallback(
                [n for n, k in (("finder", finder_kind), ("skeptic", skeptic_kind)) if k == "agent"]
            )
        # the judge and finder are the independent confirmers, the skeptic is the challenger and
        # confirms nothing, a drop needs every applicable confirmer to uphold the refutation
        confirmers = _confirmers(args, challenger=challenger, judge=judge, finder=finder)

    args.concurrency = _auto_concurrency(args.concurrency, "" if args.dry_run else _seat_backend(finder, args.executor))

    def _progress(p, lens, new, total):
        print(f"  pass {p} [{lens or 'general'}]  +{new} new  union={total}", file=sys.stderr)

    _note_verify_route(args, confirmers)
    print(f"Running the coded multi-pass engine over {args.directory} ...", file=sys.stderr)
    try:
        res = run_repository_review(
            args.directory,
            args.workspace,
            provider=provider,
            model=model,
            reviewer=reviewer_obj,
            verifier=verifier_obj,
            confirmers=confirmers,
            verify=args.verify,
            votes=args.votes,
            max_passes=args.max_passes,
            converge_after=args.converge_after,
            min_lens_shots=args.min_lens_shots,
            concurrency=args.concurrency,
            fresh=args.fresh,
            on_pass=_progress,
            on_verify=_verify_progress,
            domain=domain,
            facts=_facts_enabled(args, domain),
            max_units=args.max_units,
            invariants=args.invariants,
        )
        if res.scaffold.fallback_note:
            print(f"NOTE: {res.scaffold.fallback_note}.", file=sys.stderr)
        if res.scaffold.invariants_note:
            print(f"NOTE: {res.scaffold.invariants_note}.", file=sys.stderr)
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
                "Results may be understated. Lower --concurrency or raise --retries and re-run.",
                file=sys.stderr,
            )
        if not acc.converged:
            print(
                f"WARNING: the union did not converge within {args.max_passes} passes, it was "
                "still finding new issues when the cap stopped it. Coverage is incomplete and "
                "recall is not guaranteed. Raise --max-passes or narrow the scope and re-run.",
                file=sys.stderr,
            )
        print(f"Findings written to {res.scaffold.workspace}/findings/ and {res.scaffold.workspace}/findings.json")
        if args._usage_meter.model_requests:
            print(args._usage_meter.summary(), file=sys.stderr)
        # fail loud: a partial run or a run still finding issues at the cap must not exit clean,
        # invariant 4 and the stability red line, so a non-converged run is not reported as done
        return 1 if failures or not acc.converged else 0
    finally:
        _close_backends(reviewer_obj, verifier_obj, *(chk for _label, chk in confirmers))


@_timed_stage("scaffold", reset=True)
def _cmd_repository_scaffold(args) -> int:
    # a bare scaffold consumes none of the run-only options, so flag the common mistake
    # of setting one without --run rather than silently doing nothing with it
    ignored = [
        flag
        for flag, used in (
            ("--dry-run", args.dry_run),
            ("--executor", args.executor != "auto"),
            ("--no-verify", not args.verify),
        )
        if used
    ]
    if ignored:
        print(
            f"NOTE: {', '.join(ignored)} only affect --run, this bare scaffold ignores them. "
            "Add --run to drive the coded engine.",
            file=sys.stderr,
        )
    domain = resolve_domain(args.domain, _repository_file_names(args.directory))
    res = scaffold(
        args.directory,
        args.workspace,
        fresh=args.fresh,
        domain=domain,
        facts=_facts_enabled(args, domain),
        max_units=args.max_units,
        invariants=args.invariants,
    )
    (Path(res.workspace) / "METHODOLOGY.md").write_text(res.methodology, encoding="utf-8")
    if res.cleared:
        print(f"Cleared {len(res.cleared)} prior-run paths in {res.workspace}", file=sys.stderr)
    elif res.had_prior_run:
        print(
            f"A previous review's output is in {res.workspace}. Re-run with --fresh to clear it first.", file=sys.stderr
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
    if res.invariants_note:
        print(f"NOTE: {res.invariants_note}.", file=sys.stderr)
    print(f"Methodology: {res.workspace}/METHODOLOGY.md", file=sys.stderr)
    print(
        "This command sets up the review, it does not find anything itself. Next, have an "
        f"interactive agent follow {res.workspace}/METHODOLOGY.md to run the review, or use the "
        "/cyberjury-review command in Claude Code or Codex. The agent proposes findings in "
        f"{res.workspace}/candidates/, finalize confirms them into {res.workspace}/findings/."
    )
    return 0


def _cmd_install_slash_command(args) -> int:
    # One domain-agnostic command, installed into both agent command directories so it works in
    # Claude Code and Codex without a choice. Both read a markdown prompt with $ARGUMENTS. The
    # command threads --domain through to Cyberjury, so web and evm run from the same command.
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
    print("Run it with: /cyberjury-review <repository or diff> [--coded] [--domain auto|web|evm]")
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
        print("  repository   scaffold a whole-repository review for an interactive agent", file=sys.stderr)
        return 1
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
