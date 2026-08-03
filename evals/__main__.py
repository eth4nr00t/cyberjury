"""Eval CLI: score a review, run the diff probe, or compare two results.

  python -m evals list
  python -m evals repository open-webui --findings-dir /tmp/cj-owui/webui/findings
  python -m evals repository open-webui --findings-json findings.json --json before.json
  python -m evals diff --mode standard --model <id> --runs 3
  python -m evals run public-smoke --model <id> --runs 3
  python -m evals compare before.json after.json --by vulnerability
  python -m evals gate after.json --baseline before.json --precision-floor 0.8
  python -m evals coverage

The repository path scores the output an agent or a coded run already wrote, it does not run the
review. Resolve a benchmark by name across the public benchmarks and any private source in
the local config, see registry.py.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from evals import registry
from evals.compare import compare_files, format_compare, format_compare_by
from evals.results import Result, SuiteResult
from evals.runners.repository import reports_from_findings_dir, reports_from_json, score_repository
from evals.schema import load_answer_key


def _format_result(res) -> str:
    known = len(res.found) + len(res.false_positives)
    lines = [
        f"=== {res.target} ===",
        f"  recall    {len(res.found)}/{res.n_planted} = {res.recall:.0%}",
        f"  precision {res.precision_known:.0%}  over {known} known-matched of {res.n_reports} reports",
    ]
    runs = getattr(res, "runs", None)
    if runs:
        lines.insert(1, f"  runs      {runs}, found by strict majority")
        flaky = {i: c for i, c in res.found_freq.items() if 0 < c < runs}
        if flaky:
            spread = ", ".join(f"{i} {c}/{runs}" for i, c in sorted(flaky.items()))
            lines.append(f"  flaky, found in some runs not all: {spread}")
    if res.missed:
        lines.append(f"  MISSED: {', '.join(res.missed)}")
    if res.false_positives:
        lines.append(f"  false positive on safe: {', '.join(res.false_positives)}")
    if res.extra:
        lines.append(f"  extra, unkeyed, read by hand: {len(res.extra)}")
    if res.errors:
        lines.append(f"  errors: {res.errors}")
    return "\n".join(lines)


def _emit(res: Result | SuiteResult, json_out: str | None) -> int:
    print(_format_result(res))
    if json_out:
        Path(json_out).write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    clean = not res.missed and not res.false_positives and not res.errors
    return 0 if clean else 1


def _cmd_repository(args) -> int:
    key = load_answer_key(registry.find_answer_key(args.name))
    if args.findings_json:
        reports = reports_from_json(args.findings_json)
    elif args.findings_dir:
        reports = reports_from_findings_dir(args.findings_dir)
    else:
        reports = reports_from_findings_dir(Path(args.workspace) / args.name / "findings")
    return _emit(score_repository(key, reports, source_root=_resolve_source(args)), args.json)


def _resolve_source(args) -> str | None:
    """The repository source root a symbol span reads from, when available. Explicit `--source` wins,
    else a local clone under `<CYBERJURY_BACKTEST_DIR>/repositories/<name>` is used when present,
    so the backtest scores by symbol span without a flag. Absent both, the scoring reads no source
    and a symbol anchor matches by name only, the committed suite behavior."""
    if args.source:
        return args.source
    root = os.environ.get("CYBERJURY_BACKTEST_DIR")
    if root:
        clone = Path(root).expanduser() / "repositories" / args.name
        if clone.is_dir():
            return str(clone)
    return None


def _run_diff(cases, args, target: str = "diff"):
    """Run the cases through the probe args.runs times. One run returns a Result, repeated
    runs fold into a SuiteResult by frequency, the anti-noise verdict, invariant 4 errors
    summed across runs."""
    from cyberjury.cli import build_diff_providers, diff_args_from_env
    from evals.runners.diff import run_diff_cases

    # build the seats the same way `review diff` does, so the probe is not a separate provider
    # path that could pass or fail differently from the product, see build_diff_providers
    dargs = diff_args_from_env(args.mode)
    if args.model:
        dargs.model = args.model
    provider, model, fp, fm, cp, cm, jp, jm = build_diff_providers(dargs)
    n = max(1, args.runs)
    runs = []
    for _ in range(n):
        r = run_diff_cases(
            cases,
            provider=provider,
            model=model,
            mode=args.mode,
            rounds=dargs.rounds,
            finder_provider=fp,
            finder_model=fm,
            challenger_provider=cp,
            challenger_model=cm,
            judge_provider=jp,
            judge_model=jm,
        )
        r.target = target
        runs.append(r)
    return SuiteResult.from_runs(target, runs) if n > 1 else runs[0]


def _cmd_diff(args) -> int:
    from evals.runners.diff import default_cases, load_cases

    cases = load_cases(args.cases) if args.cases else default_cases()
    return _emit(_run_diff(cases, args), args.json)


def _cmd_run(args) -> int:
    from evals.runners.diff import default_cases
    from evals.suites import load_suite, select_cases

    suite = load_suite(args.suite)
    cases = select_cases(suite, default_cases())
    if not cases:
        raise SystemExit(f"suite '{suite.name}' selects no diff cases")
    return _emit(_run_diff(cases, args, target=suite.name), args.json)


def _cmd_list(args) -> int:
    from evals.diff_cases import default_cases
    from evals.registry import all_benchmarks
    from evals.suites import all_suites, select_benchmarks, select_cases

    benches = all_benchmarks()
    cases = default_cases()
    print("benchmarks:")
    for name, b in sorted(benches.items()):
        print(f"  {name:24} {b.kind:5} {b.provenance:8} tags={','.join(b.tags) or '-'}")
    n_pos = sum(c.is_positive for c in cases)
    print(f"diff cases: {len(cases)}, {n_pos} positive, {len(cases) - n_pos} safe")
    print("suites:")
    for s in all_suites():
        nc = len(select_cases(s, cases))
        nb = len(select_benchmarks(s, list(benches.values())))
        print(f"  {s.name:24} {nc} cases, {nb} benchmarks  tags={','.join(s.tags) or 'all'}")
    return 0


def _cmd_compare(args) -> int:
    from evals.compare import format_arms, with_arms

    d = compare_files(args.before, args.after, axis=args.by)
    print(format_compare_by(d) if args.by else format_compare(d))
    if args.before_workspace or args.after_workspace:
        d = with_arms(d, args.before_workspace, args.after_workspace)
        print(format_arms(d))
        return 0 if d["comparable"] else 1
    return 0


def _cmd_gate(args) -> int:
    from evals.gate import format_gate, gate

    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    fails = gate(after, baseline, precision_floor=args.precision_floor, structural=not args.no_structural)
    print(format_gate(fails, after.get("target", "?")))
    return 1 if fails else 0


def _cmd_coverage(args) -> int:
    from evals.coverage import coverage_matrix, coverage_problems, format_matrix

    cov = coverage_matrix()
    problems = coverage_problems(cov)
    print(format_matrix(cov, problems))
    # a missing case is a known gap the case library fills over time, but a reference to a
    # knowledge file that does not exist is broken benchmark data, so fail loud on it
    unresolved = [p for p in problems if p.kind == "unresolved-reference"]
    return 1 if unresolved else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="evals", description="detection-quality eval ruler")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("repository", help="score a whole-repository review against an answer key")
    r.add_argument("name", help="benchmark name, e.g. open-webui")
    r.add_argument("--workspace", default=None, help="review workspace root, reads <workspace>/<name>/findings")
    r.add_argument("--findings-dir", default=None, help="a findings/ directory directly")
    r.add_argument("--findings-json", default=None, help="a findings.json or a json list of reports")
    r.add_argument(
        "--source",
        default=None,
        help="repository source root, lets a symbol anchor credit a report that pins the bug "
        "by line inside the symbol without naming it, auto-discovered from a "
        "CYBERJURY_BACKTEST_DIR clone when unset",
    )
    r.add_argument("--json", default=None, help="write the structured result here for compare")
    r.set_defaults(func=_cmd_repository)

    d = sub.add_parser("diff", help="run the diff capability probe over the whole library and score")
    d.add_argument("--mode", default="standard")
    d.add_argument("--model", default=None)
    d.add_argument("--cases", default=None, help="cases YAML, defaults to the shipped diff cases")
    d.add_argument("--runs", type=int, default=1, help="repeat N times and fold by frequency")
    d.add_argument("--json", default=None)
    d.set_defaults(func=_cmd_diff)

    rn = sub.add_parser("run", help="run a suite of diff cases selected by tag and score")
    rn.add_argument("suite", help="suite name, e.g. public-smoke or knowledge-coverage")
    rn.add_argument("--mode", default="standard")
    rn.add_argument("--model", default=None)
    rn.add_argument("--runs", type=int, default=1, help="repeat N times and fold by frequency")
    rn.add_argument("--json", default=None)
    rn.set_defaults(func=_cmd_run)

    sub.add_parser("list", help="benchmarks and suites the registry sees").set_defaults(func=_cmd_list)

    c = sub.add_parser("compare", help="compare two result JSON files")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument(
        "--by",
        default=None,
        choices=["vulnerability", "language", "framework", "protocol", "tag"],
        help="group the flips by an axis",
    )
    c.add_argument(
        "--before-workspace",
        default=None,
        help="the baseline arm's review workspace, to fold in its completeness and cost",
    )
    c.add_argument(
        "--after-workspace",
        default=None,
        help="the changed arm's review workspace. With both, exit 1 when either arm did not run clean",
    )
    c.set_defaults(func=_cmd_compare)

    g = sub.add_parser("gate", help="fail loud on a regression against a baseline")
    g.add_argument("after", help="the result JSON to gate")
    g.add_argument("--baseline", default=None, help="a baseline result JSON to judge the move against")
    g.add_argument("--precision-floor", type=float, default=0.0, help="fail when precision is below this")
    g.add_argument("--no-structural", action="store_true", help="skip the benchmark-data soundness checks")
    g.set_defaults(func=_cmd_gate)

    cov = sub.add_parser("coverage", help="knowledge coverage matrix, which files lack eval coverage")
    cov.set_defaults(func=_cmd_coverage)

    args = p.parse_args(argv)
    if args.cmd == "repository" and not (args.findings_dir or args.findings_json or args.workspace):
        p.error("repository needs one of --workspace, --findings-dir, or --findings-json")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
