"""Command line interface for benchmark evaluation and backtests.

Examples:
  python -m evals list
  python -m evals repository open-webui --findings-dir /tmp/cj-owui/webui/findings
  python -m evals repository open-webui --findings-json findings.json --json before.json
  python -m evals diff --mode standard --model <id> --runs 3
  python -m evals compare before.json after.json --by vulnerability
  python -m evals gate after.json --baseline before.json --precision-floor 0.8
  python -m evals coverage

The repository path scores output a review already wrote. It does not run the review.
Benchmark names resolve across the public benchmarks and any private source in the local
config, see registry.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from evals.backtest.compare import compare_files, format_compare, format_compare_by
from evals.review.repository import score as score_repository
from evals.score.result import RepeatedResult, Result


def _format_result(res) -> str:
    known = len(res.found) + len(res.false_positives)
    lines = [
        f"=== {res.target} ===",
        f"  recall    {len(res.found)}/{res.n_findings} = {res.recall:.0%}",
        f"  precision {res.precision_known:.0%}  over {known} known-matched of {res.n_reports} reports",
    ]
    if res.n_file_findings:
        lines.append(f"  file      {len(res.file_found)}/{res.n_file_findings} = {res.file_recall:.0%}")
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
        lines.append(f"  false positive on clean check: {', '.join(res.false_positives)}")
    if res.extra:
        lines.append(f"  extra, unkeyed, read by hand: {len(res.extra)}")
    if res.errors:
        lines.append(f"  errors: {res.errors}")
    return "\n".join(lines)


def _emit(res: Result | RepeatedResult, json_out: str | None) -> int:
    print(_format_result(res))
    if json_out:
        Path(json_out).write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    clean = not res.missed and not res.false_positives and not res.errors
    return 0 if clean else 1


def _progress_sidecar(json_out: str | None) -> Path | None:
    if not json_out:
        return None
    path = Path(json_out)
    return path.with_name(f"{path.stem}.cases.jsonl")


def _diff_progress_writer(json_out: str | None) -> Callable[[dict[str, object]], None]:
    sidecar = _progress_sidecar(json_out)
    if sidecar is not None:
        try:
            sidecar.parent.mkdir(parents=True, exist_ok=True)
            sidecar.write_text("", encoding="utf-8")
        except OSError:
            sidecar = None

    def write(event: dict[str, object]) -> None:
        if event.get("event") in {
            "case_started",
            "case_batch_finished",
            "case_judgment_finished",
            "case_failed",
            "case_finished",
        }:
            print(_format_diff_progress(event), file=sys.stderr, flush=True)
        else:
            print(json.dumps(event, sort_keys=True), file=sys.stderr, flush=True)
        if sidecar is None:
            return
        try:
            with sidecar.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            return

    return write


def _format_diff_progress(event: dict[str, object]) -> str:
    run = ""
    if int(event.get("runs") or 1) > 1:
        run = f"run {event['run']}/{event['runs']} "
    prefix = f"{run}[{event['index']}/{event['total']}] {event['case']}"
    kind = event["event"]
    if kind == "case_started":
        return f"{prefix} started"
    if kind == "case_batch_finished":
        return f"{prefix} batch {event['batch']}/{event['batches']} finished in {event['batch_seconds']}s"
    if kind == "case_judgment_finished":
        return (
            f"{prefix} knowledge judgment {event['judgment']}/{event['judgments']} "
            f"[{event['judgment_label']}] finished in {event['judgment_seconds']}s"
        )
    if kind == "case_failed":
        return f"{prefix} failed after {event['elapsed_seconds']}s: {event['error']}"
    if kind == "case_finished":
        return (
            f"{prefix} finished in {event['elapsed_seconds']}s, reports={event['reports']}, "
            f"found={event['found']}, missed={event['missed']}, fp={event['false_positives']}, extra={event['extra']}"
        )
    raise ValueError(f"unknown diff progress event: {kind}")


def _cmd_repository(args) -> int:
    result = score_repository(
        args.name,
        workspace=args.workspace,
        findings_json=args.findings_json,
        findings_dir=args.findings_dir,
        source_root=args.source,
    )
    return _emit(result, args.json)


def _cmd_diff(args) -> int:
    from evals.benchmarks.cases import diff_cases, load_project_diff_cases
    from evals.review.diff import run

    cases = _load_diff_cases_arg(args.cases, load_project_diff_cases) if args.cases else diff_cases()
    progress = _diff_progress_writer(args.json)
    result = run(
        cases,
        mode=args.mode,
        rounds=args.rounds,
        model_override=args.model,
        runs=args.runs,
        progress=progress,
        trace=progress if args.debug else None,
    )
    return _emit(result, args.json)


def _load_diff_cases_arg(path, load_project_diff_cases):
    p = Path(path)
    if p.is_dir():
        benchmark = p / "benchmark.yaml"
        if benchmark.is_file():
            loaded = load_project_diff_cases(benchmark, provenance="private")
            if loaded:
                return loaded
            raise ValueError(f"{benchmark} has no diff tasks")
        raise ValueError(f"{p} has no benchmark.yaml")
    if p.name == "benchmark.yaml":
        loaded = load_project_diff_cases(p, provenance="private")
        if loaded:
            return loaded
        raise ValueError(f"{p} has no diff tasks")
    raise ValueError(f"{p} is not a benchmark.yaml or benchmark directory")


def _cmd_list(args) -> int:
    from evals.benchmarks.cases import diff_cases, repository_cases

    benches = repository_cases()
    cases = diff_cases()
    print("benchmarks:")
    for name, b in sorted(benches.items()):
        print(f"  {name:24} {b.kind:5} {b.provenance:8} profile={b.profile}")
    n_pos = sum(c.is_positive for c in cases)
    print(f"diff benchmarks: {len(cases)}, {n_pos} findings checks, {len(cases) - n_pos} clean checks")
    return 0


def _cmd_compare(args) -> int:
    from evals.backtest.metrics import format_arms, with_arms

    d = compare_files(args.before, args.after, axis=args.by)
    print(format_compare_by(d) if args.by else format_compare(d))
    if args.before_workspace or args.after_workspace:
        d = with_arms(d, args.before_workspace, args.after_workspace)
        print(format_arms(d))
        return 0 if d["comparable"] else 1
    return 0


def _cmd_gate(args) -> int:
    from evals.backtest.gate import format_gate, gate

    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    fails = gate(after, baseline, precision_floor=args.precision_floor, structural=not args.no_structural)
    print(format_gate(fails, after.get("target", "?")))
    return 1 if fails else 0


def _cmd_coverage(args) -> int:
    from evals.benchmarks.coverage import coverage_matrix, coverage_problems, format_matrix

    cov = coverage_matrix()
    problems = coverage_problems(cov)
    print(format_matrix(cov, problems))
    return 0


def _cmd_prepare(args) -> int:
    from evals.benchmarks.prepare import default_root, prepare_target, solidity_targets, write_report

    root = Path(args.root) if args.root else default_root()
    targets = solidity_targets()
    if args.only:
        missing = [n for n in args.only if n not in targets]
        if missing:
            print(f"unknown or non-solidity target(s): {', '.join(missing)}", file=sys.stderr)
            return 2
        targets = {n: targets[n] for n in args.only}
    results = []
    for name, target in targets.items():
        res = prepare_target(name, target, root)
        results.append(res)
        label = "ok  " if res.ok else ("skip" if res.skipped else "FAIL")
        print(f"{label} {name:24} {res.detail}", flush=True)
        if not res.ok and not res.skipped:
            for step in res.steps:
                print(f"       {step}", file=sys.stderr)
    write_report(results, root.parent / "prepare.json")
    failed = [r.name for r in results if not (r.ok or r.skipped)]
    skipped = [r.name for r in results if r.skipped]
    ready = [r.name for r in results if r.ok]
    tail = f", {len(skipped)} skipped" if skipped else ""
    print(f"\n{len(ready)}/{len(results)} can ground{tail}, report in {root.parent / 'prepare.json'}")
    if skipped:
        print(f"skipped, nothing this command can do: {', '.join(skipped)}", file=sys.stderr)
    if failed:
        print(f"not prepared: {', '.join(failed)}", file=sys.stderr)
    return 1 if failed else 0


def _cmd_validate(args) -> int:
    from evals.benchmarks.validate import validate_benchmark

    validate_benchmark(args.path, source_root=args.source_root)
    print(f"valid: {args.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    p = argparse.ArgumentParser(prog="evals", description="detection quality evaluation and backtests")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("repository", help="score a repository review against an answer key")
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

    d = sub.add_parser("diff", help="run the diff benchmark library and score")
    d.add_argument(
        "--mode",
        choices=["standard", "adversarial"],
        default=None,
        help="override the review mode declared by every selected benchmark task",
    )
    d.add_argument("--model", default=None)
    d.add_argument("--cases", default=None, help="benchmark.yaml or benchmark directory, defaults to shipped tasks")
    d.add_argument("--rounds", type=int, default=3, help="adversarial mode role rounds")
    d.add_argument("--runs", type=int, default=1, help="repeat N times and fold by frequency")
    d.add_argument("--json", default=None)
    d.add_argument("--debug", action="store_true", help="emit review stage diagnostics")
    d.set_defaults(func=_cmd_diff)

    sub.add_parser("list", help="benchmarks the registry sees").set_defaults(func=_cmd_list)

    c = sub.add_parser("compare", help="compare two result JSON files")
    c.add_argument("before")
    c.add_argument("after")
    c.add_argument(
        "--by",
        default=None,
        choices=["vulnerability", "language", "framework", "protocol"],
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

    prep = sub.add_parser("prepare", help="clone, install, and compile the Solidity targets so a review can ground")
    prep.add_argument("--only", nargs="+", default=None, help="prepare just these benchmark names")
    prep.add_argument(
        "--root", default=None, help="where clones live, defaults to $CYBERJURY_BACKTEST_DIR/repositories"
    )
    prep.set_defaults(func=_cmd_prepare)

    val = sub.add_parser("validate", help="validate a benchmark manifest and answer key")
    val.add_argument("path", help="benchmark directory or benchmark.yaml")
    val.add_argument("--source-root", default=None, help="checkout root used to verify answer-key file locations")
    val.set_defaults(func=_cmd_validate)

    cov = sub.add_parser("coverage", help="knowledge coverage matrix, which files lack eval coverage")
    cov.set_defaults(func=_cmd_coverage)

    args = p.parse_args(argv)
    if args.cmd == "repository" and not (args.findings_dir or args.findings_json or args.workspace):
        p.error("repository needs one of --workspace, --findings-dir, or --findings-json")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
