"""Command line interface for benchmark evaluation and backtests.

Source-reviewed adjudication is the measure of record. The strict location score is a
pre-assignment hint for the source assessment ledger. It is printed as raw location
matches and never sets the exit status or a gate result.

Diff workflow:
  python -m evals diff --cases evals/projects/paperless-ngx --runs 3 --attempts-dir runs
  then write one source assessment ledger for each runs/<project>/<task>/attempt-NN.json
  python -m evals adjudicate-diff paperless-ngx:<task> --manifest <benchmark.yaml>
      --attempt-json runs/paperless-ngx/<task>/attempt-01.json --ledger ledger-01.json
      --source <checkout at the task commit> --json reviewed/<task>-01.json
  python -m evals certify reviewed --manifest evals/projects/paperless-ngx/benchmark.yaml
  python -m evals gate reviewed --baseline reviewed-before --precision-floor 0.8

Repository workflow:
  python -m evals repository paperless-ngx --findings-json findings.json --json after.json
  python -m evals adjudicate paperless-ngx --findings-json findings.json --ledger ledger.json --source <checkout>
  python -m evals gate after.json --adjudication-ledger ledger.json --findings-json findings.json --source <checkout>

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

from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from evals.backtest.compare import compare_files, format_compare
from evals.review.repository import score as score_repository
from evals.score.result import RepeatedResult, Result


def _format_result(res) -> str:
    known = len(res.found) + len(res.false_positives)
    lines = [
        f"=== {res.target} ===",
        "  raw location matches, not source reviewed; adjudication is the measure of record",
        f"  raw matched checks {len(res.found)}/{res.n_findings}",
        f"  raw known-check precision {res.precision_known:.0%}  over {known} matched of {res.n_reports} reports",
    ]
    runs = getattr(res, "runs", None)
    if runs:
        lines.insert(1, f"  runs      {runs}, raw match by strict majority")
        flaky = {i: c for i, c in res.found_freq.items() if 0 < c < runs}
        if flaky:
            spread = ", ".join(f"{i} {c}/{runs}" for i, c in sorted(flaky.items()))
            lines.append(f"  raw matched in some runs not all: {spread}")
    if res.missed:
        lines.append(f"  raw unmatched: {', '.join(res.missed)}")
    if res.false_positives:
        lines.append(f"  raw match on clean check: {', '.join(res.false_positives)}")
    if res.extra:
        lines.append(f"  unmatched reports awaiting adjudication: {len(res.extra)}")
    if res.errors:
        lines.append(f"  errors: {res.errors}")
    return "\n".join(lines)


def _emit(res: Result | RepeatedResult, json_out: str | None) -> int:
    print(_format_result(res))
    if json_out:
        Path(json_out).write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
    return 1 if res.errors else 0


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
        return f"{prefix} review judgment [{event['judgment_label']}] finished in {event['judgment_seconds']}s"
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
        source_root=args.source,
    )
    return _emit(result, args.json)


def _cmd_adjudicate(args) -> int:
    from evals.adjudication import adjudicate

    result = adjudicate(
        args.name,
        findings_json=args.findings_json,
        ledger_json=args.ledger,
        source_root=args.source,
        run_status=args.run_status,
    )
    counts = ", ".join(f"{name}={count}" for name, count in result.counts.items())
    known_total = len(result.known_found) + len(result.known_missed)
    print(f"=== adjudicate: {result.target} ===")
    print(f"  {counts}")
    extras = ", ".join(f"{name}={count}" for name, count in result.extra_dispositions.items() if count)
    print(f"  raw extra dispositions {extras or 'none'}")
    print(f"  source-supported known checks {len(result.known_found)}/{known_total}")
    print(f"  paired introduction checks {result.introduction_check_count}/{known_total} repository checks")
    if result.new_supported:
        print(f"  supported issues without a paired introduction: {len(result.new_supported)}")
    if result.mismatched_assignments:
        print(f"  NOTE: strict location assignments differ from source assessment {len(result.mismatched_assignments)}")
    precision = "unknown" if result.report_precision is None else f"{result.report_precision:.0%}"
    print(f"  unique report precision {precision}")
    if result.independent_verified is not None:
        print(f"  machine confirmed {result.machine_confirmed}, independently verified {result.independent_verified}")
    if result.missing_introductions:
        print(f"  missing introduction cases: {', '.join(result.missing_introductions)}")
    if result.introduction_not_ancestor:
        print(f"  introduction commits outside repository history: {', '.join(result.introduction_not_ancestor)}")
    if result.pending:
        print(f"  pending source assessments: {len(result.pending)}")
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return int(
        bool(
            result.pending
            or (
                args.require_introductions
                and (result.missing_introductions or result.introduction_not_ancestor or result.new_supported)
            )
        )
    )


def _cmd_adjudicate_diff(args) -> int:
    from evals.adjudication import adjudicate_diff

    result = adjudicate_diff(
        args.manifest,
        args.name,
        attempt_json=args.attempt_json,
        ledger_json=args.ledger,
        source_root=args.source,
    )
    total = len(result.reviewed_found) + len(result.reviewed_missed)
    print(f"=== adjudicate diff: {result.case} attempt {result.attempt} ===")
    print(f"  raw strict matches {len(result.raw_found)}/{total}")
    print(f"  source reviewed matches {len(result.reviewed_found)}/{total}")
    if result.pending:
        print(f"  pending source assessments {len(result.pending)}")
    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return int(bool(result.pending))


def _cmd_diff(args) -> int:
    from cyberjury.providers.metering import UsageMeter, validate_model_calls_document
    from evals.review.diff import run

    cases = _selected_diff_cases(args.cases, args.case)
    if args.attempts_dir:
        directory = Path(args.attempts_dir)
        paths = (_attempt_path(directory, case.name, number) for case in cases for number in range(1, args.runs + 1))
        if existing := next((path for path in paths if path.exists()), None):
            raise ValueError(f"diff attempt already exists: {existing}")
    progress = _diff_progress_writer(args.json)
    meter = UsageMeter() if args.calls_json or args.calls_dir else None
    calls_dir = Path(args.calls_dir) if args.calls_dir else None
    if calls_dir is not None:
        calls_dir.mkdir(parents=True, exist_ok=True)

    def save_run_calls(number: int, document: dict[str, object]) -> None:
        if calls_dir is None:
            return
        path = calls_dir / f"run-{number:02d}-model-calls.json"
        with path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(document, indent=2))

    def save_attempt(number: int, record: dict[str, object]) -> None:
        path = _attempt_path(Path(args.attempts_dir), str(record["case"]), number)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as output:
            output.write(json.dumps(record, indent=1, ensure_ascii=False))

    result = run(
        cases,
        model_override=args.model,
        runs=args.runs,
        concurrency=args.concurrency,
        progress=progress,
        trace=progress if args.debug else None,
        meter=meter,
        on_run_calls=save_run_calls if calls_dir is not None else None,
        on_attempt=save_attempt if args.attempts_dir else None,
    )
    if args.calls_json and meter is not None:
        document = validate_model_calls_document(meter.document())
        Path(args.calls_json).write_text(json.dumps(document, indent=2), encoding="utf-8")
    return _emit(result, args.json)


def _attempt_path(directory: Path, case: str, number: int) -> Path:
    project, task = case.split(":", 1)
    return directory / project / task / f"attempt-{number:02d}.json"


def _selected_diff_cases(path: str | None, name: str | None) -> list:
    from evals.benchmarks.cases import diff_cases, load_project_diff_cases

    cases = _load_diff_cases_arg(path, load_project_diff_cases) if path else diff_cases()
    if name:
        cases = [case for case in cases if case.name == name]
        if not cases:
            raise ValueError(f"unknown diff case {name!r}")
    return cases


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

    d = compare_files(args.before, args.after)
    print(format_compare(d))
    if args.before_workspace or args.after_workspace:
        d = with_arms(d, args.before_workspace, args.after_workspace)
        print(format_arms(d))
        return 0 if d["comparable"] else 1
    return 0


def _cmd_calls(args) -> int:
    from evals.backtest.calls import compare_model_call_summaries, load_model_call_summary

    after = load_model_call_summary(args.artifact)
    result = compare_model_call_summaries(load_model_call_summary(args.baseline), after) if args.baseline else after
    if args.baseline:
        print(f"models: baseline {', '.join(result['before_models']) or 'none'}")
        print(f"models: changed {', '.join(result['after_models']) or 'none'}")
    else:
        print(f"models: {', '.join(result['models']) or 'none'}")
    for stage in result["stages"]:
        name = f"{stage['trigger']} {stage['role']}"
        if args.baseline:
            print(
                f"{name}: requests {stage['before_requests']} -> {stage['after_requests']}, "
                f"max prompt chars {stage['before_max_prompt_chars']} -> {stage['after_max_prompt_chars']}, "
                f"input tokens {stage['before_input_tokens']} -> {stage['after_input_tokens']}, "
                f"output tokens {stage['before_output_tokens']} -> {stage['after_output_tokens']}, "
                f"failed {stage['before_failed_requests']} -> {stage['after_failed_requests']}"
            )
        else:
            print(
                f"{name}: requests {stage['requests']}, "
                f"max prompt chars {stage['max_prompt_chars']}, "
                f"input tokens {stage['total_input_tokens']}, output tokens {stage['output_tokens']}, "
                f"failed {stage['failed_requests']}"
            )
    if args.baseline and not result["comparable_models"]:
        print("model sets differ; token deltas cannot be attributed to review design alone")
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


def _cmd_gate(args) -> int:
    if Path(args.after).is_dir():
        return _reviewed_gate(args)
    from evals.backtest.gate import format_gate, gate

    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
    from evals.adjudication import adjudicate

    adjudication = adjudicate(
        after["target"],
        findings_json=args.findings_json,
        ledger_json=args.adjudication_ledger,
        source_root=args.source,
        run_status=args.run_status,
    ).to_dict()
    baseline_adjudication = None
    if args.baseline_adjudication_ledger:
        baseline_adjudication = adjudicate(
            baseline["target"],
            findings_json=args.baseline_findings_json,
            ledger_json=args.baseline_adjudication_ledger,
            source_root=args.source,
            run_status=args.baseline_run_status,
        ).to_dict()
    fails = gate(
        after,
        baseline,
        precision_floor=args.precision_floor,
        adjudication=adjudication,
        baseline_adjudication=baseline_adjudication,
        require_introductions=args.require_introductions,
    )
    print(format_gate(fails, after.get("target", "?")))
    for side, assessment in (("changed", adjudication), ("baseline", baseline_adjudication)):
        if assessment is not None and assessment.get("mismatched_assignments"):
            print(
                f"NOTE: {side} arm has {len(assessment['mismatched_assignments'])} "
                "raw location assignments that differ from source assessment",
                file=sys.stderr,
            )
    return 1 if fails else 0


def _format_reviewed(side: str, summary: dict[str, int]) -> str:
    total = summary["check_attempts"]
    return (
        f"  {side}: {summary['cases']} cases, {summary['attempts']} attempts, "
        f"source reviewed {summary['reviewed_found']}/{total}, strict raw {summary['raw_found']}/{total}"
    )


def _reviewed_gate(args) -> int:
    from evals.adjudication import load_diff_adjudications
    from evals.backtest.gate import format_gate, reviewed_gate, reviewed_summary

    after = load_diff_adjudications(args.after)
    baseline = load_diff_adjudications(args.baseline) if args.baseline else None
    fails = reviewed_gate(after, baseline, precision_floor=args.precision_floor)
    print(format_gate(fails, args.after))
    print(_format_reviewed("changed", reviewed_summary(after)))
    if baseline is not None:
        print(_format_reviewed("baseline", reviewed_summary(baseline)))
    return 1 if fails else 0


def _cmd_certify(args) -> int:
    from evals.adjudication import load_diff_adjudications
    from evals.backtest.gate import certify

    expected = {
        case.name: frozenset(check.id for check in case.answer_key.findings)
        for case in _selected_diff_cases(args.manifest, args.case)
        if case.expectation == "findings"
    }
    receipt = certify(
        load_diff_adjudications(args.reviewed),
        expected,
        runs=args.runs,
        required_passes=args.required_passes,
    )
    print(f"=== certify: {args.reviewed} ===")
    print(
        f"  source reviewed {receipt['passed_cases']}/{receipt['total_cases']} cases passed at least "
        f"{receipt['required_passes']}/{receipt['runs']} whole attempts, "
        f"strict raw {receipt['raw_passed_cases']}/{receipt['total_cases']}"
    )
    if receipt["failed_cases"]:
        print(f"  CERTIFICATION FAILED: {', '.join(receipt['failed_cases'])}")
    if receipt["unexpected_cases"]:
        print(f"  results outside the selected cases: {', '.join(receipt['unexpected_cases'])}")
    if args.json:
        Path(args.json).write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return 0 if receipt["passed"] else 1


def _cmd_validate(args) -> int:
    from evals.benchmarks.validate import validate_benchmark

    validate_benchmark(args.path, source_root=args.source_root)
    print(f"valid: {args.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    p = argparse.ArgumentParser(
        prog="evals",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("repository", help="score a repository review against an answer key", allow_abbrev=False)
    r.add_argument("name", help="benchmark name, e.g. paperless-ngx")
    r.add_argument(
        "--workspace",
        default=None,
        help="review workspace root or one review session directory, requires a complete repository run",
    )
    r.add_argument("--findings-json", default=None, help="a findings.json or a json list of reports")
    r.add_argument(
        "--source",
        default=None,
        help="checkout root at the benchmark's pinned commit, selects the session that reviewed the case "
        "scope and lets a symbol anchor credit a report that pins the bug by line inside the symbol",
    )
    r.add_argument("--json", default=None, help="write the structured result here for compare")
    r.set_defaults(func=_cmd_repository)

    adjudication = sub.add_parser("adjudicate", help="check a complete source assessment ledger", allow_abbrev=False)
    adjudication.add_argument("name", help="repository benchmark name")
    adjudication.add_argument("--findings-json", required=True)
    adjudication.add_argument("--ledger", required=True)
    adjudication.add_argument("--source", required=True, help="checkout at the benchmark's pinned commit")
    adjudication.add_argument("--run-status", default=None, help="_run.json beside findings.json")
    adjudication.add_argument("--require-introductions", action="store_true")
    adjudication.add_argument("--json", default=None, help="write the adjudication summary")
    adjudication.set_defaults(func=_cmd_adjudicate)

    diff_adjudication = sub.add_parser(
        "adjudicate-diff", help="assess a saved complete diff run without model calls", allow_abbrev=False
    )
    diff_adjudication.add_argument("name", help="full project:diff-task case name")
    diff_adjudication.add_argument("--manifest", required=True, help="benchmark.yaml for the saved case")
    diff_adjudication.add_argument("--attempt-json", required=True, help="saved complete diff attempt")
    diff_adjudication.add_argument("--ledger", required=True, help="source assessment ledger")
    diff_adjudication.add_argument("--source", required=True, help="checkout at the case's pinned commit")
    diff_adjudication.add_argument("--json", default=None, help="write both raw and reviewed results")
    diff_adjudication.set_defaults(func=_cmd_adjudicate_diff)

    d = sub.add_parser(
        "diff",
        help="run the diff benchmark library, score it strictly, and save attempts",
        allow_abbrev=False,
    )
    d.add_argument("--model", default=None)
    d.add_argument("--cases", default=None, help="benchmark.yaml or benchmark directory, defaults to shipped tasks")
    d.add_argument("--case", default=None, help="run one exact case name from the selected benchmark")
    d.add_argument("--runs", type=int, default=1, help="repeat N times and fold by frequency")
    d.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
        help="diff batch reviews or verification calls to run in parallel",
    )
    d.add_argument(
        "--attempts-dir",
        default=None,
        help="write <project>/<task>/attempt-NN.json per case and run for source assessment and adjudicate-diff",
    )
    d.add_argument("--json", default=None)
    d.add_argument("--calls-json", default=None, help="write validated model call receipts separately from scores")
    d.add_argument("--calls-dir", default=None, help="write one validated model call receipt for each run")
    d.add_argument("--debug", action="store_true", help="emit review stage diagnostics")
    d.set_defaults(func=_cmd_diff)

    sub.add_parser("list", help="benchmarks the registry sees", allow_abbrev=False).set_defaults(func=_cmd_list)

    c = sub.add_parser("compare", help="compare two strict result JSON files", allow_abbrev=False)
    c.add_argument("before")
    c.add_argument("after")
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

    calls = sub.add_parser(
        "calls", help="summarize validated model-call stages without running a review", allow_abbrev=False
    )
    calls.add_argument("artifact", help="saved model-calls.json artifact")
    calls.add_argument("--baseline", default=None, help="saved baseline model-calls.json artifact")
    calls.add_argument("--json", default=None, help="write the structured stage summary")
    calls.set_defaults(func=_cmd_calls)

    g = sub.add_parser("gate", help="fail loud on a regression against a baseline", allow_abbrev=False)
    g.add_argument(
        "after",
        help="a directory of saved adjudicate-diff JSON outputs, read as trusted and not re-verified, "
        "or a repository result JSON with its source assessment",
    )
    g.add_argument("--baseline", default=None, help="a baseline of the same kind to judge the move against")
    g.add_argument(
        "--precision-floor",
        type=float,
        default=0.0,
        help="unique report precision floor over source assessments",
    )
    g.add_argument("--adjudication-ledger", default=None, help="source assessment ledger for this repository score")
    g.add_argument("--baseline-adjudication-ledger", default=None, help="source assessment ledger for the baseline")
    g.add_argument("--findings-json", default=None, help="exact findings artifact bound by the ledger")
    g.add_argument("--baseline-findings-json", default=None, help="exact baseline findings artifact")
    g.add_argument("--source", default=None, help="clean checkout at the benchmark's pinned commit")
    g.add_argument("--run-status", default=None, help="verification count beside findings.json")
    g.add_argument("--baseline-run-status", default=None, help="baseline verification count beside its findings")
    g.add_argument("--require-introductions", action="store_true")
    g.set_defaults(func=_cmd_gate)

    cert = sub.add_parser(
        "certify",
        help="require every findings case to pass enough source-reviewed whole-case attempts",
        allow_abbrev=False,
    )
    cert.add_argument(
        "reviewed", help="directory of saved adjudicate-diff JSON outputs, read as trusted and not re-verified"
    )
    cert.add_argument("--manifest", default=None, help="benchmark.yaml whose findings cases are expected")
    cert.add_argument("--case", default=None, help="expect one exact case name from the selected benchmark")
    cert.add_argument("--runs", type=int, default=3, help="complete attempts required for each case")
    cert.add_argument("--required-passes", type=int, default=2, help="reviewed passes required for each case")
    cert.add_argument("--json", default=None, help="write the certification receipt")
    cert.set_defaults(func=_cmd_certify)

    val = sub.add_parser("validate", help="validate a benchmark manifest and answer key", allow_abbrev=False)
    val.add_argument("path", help="benchmark directory or benchmark.yaml")
    val.add_argument("--source-root", default=None, help="checkout root used to verify answer-key file locations")
    val.set_defaults(func=_cmd_validate)

    args = p.parse_args(argv)
    if (
        args.cmd == "diff"
        and args.calls_json
        and args.json
        and Path(args.calls_json).resolve() == Path(args.json).resolve()
    ):
        p.error("diff score and model call receipts need different output paths")
    if args.cmd == "diff" and args.concurrency < 1:
        p.error("diff concurrency must be at least 1")
    if args.cmd == "diff" and args.calls_dir:
        directory = Path(args.calls_dir).resolve()
        run_paths = {directory / f"run-{number:02d}-model-calls.json" for number in range(1, args.runs + 1)}
        if any(Path(path).resolve() in run_paths for path in (args.json, args.calls_json) if path):
            p.error("diff score and aggregate call paths must differ from per-run receipts")
        if existing := next((path for path in sorted(run_paths) if path.exists()), None):
            p.error(f"per-run model call receipt already exists: {existing}")
    if args.cmd == "repository" and not (args.findings_json or args.workspace):
        p.error("repository needs one of --workspace or --findings-json")
    if args.cmd == "gate" and Path(args.after).is_dir():
        if args.baseline and not Path(args.baseline).is_dir():
            p.error("a reviewed gate baseline must also be a directory of adjudicate-diff outputs")
        repository_options = (
            args.adjudication_ledger,
            args.baseline_adjudication_ledger,
            args.findings_json,
            args.baseline_findings_json,
            args.source,
            args.run_status,
            args.baseline_run_status,
            args.require_introductions,
        )
        if any(repository_options):
            p.error("a reviewed gate reads saved adjudicate-diff outputs and takes no repository assessment options")
        return args.func(args)
    if args.cmd == "gate" and not args.adjudication_ledger:
        p.error("gate on a result JSON requires --adjudication-ledger; raw location matches never gate")
    if args.cmd == "gate" and not (args.findings_json and args.source):
        p.error("gate --adjudication-ledger requires --findings-json and --source")
    if args.cmd == "gate" and args.baseline and not (args.baseline_adjudication_ledger and args.baseline_findings_json):
        p.error("gate with a baseline and source assessment requires the baseline ledger and findings")
    if args.cmd == "gate" and args.baseline_adjudication_ledger and not args.baseline:
        p.error("gate baseline source assessment requires --baseline")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
