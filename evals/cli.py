"""Review quality measurement on benchmark cases by source-reviewed adjudication."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evals.attempts import attempt_path, recorded_attempt
from evals.benchmarks.cases import find_case, load_cases
from evals.benchmarks.validate import validate_benchmark
from evals.diff import case_state_dir, run
from evals.packets import build_packets, write_ledgers
from evals.report import failures, format_summary, summarize, write_json

_EPILOG = "Run from the repository root after `pip install -e '.[dev]'`."


def _write_new(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(document, indent=1, ensure_ascii=False))


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        parsed = 0
    if parsed < 1:
        raise ValueError("must be a positive integer")
    return parsed


def _progress(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _cmd_diff(args) -> int:
    cases = [case for case in load_cases(args.benchmark).values() if case.kind == "diff"]
    if args.case:
        cases = [case for case in cases if case.name == args.case]
        if not cases:
            raise ValueError(f"unknown diff case {args.case!r}")
    runs_dir = Path(args.runs_dir)
    state_dir = Path(args.state_dir).expanduser().resolve()
    paths = [
        path
        for case in cases
        for number in range(1, args.repeat + 1)
        for path in (attempt_path(runs_dir, case.name, number), case_state_dir(state_dir, case, number))
    ]
    if existing := next((path for path in paths if path.exists()), None):
        raise ValueError(f"diff output already exists: {existing}")

    def save_attempt(record: dict[str, object]) -> None:
        _write_new(attempt_path(runs_dir, str(record["case"]), int(record["attempt"])), record)

    records = run(
        cases,
        runs=args.repeat,
        state_dir=state_dir,
        progress=_progress,
        on_attempt=save_attempt,
    )
    failed = [record for record in records if not record["complete"]]
    print(f"=== diff: {runs_dir} ===")
    print(
        f"  cases {len(cases)}, runs {args.repeat}, complete attempts {len(records) - len(failed)}/{len(records)}, "
        f"reports {sum(len(record['findings']) for record in records if record['complete'])}"
    )
    for record in failed:
        print(f"  failed: {record['case']} attempt {record['attempt']}: {record['error']}")
    return 1 if failed else 0


def _cmd_record(args) -> int:
    case = find_case(args.case, args.benchmark)
    if case.kind != "repository":
        raise ValueError(f"{case.name} is not a repository case")
    runs_dir = Path(args.runs_dir)
    number = 1
    while attempt_path(runs_dir, case.name, number).exists():
        number += 1
    record = recorded_attempt(case, Path(args.review_attempt), number)
    _write_new(attempt_path(runs_dir, case.name, number), record)
    state = "complete" if record["complete"] else "incomplete"
    print(f"recorded {case.name} attempt {number}: {state}, reports {len(record['findings'])}")
    return 0 if record["complete"] else 1


def _cmd_packets(args) -> int:
    counts = build_packets(
        load_cases(args.benchmark),
        [Path(path) for path in args.runs],
        Path(args.out),
        groups=args.groups,
        max_reports=args.max_reports,
        mapping_path=Path(args.mapping) if args.mapping else None,
        references=[Path(path) for path in args.references],
    )
    print(
        f"packets {args.out}: cases {counts['cases']}, complete attempts {counts['attempts']}, "
        f"reports {counts['reports']}, skipped incomplete attempts {counts['skipped']}"
    )
    print(f"round {counts['round_id']}, private mapping {counts['mapping']} (do not give it to adjudicators)")
    references = counts["references"]
    if references is not None:
        if not any(references.values()):
            print("references: no earlier verdicts were found for any case, so adjudicators will see empty references")
        for name, count in references.items():
            print(f"  references {name}: earlier verdicts {count}")
        if counts["reference_attempts_without_ledger"]:
            print(f"  reference attempts without a ledger {counts['reference_attempts_without_ledger']}")
    return 0


def _cmd_ledger(args) -> int:
    written, rejected = write_ledgers(
        load_cases(args.benchmark),
        Path(args.packets),
        mapping_path=Path(args.mapping) if args.mapping else None,
        supersede=args.supersede,
    )
    print(f"ledgers written {written}, rejected {len(rejected)}")
    for failure in rejected:
        print(f"  rejected: {failure}")
    return 1 if rejected else 0


def _cmd_report(args) -> int:
    summary = summarize(load_cases(args.benchmark), Path(args.runs), [Path(path) for path in args.calls])
    fails = failures(summary, precision_floor=args.precision_floor)
    print(format_summary(summary))
    print("report PASS" if not fails else f"report FAIL, {len(fails)} blocking")
    for fail in fails:
        print(f"  - {fail}")
    if args.json:
        write_json(args.json, summary, fails)
    return 1 if fails else 0


def _cmd_list(args) -> int:
    for case in load_cases(args.benchmark).values():
        print(f"{case.name:40} {case.kind:10} checks {len(case.checks)}")
    return 0


def _cmd_validate(args) -> int:
    validate_benchmark(args.path, source_root=args.source_root)
    print(f"valid: {args.path}")
    return 0


def _command(sub, name: str, summary: str, **options) -> argparse.ArgumentParser:
    return sub.add_parser(
        name, help=summary, description=f"{summary[0].upper()}{summary[1:]}.", allow_abbrev=False, **options
    )


def _add_benchmark(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--benchmark",
        metavar="PATH",
        action="append",
        default=None,
        help="benchmark.yaml or project directory, default every project under evals/projects, repeatable",
    )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    parser = argparse.ArgumentParser(
        prog="evals",
        description=__doc__,
        epilog=_EPILOG,
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    diff_parser = _command(sub, "diff", "run diff cases and record one attempt per case and run")
    diff_parser.add_argument(
        "--runs-dir", metavar="DIR", required=True, help="runs directory for <project>/<case>/attempt-NN.json"
    )
    diff_parser.add_argument(
        "--state-dir",
        metavar="DIR",
        required=True,
        help="review state directory for <project>/<case>/run-NN, holding each attempt and its model-calls.json",
    )
    diff_parser.add_argument(
        "--case", metavar="NAME", default=None, help="exact name of the one case to run, default every diff case"
    )
    diff_parser.add_argument(
        "--repeat",
        metavar="N",
        type=_positive_int,
        default=1,
        help="number of independent runs of every case, default 1",
    )
    _add_benchmark(diff_parser)
    diff_parser.set_defaults(func=_cmd_diff)

    record_parser = _command(
        sub, "record", "record a repository review attempt directory as the next attempt of a repository case"
    )
    record_parser.add_argument("case", help="full <project>:<repository case id> name")
    record_parser.add_argument("review_attempt", help="review attempt directory holding record.json and findings.json")
    record_parser.add_argument(
        "--runs-dir", metavar="DIR", required=True, help="runs directory for <project>/<case>/attempt-NN.json"
    )
    _add_benchmark(record_parser)
    record_parser.set_defaults(func=_cmd_record)

    packets_parser = _command(sub, "packets", "build blind adjudication packets from runs")
    packets_parser.add_argument(
        "runs", metavar="runs_dir", nargs="+", help="runs directories whose attempts are packaged into one round"
    )
    packets_parser.add_argument(
        "--out", metavar="DIR", required=True, help="directory adjudicators receive: packets and rubric only"
    )
    packets_parser.add_argument(
        "--mapping",
        metavar="FILE",
        default=None,
        help="new private mapping path outside --out, default <out>.private/mapping.json",
    )
    packets_parser.add_argument(
        "--groups",
        metavar="N",
        type=_positive_int,
        default=1,
        help="number of packets to split the cases into, default 1",
    )
    packets_parser.add_argument(
        "--max-reports",
        metavar="N",
        type=_positive_int,
        default=None,
        help="maximum reports in one packet entry, splitting a larger case into entries that list each other, "
        "default no limit",
    )
    packets_parser.add_argument(
        "--references",
        metavar="PATH",
        action="append",
        default=[],
        help="adjudicated runs directory, or the private mapping.json of an earlier round, whose ledger verdicts "
        "are shown to adjudicators, default no references, repeatable",
    )
    _add_benchmark(packets_parser)
    packets_parser.set_defaults(func=_cmd_packets)

    ledger_parser = _command(sub, "ledger", "validate adjudicator results and write a ledger beside each attempt")
    ledger_parser.add_argument("packets", help="packets directory holding result-N.json")
    ledger_parser.add_argument(
        "--mapping", metavar="FILE", default=None, help="private mapping path, default <packets>.private/mapping.json"
    )
    ledger_parser.add_argument(
        "--supersede",
        action="store_true",
        help="replace ledgers that another adjudication round wrote for this round's attempts",
    )
    _add_benchmark(ledger_parser)
    ledger_parser.set_defaults(func=_cmd_ledger)

    report_parser = _command(sub, "report", "report reviewed recall, report precision, verdicts, and model call cost")
    report_parser.add_argument("runs", metavar="runs_dir", help="adjudicated runs directory")
    report_parser.add_argument(
        "--calls",
        metavar="PATH",
        action="append",
        default=[],
        help="model call receipt or directory, default no cost report, repeatable",
    )
    report_parser.add_argument(
        "--precision-floor",
        metavar="RATIO",
        type=float,
        default=0.0,
        help="report precision below which the run fails, supported / (supported + not_actionable), default 0",
    )
    report_parser.add_argument(
        "--json",
        metavar="FILE",
        default=None,
        help="file to write the run summary and its failures to as JSON, default no file",
    )
    _add_benchmark(report_parser)
    report_parser.set_defaults(func=_cmd_report)

    list_parser = _command(sub, "list", "list benchmark cases")
    _add_benchmark(list_parser)
    list_parser.set_defaults(func=_cmd_list)

    validate_parser = _command(sub, "validate", "validate a benchmark definition")
    validate_parser.add_argument("path", help="benchmark directory or benchmark.yaml")
    validate_parser.add_argument(
        "--source-root",
        metavar="DIR",
        default=None,
        help="checkout of repository.commit that repository case locations must exist in, default no location check",
    )
    validate_parser.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)
