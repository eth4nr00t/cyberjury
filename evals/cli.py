"""Measure review quality on benchmark cases by source-reviewed adjudication."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyberjury.cli import positive_int
from cyberjury.review.settings import DEFAULT_REVIEW_SETTINGS
from evals.attempts import attempt_path, recorded_attempt
from evals.benchmarks.cases import find_case, load_cases
from evals.benchmarks.validate import validate_benchmark
from evals.diff import case_state_dir, run
from evals.packets import build_packets, write_ledgers
from evals.report import failures, format_summary, summarize, write_json

_EPILOG = (
    "Run from the repository root with the dev extra installed, for example "
    "`pip install -e '.[dev]'` then `python -m evals ...`. Commands that take --benchmark default to "
    "every project under evals/projects."
)


def _write_new(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(document, indent=1, ensure_ascii=False))


def _progress(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _cmd_diff(args) -> int:
    cases = [case for case in load_cases(args.benchmark).values() if case.kind == "diff"]
    if args.case:
        cases = [case for case in cases if case.name == args.case]
        if not cases:
            raise ValueError(f"unknown diff case {args.case!r}")
    attempts = Path(args.attempts_dir)
    state_dir = Path(args.state_dir).expanduser().resolve()
    paths = [
        path
        for case in cases
        for number in range(1, args.runs + 1)
        for path in (attempt_path(attempts, case.name, number), case_state_dir(state_dir, case, number))
    ]
    if existing := next((path for path in paths if path.exists()), None):
        raise ValueError(f"diff output already exists: {existing}")

    def save_attempt(record: dict[str, object]) -> None:
        _write_new(attempt_path(attempts, str(record["case"]), int(record["attempt"])), record)

    records = run(
        cases,
        runs=args.runs,
        concurrency=args.concurrency,
        state_dir=state_dir,
        progress=_progress,
        on_attempt=save_attempt,
    )
    failed = [record for record in records if not record["complete"]]
    print(f"=== diff: {attempts} ===")
    print(
        f"  cases {len(cases)}, runs {args.runs}, complete attempts {len(records) - len(failed)}/{len(records)}, "
        f"reports {sum(len(record['findings']) for record in records if record['complete'])}"
    )
    for record in failed:
        print(f"  failed: {record['case']} attempt {record['attempt']}: {record['error']}")
    return 1 if failed else 0


def _cmd_repository(args) -> int:
    case = find_case(args.case, args.benchmark)
    if case.kind != "repository":
        raise ValueError(f"{case.name} is not a repository case")
    attempts = Path(args.attempts_dir)
    number = 1
    while attempt_path(attempts, case.name, number).exists():
        number += 1
    record = recorded_attempt(case, Path(args.review_attempt), number)
    _write_new(attempt_path(attempts, case.name, number), record)
    print(f"recorded {case.name} attempt {number}: {len(record['findings'])} reports, complete {record['complete']}")
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
        f"packets {args.out}: {counts['cases']} cases, {counts['attempts']} complete attempts, "
        f"{counts['reports']} reports, skipped {counts['skipped']} incomplete attempts"
    )
    print(f"round {counts['round_id']}, private mapping {counts['mapping']} (do not give it to adjudicators)")
    references = counts["references"]
    if references is not None:
        if not any(references.values()):
            print("references: no earlier verdicts were found for any case, so adjudicators will see empty references")
        for name, count in references.items():
            print(f"  references {name}: {count} earlier verdicts")
        if counts["reference_attempts_without_ledger"]:
            print(f"  {counts['reference_attempts_without_ledger']} reference attempts have no ledger beside them")
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
        print(f"{case.name:40} {case.kind:10} checks={len(case.checks)}")
    return 0


def _cmd_validate(args) -> int:
    validate_benchmark(args.path, source_root=args.source_root)
    print(f"valid: {args.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI command and return a process-style exit code."""
    parser = argparse.ArgumentParser(
        prog="evals",
        description=__doc__,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    benchmark = argparse.ArgumentParser(add_help=False)
    benchmark.add_argument(
        "--benchmark", action="append", default=None, help="benchmark.yaml or project directory, repeatable"
    )

    diff_parser = sub.add_parser(
        "diff", parents=[benchmark], help="run diff cases and record one attempt per case and run", allow_abbrev=False
    )
    diff_parser.add_argument("--case", default=None, help="run one exact case name")
    diff_parser.add_argument("--runs", type=positive_int, default=1, help="independent runs of every case")
    diff_parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=DEFAULT_REVIEW_SETTINGS.execution.default_model_call_concurrency,
        help="diff unit reviews or issue link calls to run in parallel",
    )
    diff_parser.add_argument(
        "--attempts-dir", required=True, help="runs directory for <project>/<case>/attempt-NN.json"
    )
    diff_parser.add_argument(
        "--state-dir",
        required=True,
        help="review state directory for <project>/<case>/run-NN, holding each attempt and its model-calls.json",
    )
    diff_parser.set_defaults(func=_cmd_diff)

    repository_parser = sub.add_parser(
        "repository",
        parents=[benchmark],
        help="record a Repository Review attempt directory as the next attempt of a repository case",
        allow_abbrev=False,
    )
    repository_parser.add_argument("case", help="full <project>:<repository case id> name")
    repository_parser.add_argument(
        "review_attempt", help="review attempt directory holding record.json and findings.json"
    )
    repository_parser.add_argument(
        "--attempts-dir", required=True, help="runs directory for <project>/<case>/attempt-NN.json"
    )
    repository_parser.set_defaults(func=_cmd_repository)

    packets_parser = sub.add_parser(
        "packets", parents=[benchmark], help="build blind adjudication packets from runs", allow_abbrev=False
    )
    packets_parser.add_argument("runs", nargs="+", help="runs directories whose attempts are packaged into one round")
    packets_parser.add_argument("--out", required=True, help="directory adjudicators receive: packets and rubric only")
    packets_parser.add_argument(
        "--mapping", default=None, help="new private mapping path outside --out, default <out>.private/mapping.json"
    )
    packets_parser.add_argument(
        "--groups", type=positive_int, default=1, help="number of packets to split the cases into"
    )
    packets_parser.add_argument(
        "--max-reports",
        type=positive_int,
        default=None,
        help="split a case with more reports into entries of at most this many, each listing the others",
    )
    packets_parser.add_argument(
        "--references",
        action="append",
        default=[],
        help="adjudicated runs directory, or the private mapping.json of an earlier round, whose ledger verdicts "
        "are shown to adjudicators, repeatable",
    )
    packets_parser.set_defaults(func=_cmd_packets)

    ledger_parser = sub.add_parser(
        "ledger",
        parents=[benchmark],
        help="validate adjudicator results and write a ledger beside each attempt",
        allow_abbrev=False,
    )
    ledger_parser.add_argument("packets", help="packets directory holding result-N.json")
    ledger_parser.add_argument(
        "--mapping", default=None, help="private mapping path, default <packets>.private/mapping.json"
    )
    ledger_parser.add_argument(
        "--supersede",
        action="store_true",
        help="replace ledgers that another adjudication round wrote for this round's attempts",
    )
    ledger_parser.set_defaults(func=_cmd_ledger)

    report_parser = sub.add_parser(
        "report",
        parents=[benchmark],
        help="reviewed recall, report precision, verdicts, and model call cost",
        allow_abbrev=False,
    )
    report_parser.add_argument("runs", help="adjudicated runs directory")
    report_parser.add_argument(
        "--calls", action="append", default=[], help="model call receipt or directory, repeatable"
    )
    report_parser.add_argument(
        "--precision-floor",
        type=float,
        default=0.0,
        help="fail below this report precision, supported / (supported + not_actionable)",
    )
    report_parser.add_argument("--json", default=None, help="write the run summary and its failures")
    report_parser.set_defaults(func=_cmd_report)

    sub.add_parser("list", parents=[benchmark], help="list benchmark cases", allow_abbrev=False).set_defaults(
        func=_cmd_list
    )

    validate_parser = sub.add_parser("validate", help="validate a benchmark definition", allow_abbrev=False)
    validate_parser.add_argument("path", help="benchmark directory or benchmark.yaml")
    validate_parser.add_argument(
        "--source-root", default=None, help="checkout of repository.commit that repository case locations must exist in"
    )
    validate_parser.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)
